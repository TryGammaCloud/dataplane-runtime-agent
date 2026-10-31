# Prompt 3 — intégration et état vérifiable

État du travail : 31 octobre 2026, branche `fix/runtime-attestation-and-secure-server-integration`.
Cette branche part de la pile existante jusqu'à `fix/runtime-integration-review`
et intègre `origin/main` (PR #14 fusionnée). Elle contient donc aussi les développements
encore proposés dans les PR #15–23 ; ils ne sont pas tous présents sur `main`.
Les fichiers mentionnés ci-dessous sont relatifs à `crates/runtime/src/`, sauf indication.

**Aucune suite de tests exécutée pendant cette finalisation.** Les cibles de tests
ont été compilées avec Clippy. Compilation et revue de code ne démontrent pas le
fonctionnement des protections dans une VM. Aucun build NixOS, déploiement ou
publication Registry. Aucun nouveau service ajouté. Le vérificateur, le broker de
secrets et le collecteur restent des dépendances externes, jamais simulées.

## 1. Audit des chemins accessibles

Fichiers modifiés : `main.rs`, `server.rs`, et les modules raccordés ci-dessous.
Avant cette correction, neuf modules avaient une exemption globale `dead_code`.
Le serveur conservait un coordinateur d'attestation distinct de son autorisation,
une session fictive et un collecteur non alimenté. Les backends réels existaient
ailleurs dans la pile.

Toutes ces exemptions globales ont été retirées. Les anciens états modifiables
« running », « verified », les collections de métriques inventées et les contrôles
lexicaux présentés comme frontière de sécurité ont été remplacés par les contrôleurs
effectifs. Les crates et les interfaces de développement opérationnelles sont conservées.
Les anciennes API internes purement déclaratives ne sont pas conservées comme chemins
alternatifs d'autorisation. Il s'agit d'un binaire, pas d'une bibliothèque publique.

Chemin effectif : `main → server::serve → Authorization::admit → dispatch`, puis :

| Interface | Contrôleur appelé | Effet réel |
|---|---|---|
| protocole développement | `Manager` | profils smoke/sleep/worker, statut/logs/arrêt |
| `enroll/rotate/revoke/attest` | `Authorization`, `AttestationCoordinator` | signatures, liaison persistante, invalidation |
| `evidence` | collecteur SNP du même binaire | ioctl `/dev/sev-guest`, preuve non auto-vérifiée |
| `execute` | `Manager → isolated → exec_guard` | service systemd et contrôles kernel avant exec |
| `session_*`, `agent_launch` | `SessionManager → Terminals → Manager` | PTY, processus isolé, séquences/cursors/expiration |
| `files`, `volume_*` | `storage → workspace` | LUKS/mount/quota et opérations relatives aux descripteurs |
| `model_*` | `model_runtime::Models → inference → Manager` | intégrité, lancement, probe réseau réelle |
| `metrics`, export périodique | `telemetry → observability` | lectures cgroups/statvfs, GPU optionnel, OTLP |
| démarrage signé | `resilience::Reconciler`, `reconcile_volumes` | arrêt des unités persistées puis verrouillage des volumes |

Les modes auxiliaires du même binaire ne sont pas des interfaces réseau de production.
`--isolated-child` vérifie les protections ; les helpers fichiers et egress refusent
l'UID root ; le probe réseau requiert les privilèges nécessaires à `setns`.
Tests préparés : `server_lifecycle.rs`, tests unitaires serveur. Dépendance : Linux.
Limite : audit statique et compilation, pas de preuve d'exécution de bout en bout.

## 2. Attestation indépendante et preuve fraîche

Code modifié : `attestation.rs`, `authorization.rs`, `server.rs`,
`crates/protocol/src/structured.rs`. Accessible par `evidence` puis `attest`.
Le coordinateur possède désormais les décisions actives et leurs échéances ; aucun
champ d'état public ni `grant_secret` déclaratif ne peut fabriquer une permission.
`Authorization` contrôle les liaisons guest/boot/propriétaire/epoch/image/identité
workload/politique. Le coordinateur exige la signature Ed25519 du vérificateur épinglé
et la correspondance challenge/empreinte de preuve/empreinte du manifeste.

Une preuve doit avoir été collectée localement depuis moins de 60 secondes. Elle
est consommée par une seule décision, valable au plus 300 secondes. Les horloges
murale et monotone sont utilisées. Une nouvelle collecte invalide la décision
précédente et arrête les workloads avant l'appel au collecteur. Sans preuve locale,
signature valide ou décision actuelle, aucune référence de décision n'est remise
aux chemins de libération des clés/credentials.

Contrat ajouté au protocole expérimental v2 : `evidence` demande `challenge` et
`workload_digest` (64 caractères hex minuscules). Le contexte SNP inclut ces champs.
La réponse contient `evidence_digest = hex(SHA256(response_hex.as_bytes()))` : on
hache exactement la représentation hexadécimale retournée, pas le JSON réencodé.
La décision signée doit contenir ce digest, le challenge et le même workload_digest.
Celui-ci est le SHA256 de la sérialisation Serde compacte du manifeste d'exécution,
ou du manifeste d'inférence complet pour `model_start`.

Dépendances : SEV-SNP réel, vérificateur indépendant validant certificat AMD, TCB,
mesure et report_data, provisioning de sa clé. Aucune validation AMD locale simulée.
Tests préparés : signatures et liaisons dans `authorization.rs` ; preuve obligatoire,
consommation unique, challenge/digest/workload substitués, preuve périmée et recul
horaire dans `attestation.rs` ; ABI/contexte dans `snp.rs`.
Limites : aucun matériel exercé ; pas de transport distant attesté/chiffré fourni.
Une signature vérifiable déjà reçue reste utilisable jusqu'à son échéance ; il n'y a
pas de consultation en ligne de la disponibilité du vérificateur à chaque commande.

## 3. Identité de développement et production

Code modifié : `identity.rs`, `server.rs`, `main.rs` ; backend existant : `authorization.rs`.
L'identité d'environnement est exclusivement descriptive en mode développement.
Le statut indique sa provenance. En mode signé, seul l'enrôlement signé et persisté
accorde les permissions. Aucun propriétaire ni session n'est créé depuis l'environnement.
Accessible : `enroll`, `rotate`, `revoke`, commandes signées ; pas de CRUD control-plane.
Dépendances : clé d'autorité provisionnée et état guest protégé.
Tests préparés : refus de remplacement, permissions, signatures, rotation/révocation
et bindings dans `authorization.rs`. Les tests de validation des métadonnées de dev
ne prouvent aucune authentification.
Limites : persistance locale sans ancrage externe anti-rollback ; récupération d'un
propriétaire révoqué volontairement refusée, pas de ré-enrôlement implicite.

## 4. Protocole authentifié et erreurs typées

Code modifié : `crates/protocol/src/structured.rs`, `authorization.rs`, `server.rs`.
Le protocole signé v2 reste expérimental ; les nouveaux champs de preuve sont
obligatoires, les clients de la première ébauche doivent être adaptés. Le protocole
texte de développement est conservé. En mode signé, seuls HEALTH/STATUS texte
restent accessibles sans enveloppe ; `Start` structuré refuse désormais les anciens
profils non isolés avec `isolated_execution_required`.
Requêtes signées sur les octets exacts, versions/IDs/délais/permissions/boot/epoch,
journal réservé avant effet, doublons identiques mis en cache et résultats incertains
non réexécutés. Réponses avec code précis et `error_kind` enum sérialisée.
Dépendances : Ed25519 et stockage durable. Pas de nouveau fournisseur d'identité.
Tests préparés : rejeux/réservations/signatures/expiration dans `authorization.rs`,
catégories typées et trames bornées dans `structured.rs`, trames serveur existantes.
Limites : journal borné sans éviction automatique ; saturation refuse l'admission.
Les réponses ne sont pas signées ni chiffrées. Aucune garantie exactly-once après crash.

## 5. Exécution Sandbox

Code modifié : `isolated.rs`, `manager.rs`, `server.rs`, `workspace.rs` ; backends
existants : `exec_guard.rs`, `seccomp.rs`, `lease.rs`. Accessible : `execute` et les
lancements session/agent/modèle autorisés. Contrôles effectifs : UID/GID non root,
cgroups v2 mémoire/CPU/PIDs, namespaces, capacités supprimées, seccomp, racines en
lecture seule et échéances. Le garde dans le service vérifie les protections kernel
avant l'exécutable ; aucun fallback non isolé. Les ancêtres des chemins exécutables
et racines doivent aussi appartenir à root et être non modifiables par les workloads.
Dépendances : image Linux x86_64, systemd compatible (propriétés utilisées dont
PrivatePIDs), cgroups v2 et profils installés et hachés. Sans prérequis, refus.
Tests préparés : restrictions de manifeste dans `isolated.rs`. La matrice VM de
`INTEGRATION_TEST_PLAN.md` reste à automatiser pour les protections kernel et la
pression de ressources ; aucune validation système de ces protections n'est annoncée.
Limites : OS et template provisionnés de confiance ; ce n'est pas une frontière
contre root dans le guest, ni une démonstration d'absence de vulnérabilité kernel.

## 6. Sessions et PTY

Code modifié : `session.rs`, `terminal.rs`, `server.rs`. `SessionManager` désigne
maintenant le contrôleur des vrais PTY ; aucune session fictive « runtime-session ».
Accessible : open/read/write/resize/close, fermeture sur rotation/révocation,
expiration TTL et inactivité. TTL appliqué aussi au timeout du service ; statut
comptant les sessions encore vivantes. I/O bornées, écriture séquencée et lecture par
curseur. Les sessions sont liées à l'unique propriétaire actif de ce runtime et à
un workload isolé autorisé ; pas de partage multi-propriétaires implicite.
Dépendances : PTY Linux et backend d'isolation.
Test préparé : `process_pty_io_replay_and_expiration`, avec un véritable `/bin/cat`
et un PTY ; il ne teste pas la chaîne systemd d'autorisation. La fermeture cgroup,
les déconnexions et la reprise nécessitent encore les scénarios VM.
Limites : une connexion socket courte ne détruit pas la session ; reconnexion par
ID jusqu'à expiration/close. Pas de service SSH, pas de persistance des buffers.

## 7. Fichiers sûrs

Code modifié : `workspace.rs`, `storage.rs`. Accessible : `files` sur un volume
activé avec décision courante et permission. Linux `openat2` avec BENEATH,
NO_SYMLINKS, NO_MAGICLINKS, NO_XDEV ; aucun fallback lexical. Helper sous UID/GID
volume, pas root. Vérification du propriétaire et des modes du workspace monté.
Lecture/écriture UTF-8 bornées, création uniquement, mkdir, remove non récursif,
chmod limité au propriétaire ; quotas kernel couvrant aussi les autres écrivains UID.
Dépendances : openat2, quotas et volume autorisé monté.
Test préparé : `descriptor_resolution_refuses_parent_and_symlink_escapes`.
Limites : pas d'édition arbitraire de fichiers existants, pas d'API binaire/streaming.
Une interruption pendant une création peut laisser un fichier partiel ; l'opération
ne promet pas une transaction de contenu. Tests de sous-montage et quotas en VM à faire.

## 8. Volumes dans la VM

Code modifié : `storage.rs`, `authorization.rs`, `server.rs`.
Accessible : `volume_unlock/status/lock/rotate`, readiness préalable aux fichiers.
Vérification device bloc, UUID LUKS et filesystem, décision courante, clé par memfd
scellé d'un broker root vérifié SO_PEERCRED, cryptsetup, montage ext4
nosuid/nodev/noexec, quotas et permissions. Aucun formatage. Ajout d'une clé de
remplacement sans suppression de slot. Un nouvel échec d'activation déclenche une
fermeture de mapping ; un échec de nettoyage est signalé sans contenu sensible.
Le verrouillage regarde l'identité réelle du montage, même si ses quotas/modes
sont devenus invalides. Expiration de décision, arrêt normal et reprise verrouillent les volumes configurés.
Dépendances : devices Node, cryptsetup/blkid, ext4/quota et broker de clés externe
respectant `STORAGE_CONTRACT.md`. Le broker doit vérifier demande/décision/scope.
Tests préparés : frontières de fichiers ; scénarios volumes détaillés dans le plan,
mais pas encore de harness automatisé LUKS complet. Aucun disque exercé.
Limites : arrêt brutal peut laisser un mapping jusqu'à la réconciliation ; démontage
occupé refuse, sans unmount paresseux. L'échec du cleanup ne prouve pas une fermeture.
Aucune orchestration de disque Node ni gestion des clés control-plane implémentée.

## 9. Réseau effectivement appliqué

Code modifié : `network_policy.rs`, `egress.rs`, `isolated.rs`, `server.rs`.
`NetworkPolicy` porte désormais la politique utilisée par la passerelle réelle.
Les anciennes chaînes d'environnement n'accordent aucun accès réseau de production.
Accessible via le template approuvé de chaque lancement : namespace réseau privé,
passerelle CONNECT dédiée, hôte/port exacts et IP épinglées, blocage d'adresses
privées sauf permission explicite, limites connexions/temps. Pas de route directe
ouverte si une destination est absente. Credentials délivrés par descripteurs,
chargés dans le répertoire protégé systemd et bornés par une lease.
Dépendances : isolation effective, application compatible proxy et broker pour
credentials. Pas de résolution DNS permissive ni de service ajouté.
Test préparé : `connect_policy_matches_exact_host_and_port`.
Limites : le test de matching n'est pas une preuve d'inaccessibilité réseau ; essais
direct-route, IP privées, passerelle arrêtée et expiration restent requis en VM.
HTTP CONNECT uniquement ; applications non compatibles proxy restent sans réseau.

## 10. Agents de développement

Code modifié : `development_agent.rs`, `terminal.rs`, `authorization.rs`, `server.rs`.
Le catalogue est celui des profils approuvés de la politique, avec template et
version. `agent_launch` exige le même template que le manifeste signé ; le serveur
ne remplace plus silencieusement ce champ. Lancement par session isolée ; aucune
installation/téléchargement de binaire. Les credentials passent par le même chemin
autorisé que les autres workloads, pas par une configuration ordinaire.
Dépendances : outil préinstallé dans l'image, template/exécutable/hachage approuvés.
Tests préparés : primitives manifeste et PTY ; pas de test spécifique exécutant les
outils Codex/Claude/etc. Leur packaging demeure sous responsabilité OS.
Limites : la chaîne `version` est descriptive ; l'intégrité est le hash exécutable,
pas cette chaîne. Un profil configuré ne garantit pas que le fournisseur soit joignable.

## 11. GammaModels

Code modifié : `model_runtime.rs`, `inference.rs`, `server.rs`, `workspace.rs`.
Le module historique expose le superviseur existant, sans état running fabriqué.
Accessible : `model_start/status/stop` avec produit Models, manifeste complet lié à
la décision, exécutables approuvés, SHA256 des artefacts locaux et ancêtres protégés.
Lancement par le même Manager isolé. Readiness par probe HTTP loopback réelle dans
la namespace du processus et son cgroup attendu. Le moteur LLM n'est pas réimplémenté.
Dépendances : moteur et poids préinstallés, contrat `INFERENCE_CONTRACT.md` à faire
valider par `dataplane-inference`, backend d'isolation. Aucun téléchargement implicite.
Tests préparés : règles de manifeste communes ; scénarios moteur/hachage/healthcheck
listés dans le plan mais pas de harness moteur complet ajouté ici.
Limites : pas de moteur réel démarré pendant cette mission, pas de support GPU
accordé implicitement ; pas de preuve d'un contrat inter-dépôts validé conjointement.

## 12. Observabilité

Code modifié : `telemetry.rs`, `manager.rs`, `authorization.rs`, `server.rs`.
Le module historique expose les lectures effectives cgroups/statvfs, GPU numérique
optionnel et export OTLP HTTP JSON vers un socket local contrôlé. Accessible :
`metrics` et export périodique si autorisé dans la politique. Les valeurs indisponibles
restent absentes ; pas de fausses valeurs zéro. Pas d'argv, contenu fichier, prompt,
clé ou token dans l'export. Les événements techniques sont des messages fixes.
Dépendances : cgroups montés, collecteur local facultatif et nvidia-smi facultatif.
Tests préparés : scénarios collecteur absents/lents et données interdites dans le
plan ; pas de harness OTLP bout en bout ajouté. La documentation compile strictement.
Limites : snapshots, cgroup path system.slice attendu ; pas de précision facturation,
pas de pipeline de traces complet ni d'accusé de livraison durable des événements.

## 13. Reprise après interruption

Code modifié : `resilience.rs`, `manager.rs`, `authorization.rs`, `storage.rs`, `server.rs`.
Le module historique utilise le registre durable existant. Intentions fsync avant
spawn ; réconciliation au démarrage avant admission, contrôle strict des noms
unités détenues, arrêt réel et conservation de l'intention en cas d'échec. Les cgroups
sont gérés par leurs unités systemd. Après arrêt des unités, démontage/verrouillage
des volumes configurés ; mapping `gc-*` inconnu = refus de démarrage pour intervention,
pas d'adoption silencieuse. Aucune reprise automatique d'une ancienne autorité.
Dépendances : état guest durable protégé, systemd/cryptsetup lorsque requis.
Test préparé : `recovery_cannot_target_unrelated_services` ; scénarios crash entre
réservation/spawn/résultat et volumes orphelins décrits dans le plan, pas encore
harness de fault injection complet. Aucun crash injecté ici.
Limites : état snapshotable sans ancrage externe ; erreur ambiguë = refus, parfois
intervention opérateur. Pas de reprise des sessions ni des buffers, pas de rollback
cryptographique de l'état, pas de reconnexion transparente à un moteur ancien.

## Vérifications et suites différées

Exécutés : `cargo fmt --all`, `cargo fmt --all -- --check`,
`cargo check --workspace --all-targets --offline`,
`cargo clippy --workspace --all-targets --offline -- -D warnings`,
`RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --offline`,
`git diff --check`. Clippy compile les tests mais ne les exécute pas.

Non exécutés : `cargo test`, suites VM, hardware SNP, tests de volumes, réseau,
engine et fault injection. Les lignes du plan d'intégration sont des scénarios à
implémenter/exécuter ; elles ne sont pas présentées comme tests automatisés existants.

Conclusion de livraison : chemins raccordés et refus implémentés, validation de
production incomplète. Aucune tâche nécessitant une preuve VM ou matérielle n'est
marquée « terminée ». Les dépendances externes doivent être provisionnées et les
preuves d'acceptation enregistrées sur les commits/images exacts avant activation.
