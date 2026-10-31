# État de la mission Runtime Agent

État du code proposé dans la pile de PR après le socle `9f55d96`.
**Aucun statut ci-dessous ne signifie « prêt pour la production ».** Les tests ne
sont pas exécutés localement pendant cette mission ; la compilation ne démontre
pas les propriétés d'isolation ni la validité matérielle.

## Les dix lots

| Lot | Code réalisé | Critère restant à démontrer |
|---|---|---|
| 1 — Socle | Erreurs par connexion, trames bornées, échéances totales, SIGTERM/SIGINT, cleanup du manager/socket | Scénarios processus/signaux dans la VM ; SIGKILL/abort exigent supervision OS/cgroups |
| 2 — Contrats | Audit des trois sources Tinfoil épinglées et responsabilités explicites dans la PR documentaire indépendante | Adoption des contrats par OS/Node/Verifier/Inference |
| 3 — Protocole | JSON v2 signé, permissions, identifiants/versions/expiration, réservations et résultats fsync, résultat incertain sans duplication | Transport distant chiffré lié à l'attestation ; interopérabilité Node |
| 4 — Identité/attestation | Enrôlement signé durable, rotation double preuve, révocation, décision indépendante signée et liée au manifeste, collecte brute SNP | Vérificateur réel, certificat/TCB/measurement SNP, anti-rollback externe et canal de clés attesté |
| 5 — Isolation | Templates immuables, services systemd, cgroups, UID/GID, namespaces, capacités, seccomp, garde vérifiant les protections et lease monotone | Tests adversariaux dans l'image OS ; politiques GPU/privilèges non prises en charge |
| 6 — Stockage | UUIDs attendus, LUKS2 via descripteurs scellés, montage/démontage, quotas, openat2 et opérations de fichiers comme utilisateur | Broker indépendant, volumes ext4/quota provisionnés, tests crash/rotation ; retrait des anciennes clés non automatique |
| 7 — Sessions/outils | PTY réels, séquences/cursors, buffers bornés, resize, expiration, nettoyage et sélection de profils d'outils | Outils/templates NixOS installés, validation interactive ; SSH natif demeure un contrat OS |
| 8 — Réseau/credentials | Namespace privé, passerelle CONNECT obligatoire avec destinations/IP épinglées, credentials temporaires via descripteurs/LoadCredential | Tests de non-contournement, broker de credentials ; pas de clone de Monitor ni d'interception TLS |
| 9 — Models | Manifestes liés à décision, contrôle SHA-256 des poids, supervision d'un moteur préinstallé et healthcheck HTTP réel dans son namespace | Moteur/poids fournis par dataplane-inference, chargement réel et validation GPU |
| 10 — Observabilité/reprise | Compteurs cgroup/disque/GPU optionnel, OTLP local, registre de services durable, arrêt des services précédents avant admission, interrogation des résultats | Tests d'interruption/reprise/collecteur, ancrage externe anti-rollback ; pas de reprise automatique des PTY/secrets |

## T01 à T16 du prompt

| Tâche | Réalisation / limite explicite |
|---|---|
| T01 | Audit initial conservé ; analyse Tinfoil approfondie avec attribution des composants externes dans la PR documentaire |
| T02 | Un seul workspace Rust et un seul runtime ; modules de transport/autorisation, exécution, stockage, sessions, inférence et observabilité raccordés au serveur |
| T03 | Protocole v2 opérationnel côté guest ; v1 de développement conservé ; bridge de développement interdit en mode signé ; vsock authentifié/chiffré non livré |
| T04 | Autorité initiale épinglée, liaison durable aux ressources, epochs, rotation et révocation ; rollback de disque non couvert |
| T05 | Profils smoke conservés ; manifestes autorisés, arguments, environnement filtré, cwd, logs/codes/arrêt via le manager commun |
| T06 | Backend Linux/systemd et garde vérifiant les protections avant exec ; aucun fallback sans isolation ; validation VM obligatoire |
| T07 | PTY, sessions bornées, reprise de polling et expiration ; aucune installation SSH non vérifiée ; SSH natif non activé |
| T08 | Lecture/création/écriture/suppression non récursive/chmod relatifs au descripteur ; refus des escapes et quotas utilisateur ; fichiers UTF-8 bornés, écriture nouvelle uniquement |
| T09 | Activation LUKS2, vérification UUID, montage, démontage non paresseux, ajout d'une clé de remplacement ; broker externe et procédure de retrait de clé requis |
| T10 | Collecte Linux SNP brute et décisions Ed25519 indépendantes ; aucune preuve hardware validée pendant cette mission, aucune auto-acceptation locale |
| T11 | Egress réellement raccordé à la namespace/passerelle ; injection par fichiers credentials protégés, pas par configuration ordinaire ; dépendance broker explicite |
| T12 | Profils sélectionnés pour les agents existants, lancement isolé et sessions ; packaging/configuration publique GammaModels sous responsabilité OS |
| T13 | Contrôleur générique du moteur ; contrôle des poids et readiness ; aucun moteur d'inférence réimplémenté ou exécuté ici |
| T14 | Mesures réelles et export OTLP optionnel, sans contenu client ; snapshots, pas de précision commerciale démontrée |
| T15 | Arrêt/signaux, leases, journal et réconciliation fail-closed ; redémarrage exige de nouvelles autorisations ; état ambigu bloque l'admission |
| T16 | Contrats, limites et scénarios documentés ; tests unitaires/intégration préparés et compilés, pas exécutés localement |

## Arborescence

Avant : `boot`, `protocol`, et `runtime` avec serveur/manager/sécurité/profils,
plus les modules d'ébauche déjà fusionnés.

Après : mêmes crates, avec `protocol::structured` et les modules runtime
`authorization`, `lifecycle`, `isolated`, `exec_guard`, `seccomp`, `storage`,
`subprocess`, `terminal`, `egress`, `inference`, `lease`, `observability`, `recovery`
et `snp`. Les modules initiaux restent présents pour compatibilité. Les anciens
scaffolds ne sont pas utilisés comme preuves de sécurité du nouveau parcours.

Chaque PR contient son diff de fichiers. La liste cumulée est dans
`docs/IMPLEMENTATION_FILES.md`. Aucun dépôt OS/Node n'a été modifié, aucun build NixOS,
déploiement ou publication de release n'a été effectué.

## Validation

Vérifications locales : `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo build --workspace --locked`, documentation Rust et `git diff --check`.
Les tests sont compilés par Clippy mais non exécutés. Les exécutions GitHub Actions
éventuellement déclenchées par les PR sont des validations distinctes à consulter.
Les PR sensibles restent en brouillon pour revue et validation d'intégration.
