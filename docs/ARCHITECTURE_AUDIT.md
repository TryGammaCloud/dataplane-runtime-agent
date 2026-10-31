# T01 — Audit du Runtime Agent existant

> État actualisé : [finalisation du Prompt 3](PROMPT3_FINALIZATION.md). Les limitations et changements de contrat de ce rapport priment sur cette description historique.

## Vue d'ensemble

Le dépôt actuel est un runtime Rust de type guest-local qui fournit :

- un socket Unix pour la commande locale,
- un binaire `gammacloud-boot` de readiness,
- un binaire `gammacloud-runtime` de service,
- un protocole ASCII simple pour `HEALTH`, `STATUS`, `START`, `WORKLOAD_STATUS`, `WORKLOAD_LOGS`, `STOP` et `SHUTDOWN`,
- une politique locale basée sur `SO_PEERCRED` et `RLIMIT_AS` / `RLIMIT_CPU`,
- une gestion de workloads de développement avec exécution de profils prédéfinis,
- un pont AF_VSOCK de développement non authentifié.

## Catégorie 1 — Capacités existantes

- `gammacloud-boot` disponible comme preuve de démarrage local.
- `gammacloud-runtime` en service Unix local.
- gestion d'un socket `/run/gammacloud/runtime.sock` avec permissions strictes.
- parsing de commandes via `gammacloud-protocol`.
- profil produit explicite `legacy`, `sandbox`, `models` via fichier de configuration.
- sélection de produit avec logique de fail-closed.
- autorisation locale par UID.
- limites CPU/MEM via `setrlimit`.
- exécution de profils prédéfinis `smoke`, `sleep`, `worker`.
- journalisation des logs par job.
- arrêt et nettoyage de processus.
- gestion de l'état d'un workload.

## Catégorie 2 — Capacités partielles

- la stratégie de `Product` est déjà introduite, mais le runtime n'a pas encore de couche d'API de capacités structurées pour les sous-systèmes `Sandbox` et `Models` ;
- le mécanisme de sécurité est local et utile uniquement comme garde-fou de développement ;
- le runtime est capable d'exécuter des workloads déterministes, mais ne distingue pas encore clairement les sous-modules `Common`, `Sandbox`, `Models` ;
- le pont VSock est structurellement présent, mais il reste un transport de développement sans autorisation réelle ;
- la persistance et les volumes ne sont pas encore coordonnés à l'intérieur du runtime.

## Catégorie 3 — Capacités absentes / à préparer

- attestation SEV-SNP vérifiable et hors guest ;
- identité propriétaire robuste et enrôlement vérifié ;
- sessions shell/PTY utilisateur ;
- isolation par cgroups v2, namespaces, seccomp ;
- permissions système par workload ;
- travail sur les workspaces et volumes chiffrés ;
- gestion de secrets conditionnelle à l'attestation ;
- supervision système OpenTelemetry ;
- contrôles réseau et credentials gérés par politique ;
- gestion de modèles d'inférence non spécifique à un moteur particulier ;
- mécanisme de reprise et de resynchronisation après redémarrage.

## Conclusion de l'audit

Le runtime actuel est un bon socle de développement et de validation locale, mais il reste un environnement de développement explicite. Le point clé est de faire émerger une architecture commune avec des capacités explicites par profil, sans masquer la différence entre `Legacy`, `Sandbox`, `Models`.
