# T04-T10 — Identity, sessions, workspaces, volumes, attestation et secrets

## T04 — Identité et propriétaire d'une Sandbox

Le runtime introduit maintenant une structure `OwnerIdentity` avec :

- organization_id
- project_id
- sandbox_id
- owner_public_key
- workload_identity
- session_id
- policy_version

Cette couche formalise l'identité propriétaire sans prétendre à une authentification distante. Elle empêche le remplacement arbitraire d'un propriétaire déjà lié.

## T05 — Exécution GammaSandbox

Le runtime conserve le moteur de jobs existant, mais le profil produit est désormais représenté par des capacités explicites. Cela prépare la mise en place d'un exécuteur Sandbox plus riche et mieux séparé des profils Legacy/Models.

## T06 — Isolation des workloads

L'architecture actuelle conserve `setrlimit` comme garde-fou local, mais le code expose maintenant l'infrastructure nécessaire pour introduire des mécanismes plus forts dans les étapes suivantes : cgroups v2, namespaces, seccomp et séparation des processus.

## T07 — Sessions et terminaux

Le runtime contient désormais un `SessionManager` et un `Session` reflétant :

- identifiant de session,
- identité propriétaire,
- dates de création et d'expiration,
- suivi d'état (`Active`, `Idle`, `Expired`, `Closed`),
- préconfiguration PTY.

## T08 — Filesystem et Workspace

Une politique `WorkspacePolicy` a été introduite pour :

- forcer les chemins relatifs,
- rejeter les traversées de répertoire,
- limiter la profondeur du chemin,
- introduire un point de contrôle clair pour le montage des volumes.

## T09 — Volumes et persistance

Le type `VolumeMount` représente :

- un identifiant de volume,
- un chemin de montage,
- un drapeau de lecture seule.

Cela prépare la future coordination des volumes attachés et de leur déverrouillage conditionnel.

## T10 — Attestation et gestion des secrets

Le runtime contient désormais un `AttestationCoordinator` qui :

- enregistre des preuves d'attestation,
- suit l'état (`Unverified`, `Pending`, `Verified`, `Rejected`),
- n'autorise la publication d'un secret qu'après vérification,
- évite la libération de secrets dans des états non sécurisés.

## Limite de sécurité

Cette étape constitue une base de conception et de sécurité logique, pas une garantie de production. Les véritables mécanismes de confiance doivent reposer sur une attestation externe, des politiques de libération vérifiables et un contrôle de clé indépendant du guest.
