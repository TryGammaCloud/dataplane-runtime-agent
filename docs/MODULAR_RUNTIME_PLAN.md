# T02 — Architecture modulaire du Runtime Agent

## Objectif

Faire évoluer le runtime actuel vers trois frontières logiques qui partagent l'infrastructure commune du guest et distinguent les workloads par usage.

## 1) Runtime commun

Le runtime commun doit contenir :

- cycle de vie du processus,
- sécurité de base,
- coordination d'attestation,
- gestion des secrets conditionnels,
- stockage et volumes,
- réseaux et policy,
- télémétrie et journalisation,
- communication avec le Node Agent.

Ce niveau reste le cœur de la plateforme. Il doit rester robuste, explicitement local et fail-closed.

## 2) Sandbox workload runtime

Le profil Sandbox doit supporter :

- exécution de commandes autorisées,
- sessions interactives,
- workspaces personnels,
- outils installés par l'image,
- absence d'exécution arbitraire non autorisée,
- ressources et shutdown contrôlés,
- intégration avec des agents de développement via des profils installés par le système.

## 3) Inference workload runtime

Le profil Models doit supporter :

- manifeste du modèle autorisé,
- validation du binaire et des artefacts,
- coordination de chargement de poids,
- supervision du moteur d'inférence,
- healthchecks et reporting,
- arrêt propre et état d'exécution.

Il est important que cette partie ne soit pas un clone d'un moteur de modèles ; elle doit coordonner l'inférence sans dépendre d'un moteur spécifique.

## Évolution minimale utile

Le premier axe concret est d'introduire une notion explicite de capacités par profil, sans modifier la structure fondamentale du runtime. Cela est déjà amorcé avec `Product::capabilities()` et les garde-fous par profil.

Le second axe est d'enregistrer le fait que les modules de sécurité et de gestion de workloads doivent évoluer séparément :

- `security` : identité locale, limites, politique de ressources,
- `manager` : lifecycle des workloads,
- `product` : profil exécutif et capacités,
- `protocol` : schema de commandes et validations,
- `server` : transport et réponse.

## Plan de découpage

- `common/` : runtime core, identity, telemetry, coordination
- `sandbox/` : workload sandbox, sessions, workspace
- `models/` : coordination d'inférence et reporting
- `security/` : policy, attestation, secret gating
- `transport/` : Unix socket, vsock, protocol versioning

## Conclusion

Le runtime a un bon socle de développement, mais il manque encore une séparation explicite entre les responsabilités communes et les responsabilités spécifiques à chaque profil produit. Cette étape est essentielle avant d’ajouter des sessions, volumes persistants, attestation et politiques de sécurité plus fortes.
