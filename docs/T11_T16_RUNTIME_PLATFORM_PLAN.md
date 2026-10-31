# T11-T16 — Réseau, agents, modèles, observabilité et résilience

## T11 — Réseau et credentials

La couche `network_policy` introduit la base d'un système de politique d'egress avec :

- allowlist de destinations autorisées,
- refus par défaut,
- exigence d'attestation avant accès,
- lease de credentials avec scope et durée de vie.

Cela prépare une séparation claire entre la politique de réseau et la libération réelle de secrets.

## T12 — Agents de développement

Le runtime supporte désormais une catalog `DevelopmentAgentCatalog` pour :

- OpenCode,
- Codex,
- Claude Code,
- Qwen Code,
- Goose.

Ces agents restent des profils installés par le système et ne sont pas poussés en tant qu'exécution arbitraire.

## T13 — GammaModels Runtime

La couche `model_runtime` formalise :

- le manifeste du modèle,
- l'état d'un moteur d'inférence,
- la validation des ressources,
- la supervision du runtime et du healthcheck.

Cette implémentation ne prétend pas remplacer un moteur de modèles complet ; elle structure le contrat d'intégration.

## T14 — Observabilité

La couche `telemetry` permet de :

- enregistrer des métriques d'exécution,
- garder un snapshot borné,
- préparer une intégration OpenTelemetry ou un backend de supervision.

## T15 — Résilience

Le module `resilience` garde l'historique des états du processus pour :

- reconstruire l'état de reprise,
- détecter les transitions de santé,
- préparer la reconciliation après redémarrage.

## T16 — Documentation et contrats

Les tâches T11-T16 sont structurées dans la documentation de runtime pour :

- signer les contrats de réseau et de credential,
- expliciter les limites de sécurité,
- préparer les pièces d'intégration avec le Node Agent et l'image OS,
- clarifier les dépendances externes et les responsabilités de chaque couche.

## Limite importante

Ceci reste un socle de conception. Les mécanismes de production réels exigent un contrôle d'attestation externe, une politique de libération robuste et des composants de sécurité distincts du runtime invité.
