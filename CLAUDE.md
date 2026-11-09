# CLAUDE.md

Projet : TP2 Incident Response – Wazuh – M2 IRS.

## Manière de raisonner

- Ce dépôt est un projet SOC / réponse à incident. Charger et appliquer le skill
  `.claude/skills/misp-threat-intel` (méthode MISP) pour toute tâche touchant aux alertes,
  IoC, investigation, enrichissement, partage de renseignement ou intégration Wazuh.
- Tout observable d'incident doit être pensé comme un attribut/objet MISP typé, classifié
  (TLP, PAP, MITRE ATT&CK) et filtré par les warninglists avant d'être utilisé en détection.
- Suivre le cycle NIST SP 800-61 (préparation → détection/analyse → confinement →
  éradication/récupération → retour d'expérience) et documenter chaque phase.

## Règles

- Aucun secret (clé API MISP, mots de passe Wazuh, certificats privés) dans le dépôt.
- Ne jamais désactiver la vérification TLS dans les scripts d'intégration.
- Rédiger la documentation en français.
