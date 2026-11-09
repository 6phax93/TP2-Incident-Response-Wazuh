---
name: misp-threat-intel
description: Méthode de réflexion orientée Threat Intelligence MISP pour les projets SOC / réponse à incident / SIEM (Wazuh, Elastic, Suricata…). À utiliser dès qu'un projet touche aux IoC, à l'enrichissement d'alertes, au partage de renseignement, à l'investigation d'incident, à MISP, PyMISP, STIX, TLP, MITRE ATT&CK, ou à l'intégration Wazuh ↔ MISP.
---

# Skill : penser « MISP » en réponse à incident

MISP (Malware Information Sharing Platform, https://github.com/MISP/MISP, branche stable **2.5**, licence AGPL-3.0)
est la plateforme open source de référence pour **collecter, corréler, qualifier et partager** des indicateurs
de compromission (IoC) et du renseignement sur la menace. Ce skill fixe la façon de raisonner sur tout projet
SOC / IR : chaque observable vu dans un incident doit pouvoir **entrer** dans MISP (capitalisation) et chaque
alerte doit pouvoir **interroger** MISP (détection / enrichissement).

## 1. Réflexes à appliquer sur chaque projet

1. **Observable → attribut typé.** Toute donnée technique (IP, domaine, URL, hash, mutex, clé de registre,
   email, user-agent, JA3…) se pense comme un attribut MISP avec un *type* précis (`ip-dst`, `domain`,
   `sha256`, `url`, `regkey`, `email-src`…) et une *catégorie* (`Network activity`, `Payload delivery`,
   `Artifacts dropped`, `Persistence mechanism`…).
2. **Grouper en objets.** Plusieurs attributs liés = un objet MISP (`file`, `domain-ip`, `network-connection`,
   `email`, `process`, `registry-key`, `url`). Ne jamais laisser un hash isolé de son nom de fichier/taille.
3. **Contexte = un événement.** Un incident / une campagne / un rapport = un *event* MISP avec `info`,
   `threat_level_id`, `analysis`, `distribution`, tags.
4. **Distinguer détection et contexte** : flag `to_ids=True` uniquement pour ce qui est exploitable en
   détection automatique (pas pour une IP de CDN, un domaine légitime, un hash de binaire Windows signé).
5. **Réduire les faux positifs** : vérifier contre les **warninglists** (`enforceWarninglist: true` dans
   `restSearch`) avant de pousser un IoC en détection.
6. **Classifier systématiquement** avec les taxonomies : `tlp:` (partage), `pap:` (actions autorisées),
   `admiralty-scale:` (fiabilité), `kill-chain:`, et les **galaxies** MITRE ATT&CK
   (`misp-galaxy:mitre-attack-pattern="... - T1059"`), threat-actor, malware, ransomware.
7. **Boucle de rétroaction** : quand un IoC MISP matche dans le SIEM → ajouter une **sighting**
   (type 0 = vu, 1 = faux positif, 2 = expiration). C'est ce qui fait vivre la base.
8. **Partage maîtrisé** : choisir le niveau de distribution le plus restrictif par défaut, élargir ensuite.
9. **Automatiser via API**, jamais à la main en production : REST (`/events/restSearch`,
   `/attributes/restSearch`), PyMISP, ou flux temps réel ZMQ / Kafka.
10. **Sécurité de l'intégration** : clé API dans une variable d'environnement ou un fichier `chmod 600`,
    jamais commitée ; TLS vérifié (`ssl=True` / CA interne) ; timeouts ; cache local des résultats ;
    rôle MISP dédié en lecture seule pour le SIEM.

## 2. Valeurs à connaître par cœur

| Champ | Valeurs |
|---|---|
| `distribution` (event/attribut) | 0 = Your organisation only · 1 = This community only · 2 = Connected communities · 3 = All communities · 4 = Sharing group · 5 = Inherit event (attribut uniquement) |
| `threat_level_id` | 1 = High · 2 = Medium · 3 = Low · 4 = Undefined |
| `analysis` | 0 = Initial · 1 = Ongoing · 2 = Completed |
| Sighting `type` | 0 = sighting · 1 = false-positive · 2 = expiration |
| TLP (v2) | `tlp:clear` · `tlp:green` · `tlp:amber` · `tlp:amber+strict` · `tlp:red` |

## 3. Cycle de réponse à incident ↔ MISP (NIST SP 800-61 / SANS PICERL)

| Phase | Usage MISP |
|---|---|
| Préparation | Abonnement aux **feeds** (CIRCL OSINT, abuse.ch, Botvrij…), activation des warninglists, synchro avec la communauté (CERT, ISAC) |
| Détection / Analyse | Le SIEM interroge MISP sur chaque observable ; corrélation (y compris ssdeep et CIDR) pour relier l'alerte à des campagnes connues ; enrichissement via **misp-modules** (VirusTotal, Shodan, passive DNS…) |
| Confinement | Export des IoC `to_ids` en règles Suricata/Snort/Zeek, zones RPZ DNS, listes de blocage firewall/EDR |
| Éradication / Récupération | Recherche rétroactive (hunting) des IoC dans les logs historiques |
| Retour d'expérience | Création de l'event MISP de l'incident (objets, ATT&CK, rapport Markdown), sightings, publication selon TLP, export **STIX 2.1** pour les partenaires |

## 4. Patterns de code

Voir `references/pymisp-cheatsheet.md` (PyMISP + REST) et `references/wazuh-misp-integration.md`
(intégration Wazuh : script `custom-misp`, bloc `ossec.conf`, règles).

## 5. Checklist avant de livrer un projet SOC/IR

- [ ] Les observables de l'incident sont-ils structurés (types, catégories, objets) et pas juste en texte libre ?
- [ ] Les IoC de détection sont-ils filtrés par warninglists et marqués `to_ids` à bon escient ?
- [ ] Chaque technique observée est-elle mappée sur MITRE ATT&CK (galaxie) ?
- [ ] TLP / PAP / distribution définis et cohérents ?
- [ ] Les matches SIEM génèrent-ils des sightings dans MISP ?
- [ ] Aucun secret (clé API MISP, mot de passe) dans le dépôt ?
- [ ] Un export exploitable (STIX 2.1, CSV, règles NIDS) est-il produit pour les équipes aval ?

## Références

- Doc / MISP book : https://www.circl.lu/doc/misp/ · OpenAPI : https://www.misp-project.org/openapi/
- PyMISP : https://github.com/MISP/PyMISP · misp-modules : https://github.com/MISP/misp-modules
- Taxonomies : https://github.com/MISP/misp-taxonomies · Warninglists : https://github.com/MISP/misp-warninglists
- Galaxies : https://www.misp-project.org/galaxy.html · Objets : https://www.misp-project.org/objects.html
- STIX : https://github.com/MISP/misp-stix · Standard : https://www.misp-standard.org/
