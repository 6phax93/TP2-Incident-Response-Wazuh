# PyMISP & API REST — aide-mémoire

```bash
pip install pymisp
export MISP_URL="https://misp.local"
export MISP_KEY="<clé API — jamais dans le dépôt>"
```

## Connexion

```python
import os
from pymisp import PyMISP, MISPEvent, MISPObject

misp = PyMISP(os.environ["MISP_URL"], os.environ["MISP_KEY"], ssl=True)  # ou ssl="/chemin/ca.pem"
```

## Créer l'événement d'un incident

```python
event = MISPEvent()
event.info = "IR-2026-001 - Compromission poste via macro Office"
event.distribution = 0        # Your organisation only (élargir après validation)
event.threat_level_id = 2     # Medium
event.analysis = 1            # Ongoing
event.add_tag("tlp:amber")
event.add_tag("pap:amber")
event.add_tag('misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059"')

event.add_attribute("ip-dst", "203.0.113.10", category="Network activity",
                    to_ids=True, comment="C2 observé dans Sysmon EID 3")
event.add_attribute("domain", "bad.example", category="Network activity", to_ids=True)

f = MISPObject("file")
f.add_attribute("filename", value="invoice.docm")
f.add_attribute("sha256", value="<sha256>", to_ids=True)
event.add_object(f)

event = misp.add_event(event, pythonify=True)
misp.publish(event)           # seulement quand l'analyse est validée
```

## Rechercher (enrichissement d'alerte)

```python
hits = misp.search(controller="attributes", value="203.0.113.10",
                   to_ids=True, enforce_warninglist=True, pythonify=True)
for a in hits:
    print(a.event_id, a.type, a.value, [t.name for t in a.tags])
```

Équivalent REST :

```bash
curl -s -X POST "$MISP_URL/attributes/restSearch" \
  -H "Authorization: $MISP_KEY" -H "Accept: application/json" -H "Content-Type: application/json" \
  -d '{"returnFormat":"json","value":"203.0.113.10","to_ids":true,"enforceWarninglist":true}'
```

## Sighting (boucle de rétroaction depuis le SIEM)

```python
misp.add_sighting({"value": "203.0.113.10", "type": "0", "source": "wazuh"})
```

## Exports utiles

```bash
# Règles Suricata pour les IoC to_ids des 7 derniers jours
curl -s -X POST "$MISP_URL/events/restSearch" -H "Authorization: $MISP_KEY" \
  -H "Content-Type: application/json" -d '{"returnFormat":"suricata","to_ids":true,"last":"7d"}'

# STIX 2.1 pour un partenaire
curl -s -X POST "$MISP_URL/events/restSearch" -H "Authorization: $MISP_KEY" \
  -H "Content-Type: application/json" -d '{"returnFormat":"stix2","eventid":1234}'
```

Autres `returnFormat` : `json`, `csv`, `text`, `snort`, `zeek`, `rpz`, `openioc`, `stix`, `hashes`.
