# Intégration Wazuh ↔ MISP

Principe : le manager Wazuh déclenche un script d'intégration sur certaines alertes (Sysmon, FIM),
le script extrait l'observable (hash, IP, domaine), interroge `attributes/restSearch` de MISP et
réinjecte le résultat comme nouvel évènement dans Wazuh, qui le fait matcher par des règles dédiées.

## 1. `ossec.conf` (manager)

```xml
<integration>
  <name>custom-misp</name>   <!-- le nom DOIT commencer par "custom-" -->
  <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

Fichiers : `/var/ossec/integrations/custom-misp` (wrapper shell) + `custom-misp.py`,
propriétaire `root:wazuh`, `chmod 750`. Redémarrer : `systemctl restart wazuh-manager`.

## 2. Observable à extraire selon l'évènement

| Source | Champ Wazuh | Type MISP |
|---|---|---|
| Sysmon EID 1 / 6 / 7 / 15 | `data.win.eventdata.hashes` (`SHA256=...`) | `sha256` |
| Sysmon EID 3 | `data.win.eventdata.destinationIp` (ignorer IP privées) | `ip-dst` |
| Sysmon EID 22 | `data.win.eventdata.queryName` | `domain` / `hostname` |
| Syscheck (FIM) | `syscheck.sha256_after` | `sha256` |

## 3. Squelette du script `custom-misp.py`

```python
#!/var/ossec/framework/python/bin/python3
import json, os, sys, ipaddress, re
from socket import socket, AF_UNIX, SOCK_DGRAM
import requests

SOCKET = "/var/ossec/queue/sockets/queue"
MISP_URL = os.environ.get("MISP_URL", "https://misp.local")
MISP_KEY = open("/var/ossec/etc/misp.key").read().strip()   # chmod 640 root:wazuh, hors dépôt
VERIFY = "/var/ossec/etc/misp-ca.pem"                        # ne pas désactiver TLS

def send(msg, agent):
    loc = f"[{agent['id']}] ({agent['name']}) {agent.get('ip','any')}->misp"
    s = socket(AF_UNIX, SOCK_DGRAM); s.connect(SOCKET)
    s.send(f"1:{loc}:{json.dumps(msg)}".encode()); s.close()

def observable(alert):
    d = alert.get("data", {}).get("win", {}).get("eventdata", {})
    eid = alert.get("data", {}).get("win", {}).get("system", {}).get("eventID")
    if eid in ("1", "6", "7", "15") and "hashes" in d:
        m = re.search(r"SHA256=([0-9A-Fa-f]{64})", d["hashes"]); return m and m.group(1)
    if eid == "3" and d.get("destinationIp"):
        ip = d["destinationIp"]
        return None if ipaddress.ip_address(ip).is_private else ip
    if eid == "22":
        return d.get("queryName")
    return alert.get("syscheck", {}).get("sha256_after")

alert = json.load(open(sys.argv[1]))
value = observable(alert)
if value:
    out = {"integration": "misp"}
    try:
        r = requests.post(f"{MISP_URL}/attributes/restSearch",
                          headers={"Authorization": MISP_KEY, "Accept": "application/json",
                                   "Content-Type": "application/json"},
                          json={"returnFormat": "json", "value": value, "to_ids": True,
                                "enforceWarninglist": True},
                          verify=VERIFY, timeout=10)
        r.raise_for_status()
        attrs = r.json().get("response", {}).get("Attribute", [])
    except Exception as e:
        out["misp"] = {"error": str(e)[:200]}
        send(out, alert["agent"]); sys.exit(0)
    if attrs:
        a = attrs[0]
        out["misp"] = {"event_id": a["event_id"], "category": a["category"], "type": a["type"],
                       "value": a["value"], "source_rule": alert["rule"]["id"]}
    else:
        out["misp"] = {"found": 0, "value": value}
    send(out, alert["agent"])
```

## 4. Règles (`/var/ossec/etc/rules/local_rules.xml`)

```xml
<group name="misp,">
  <rule id="100620" level="10">
    <field name="integration">misp</field>
    <description>MISP: évènement d'intégration</description>
    <options>no_full_log</options>
  </rule>
  <rule id="100621" level="5">
    <if_sid>100620</if_sid>
    <field name="misp.error">\.+</field>
    <description>MISP: erreur de connexion à l'API</description>
  </rule>
  <rule id="100622" level="12">
    <if_sid>100620</if_sid>
    <field name="misp.category">\.+</field>
    <description>MISP: IoC détecté - $(misp.type) $(misp.value) (event $(misp.event_id))</description>
    <group>pci_dss_10.6.1,gdpr_IV_35.7.d,</group>
  </rule>
</group>
```

Ajouter éventuellement une **active response** (blocage firewall de `misp.value`) sur la règle 100622,
et une sighting MISP renvoyée par le script pour fermer la boucle.

## 5. Tests

- Tester la règle : `/var/ossec/bin/wazuh-logtest`.
- Générer un match : ajouter un IoC de test (`to_ids`) dans MISP, puis sur l'agent Windows
  `nslookup <domaine-de-test>` (EID 22) ou exécuter le fichier dont le hash est dans MISP (EID 1).
- Logs : `/var/ossec/logs/integrations.log`, `/var/ossec/logs/ossec.log`, alertes dans `alerts.json`.
