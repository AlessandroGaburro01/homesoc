# Fase 4 — Incident Response Layer
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `docs/phase4-incident-response.md`  
**Versione:** 1.0 — Maggio 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 4 — Response: Case Management e Analisi Automatizzata  
**Prerequisiti:** `phase3c-consolidation.md` v1.0 ✅ · `phase3d-deception.md` v1.1 ✅

> **Scopo:** Aggiungere il layer di Incident Response strutturato al HomeSOC. Gli alert Wazuh smettono di essere notifiche isolate e diventano *case* gestibili con stato, timeline, osservabili e azioni documentate. Cortex automatizza l'arricchimento degli osservabili (IP, hash, dominio) contro API di threat intelligence esterne. Al termine di questa fase ogni incidente rilevante genera automaticamente un case TheHive con osservabili pre-arricchiti, pronto per il triage guidato da playbook strutturato.

**Changelog:**
- v1.0 — Maggio 2026 — Prima stesura (scoping e design)

---

## Indice

1. [Principio — Perché l'Incident Response strutturato](#1-principio--perché-lincident-response-strutturato)
2. [Architettura del Response Layer](#2-architettura-del-response-layer)
3. [Decisioni Architetturali](#3-decisioni-architetturali)
4. [Task Overview](#4-task-overview)
5. [T-01 — Provisioning vm-104 su Proxmox](#5-t-01--provisioning-vm-104-su-proxmox)
6. [T-02 — Installazione TheHive 5 + Cortex 3](#6-t-02--installazione-thehive-5--cortex-3)
7. [T-03 — Integrazione Wazuh → TheHive](#7-t-03--integrazione-wazuh--thehive)
8. [T-04 — Cortex Analyzers — VirusTotal, AbuseIPDB, Shodan](#8-t-04--cortex-analyzers--virustotal-abuseipdb-shodan)
9. [T-05 — Playbook IR — 4 Scenari](#9-t-05--playbook-ir--4-scenari)
10. [Verifica End-to-End](#10-verifica-end-to-end)
11. [MITRE ATT&CK Mapping](#11-mitre-attck-mapping)
12. [Aggiornamenti Threat Model e Risk Register](#12-aggiornamenti-threat-model-e-risk-register)

---

## 1. Principio — Perché l'Incident Response strutturato

Fino alla Fase 3d il HomeSOC produce alert: notifiche Slack con IP sorgente, regola attivata e timestamp. Questo è sufficiente per sapere *che cosa è successo*, ma non per gestire *cosa fare dopo*. Un alert che arriva su Slack e non viene processato in modo tracciato non è un incidente gestito — è un incidente ignorato con documentazione.

L'Incident Response strutturato introduce tre cambiamenti fondamentali:

**1. Stato esplicito.** Ogni incidente esiste in un sistema con uno stato definito: *New → In Progress → Resolved*. È impossibile "dimenticare" un alert aperto — rimane visibile fino a chiusura documentata.

**2. Osservabili arricchiti.** Gli IP sorgente, gli hash dei file, i domini malevoli vengono interrogati automaticamente su VirusTotal, AbuseIPDB e Shodan nel momento in cui il case viene creato. Il triage parte da dati di contesto già presenti, non da una query manuale.

**3. Procedure ripetibili.** I playbook trasformano la risposta da attività ad hoc a procedura verificabile con checklist. Questo è l'elemento più rilevante per il portfolio: dimostra che il SOC opera con metodologia, non per istinto.

### 1.1 Confronto stato pre/post Fase 4

| Aspetto | Pre Fase 4 | Post Fase 4 |
|---|---|---|
| Alert tracking | Slack (fire and forget) | TheHive case con stato e timeline |
| Arricchimento osservabili | Manuale (copia IP su VT) | Automatico via Cortex al momento della creazione |
| Procedura di risposta | Implicita / ad hoc | Playbook strutturato per scenario |
| Documentazione incidente | Assente | Case history + note + tag MITRE |
| Visibilità storica | Zero (Slack scrollback) | Dashboard TheHive — tutti i case per periodo |

---

## 2. Architettura del Response Layer

### 2.1 Flusso dati

```
RESPONSE LAYER — HomeSOC Fase 4

┌─────────────────────────────────────────────────────────────────────┐
│ DETECTION (preesistente — Fase 3)                                   │
│                                                                     │
│  Wazuh Manager — vm-103 (192.168.68.204)                           │
│  ├── alert level ≥ 10 → integration script → TheHive API           │
│  ├── alert level ≥ 10 → slack.py → #homesoc-alerts (invariato)     │
│  └── alerts.json / OpenSearch (invariato)                          │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ HTTP POST /api/v1/case
                               │ (custom-thehive.py su vm-103)
┌──────────────────────────────▼──────────────────────────────────────┐
│ CASE MANAGEMENT — vm-104 (192.168.68.205)                           │
│                                                                     │
│  TheHive 5 — porta 9000                                             │
│  ├── Case creato automaticamente per alert level ≥ 10              │
│  ├── Titolo: "HomeSOC — <descrizione regola> [rule XXXXX]"         │
│  ├── Severità mappata da Wazuh level (10-11: Medium, 12-13: High,  │
│  │   14-15: Critical)                                               │
│  ├── Tag: regola Wazuh, MITRE technique ID, segmento rete          │
│  └── Observable aggiunto: src_ip (type: ip) o hash (type: hash)   │
│                               │                                     │
│                               │ analisi observable                  │
│                               ▼                                     │
│  Cortex 3 — porta 9001                                              │
│  ├── Analyzer: VirusTotal_GetReport_3_1 (IP, hash, dominio)        │
│  ├── Analyzer: AbuseIPDB_1_0 (IP — reputation score)              │
│  └── Analyzer: Shodan_Host_1_0 (IP — porte esposte, banner)       │
│                               │                                     │
│                               │ risultato analisi → observable      │
│                               ▼                                     │
│  Cortex chiama API esterne:                                         │
│  ├── api.virustotal.com (HTTPS 443)                                 │
│  ├── api.abuseipdb.com  (HTTPS 443)                                 │
│  └── api.shodan.io      (HTTPS 443)                                 │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               │ triage operativo
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ PLAYBOOK IR                                                         │
│  PB-01: SSH Brute Force         (rule 100001 — T1110.001)          │
│  PB-02: Rogue Device Detected   (rule 100040/41 — T1078)           │
│  PB-03: Greenbone Critical CVE  (rule 100070 — T1190)              │
│  PB-04: Honeypot Interaction    (rule 100080-85 — T1046, T1021)    │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Nuova infrastruttura — vm-104

| ID | Tipo | IP | Hostname | Servizi | Wazuh Agent |
|---|---|---|---|---|---|
| vm-104 | VM Ubuntu 22.04 | 192.168.68.205 | vm-ir | TheHive 5, Cortex 3 | ID 005 |

> **IP assegnazione:** .205 è il gap tra vm-103 (.204) e ct-104 (.206). Coerente con la sequenza corrente dell'inventario.

---

## 3. Decisioni Architetturali

### ADR-04-01 — TheHive 5 Community vs TheHive 4

**Decisione:** TheHive 5 Community (StrangeBee)

**Motivazione:** TheHive 5 ha API v1 più moderne, UI rinnovata, e storage LocalDB integrato che elimina la dipendenza da Cassandra. L'architettura originale in `02-architecture.md` già specifica vm-104 con TheHive 5. TheHive 4 è in manutenzione — nuovi deployment su 5.

### ADR-04-02 — Storage LocalDB vs Cassandra

**Decisione:** LocalDB (BerkeleyDB + filesystem locale)

**Motivazione:** Cassandra richiede almeno 2 GB RAM aggiuntivi e complessità operativa non giustificata per un'istanza single-node home SOC. LocalDB è lo storage default di TheHive 5 Community per deployment piccoli, gestisce egregiamente il volume di case atteso (decine/mese, non migliaia). Risparmio: 2 GB RAM su un host già al 91% del budget allocato.

**Trade-off documentato:** LocalDB non supporta clustering/HA. Accettato — già documentato nel threat model come single point of failure per R-09.

### ADR-04-03 — TheHive e Cortex sulla stessa VM

**Decisione:** Colocate su vm-104

**Motivazione:** TheHive e Cortex comunicano via HTTP locale. Separare su due VM aggiungerebbe 2 GB RAM (VM Proxmox overhead) senza benefici di isolamento rilevanti nel threat model attuale. La comunicazione rimane su loopback, non attraversa la LAN. Budget RAM totale con vm-104: `6 GB (vm-103) + 4 GB (vm-104) + 4 GB (ct-102) + 2 GB (vm-100) + 1 GB (ct-101) + 1 GB (ct-104) + 4 GB (host) = 22 GB su 32 GB`.

### ADR-04-04 — Routing alert verso TheHive

**Decisione:** Tutti gli alert Wazuh level ≥ 10

**Motivazione:** Level 10 è la soglia già usata per Slack. Mantenere la stessa soglia evita divergenze tra il canale di notifica real-time (Slack) e il sistema di case management (TheHive). Alert sotto il 10 sono informativi — non richiedono triage strutturato. I Canarytoken (routing diretto Slack, non via Wazuh) restano esclusi — il loro webhook punta a Slack direttamente.

### ADR-04-05 — Analyzers Cortex: solo tier gratuito

**Decisione:** VirusTotal free (4 req/min), AbuseIPDB free (1000 req/giorno), Shodan free (100 req/mese)

**Motivazione:** Il volume di case atteso non supera le 10-15 analisi/giorno. I limiti free tier sono abbondantemente sufficienti. Le API key vengono registrate con account personale, mai committate nel repo — gestite tramite Cortex UI.

---

## 4. Task Overview

| ID | Titolo | Effort est. | Dipendenze | Stato |
|---|---|---|---|---|
| T-01 | Provisioning vm-104 su Proxmox | 15 min | — | ⬜ |
| T-02 | Installazione TheHive 5 + Cortex 3 | 45 min | T-01 | ⬜ |
| T-03 | Integrazione Wazuh → TheHive | 1h | T-02 | ⬜ |
| T-04 | Cortex analyzers — VT, AbuseIPDB, Shodan | 30 min | T-02 | ⬜ |
| T-05 | Playbook IR — 4 scenari | 2h | T-03, T-04 | ⬜ |

**Ordine esecuzione:** T-01 → T-02 → T-03 → T-04 → T-05

---

## 5. T-01 — Provisioning vm-104 su Proxmox

### 5.1 Creazione VM

```bash
# Su SOC-01 — Proxmox host (192.168.68.200, porta 2222)
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200

# Snapshot vm-103 prima di iniziare (precauzione standard)
qm snapshot 103 pre-phase4 --description "Pre-Phase 4 snapshot"

# Crea vm-104 — Ubuntu 22.04 LTS
qm create 104 \
  --name vm-ir \
  --memory 4096 \
  --cores 2 \
  --net0 virtio,bridge=vmbr0 \
  --scsihw virtio-scsi-pci \
  --scsi0 local-lvm:32 \
  --ide2 local:iso/ubuntu-22.04.4-live-server-amd64.iso,media=cdrom \
  --boot order=ide2 \
  --ostype l26 \
  --agent enabled=1
```

> **ISO:** Verificare nome esatto ISO disponibile: `ls /var/lib/vz/template/iso/`  
> Usare stessa ISO di vm-103 (Ubuntu 22.04.x LTS) per coerenza.

### 5.2 Installazione Ubuntu 22.04

Avviare la VM dalla Proxmox console (`192.168.68.200:8006`).

**Parametri installazione:**
- Hostname: `vm-ir`
- Username: `alessandro`
- Partitioning: LVM sull'intero disco (32 GB)
- OpenSSH Server: abilitato durante setup
- Nessun snap aggiuntivo

### 5.3 Configurazione post-installazione

```bash
# Accesso iniziale via console Proxmox, poi SSH
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.205

# Aggiornamento sistema
sudo apt update && sudo apt full-upgrade -y

# QEMU guest agent (coerenza con vm-103)
sudo apt install -y qemu-guest-agent
sudo systemctl enable --now qemu-guest-agent

# Timezone
sudo timedatectl set-timezone Europe/Rome

# Aggiungi chiave pubblica MacBook per accesso diretto
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILsW59CQJvLyySX2FM9Xp4045yDFc1dRdh5P0u5+ieWp homesoc-admin" \
  >> ~/.ssh/authorized_keys
```

### 5.4 IP statico

```bash
# Ubuntu 22.04 usa Netplan
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  version: 2
  ethernets:
    ens18:
      dhcp4: false
      addresses:
        - 192.168.68.205/24
      routes:
        - to: default
          via: 192.168.68.1
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
```

```bash
sudo netplan apply

# Verifica
ip addr show ens18
# Atteso: inet 192.168.68.205/24
```

### 5.5 Enrollment Wazuh agent (ID 005)

```bash
# Su vm-104
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
  && sudo chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update && sudo apt install -y wazuh-agent

# Configura manager
sudo sed -i 's/MANAGER_IP/192.168.68.204/' /var/ossec/etc/ossec.conf
sudo sed -i 's/<protocol>udp/<protocol>tcp/' /var/ossec/etc/ossec.conf

WAZUH_MANAGER='192.168.68.204' WAZUH_AGENT_NAME='vm-104-ir' \
  sudo /var/ossec/bin/agent-auth -m 192.168.68.204

sudo systemctl enable --now wazuh-agent

# Verifica su vm-103
sudo /var/ossec/bin/agent_control -l
# Atteso: ID 005 vm-104-ir (Active)
```

### 5.6 Entry hosts su vm-103 e MacBook

```bash
# Su vm-103
echo "192.168.68.205 vm-ir vm-ir.local" | sudo tee -a /etc/hosts

# Su MacBook (END-05)
echo "192.168.68.205 vm-ir vm-ir.local" | sudo tee -a /etc/hosts
```

### 5.7 Criterio di completamento T-01

- [ ] `ping 192.168.68.205` da vm-103 risponde
- [ ] SSH `ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.205` funziona da MacBook
- [ ] Wazuh agent ID 005 in stato Active su vm-103
- [ ] `qemu-guest-agent` attivo — vm-104 visibile come Online in Proxmox

---

## 6. T-02 — Installazione TheHive 5 + Cortex 3

### 6.1 Dipendenze Java

TheHive 5 e Cortex 3 richiedono entrambi Java 11.

```bash
# Su vm-104
sudo apt install -y openjdk-11-jre-headless

java -version
# Atteso: openjdk version "11.x.x"
```

### 6.2 Repository TheHive Project

```bash
wget -qO- https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY \
  | sudo gpg --dearmor -o /usr/share/keyrings/thehive-project-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/thehive-project-archive-keyring.gpg] \
  https://deb.thehive-project.org release main" \
  | sudo tee /etc/apt/sources.list.d/thehive-project.list

sudo apt update
```

### 6.3 Installazione TheHive 5

```bash
sudo apt install -y thehive
```

### 6.4 Configurazione TheHive

```bash
sudo nano /etc/thehive/application.conf
```

**Sezioni da modificare/verificare:**

```hocon
# Secret key — genera una stringa random
play.http.secret.key = "<STRINGA_RANDOM_64_CHAR>"

# Storage LocalDB (default community — nessuna Cassandra)
storage {
  provider = localfs
  localfs.location = /opt/thp/thehive/data
}

# Indice locale (nessun OpenSearch/Elasticsearch esterno)
index.search {
  provider = lucene
  lucene.directory = /opt/thp/thehive/index
}

# Porta HTTP
http.port = 9000

# Cortex — verrà configurato dopo T-04
# cortex.servers = [
#   {
#     name = cortex
#     url = "http://127.0.0.1:9001"
#     auth { type = bearer, key = "<CORTEX_API_KEY>" }
#   }
# ]
```

```bash
# Crea directory data con permessi corretti
sudo mkdir -p /opt/thp/thehive/data /opt/thp/thehive/index
sudo chown -R thehive:thehive /opt/thp/thehive/

sudo systemctl enable --now thehive

# Verifica avvio (può richiedere 30-60 secondi)
sudo systemctl status thehive
curl -s http://127.0.0.1:9000/api/v1/status | python3 -m json.tool
# Atteso: {"versions": {...}, "config": {...}}
```

### 6.5 Setup iniziale TheHive — admin user

```bash
# Accedi alla UI: http://192.168.68.205:9000
# Credenziali default prima del setup: admin@thehive.local / secret
# Cambiarle immediatamente al primo accesso
```

**Operazioni UI (prima configurazione):**

1. Login con `admin@thehive.local` / `secret`
2. **Cambia password** admin (impostazioni account)
3. Crea organizzazione: **HomeSOC**
4. Crea utente operativo: `homesoc-ops` con ruolo *Analyst*
5. Crea utente API per Wazuh: `wazuh-integration` con ruolo *Analyst* → genera API key → **annotare in vault locale**

> **Non committare API key nel repo.** Gestione credenziali: annotare in KeePass/Bitwarden locale.

### 6.6 Installazione Cortex 3

```bash
# Su vm-104 — stesso repository già configurato
sudo apt install -y cortex
```

### 6.7 Configurazione Cortex

```bash
sudo nano /etc/cortex/application.conf
```

```hocon
# Secret key — diversa da TheHive
play.http.secret.key = "<STRINGA_RANDOM_64_CHAR_DIVERSA>"

# Porta HTTP
http.port = 9001

# Job directory per risultati analisi
job {
  directory = /opt/thp/cortex/jobs
}
```

```bash
sudo mkdir -p /opt/thp/cortex/jobs
sudo chown -R cortex:cortex /opt/thp/cortex/

sudo systemctl enable --now cortex

curl -s http://127.0.0.1:9001/api/v1/status | python3 -m json.tool
# Atteso: {"versions": {...}}
```

### 6.8 Setup Cortex — admin e organizzazione

**Operazioni UI** su `http://192.168.68.205:9001`:

1. Login primo avvio → crea utente admin Cortex: `cortex-admin` + password forte
2. Crea organizzazione: **HomeSOC**
3. Crea utente operativo: `cortex-ops` con ruolo *Analyst*
4. Crea utente API per TheHive: `thehive-cortex` con ruolo *Analyst* → genera API key → annotare

### 6.9 Collegamento TheHive → Cortex

Tornare nella configurazione TheHive e decommentare il blocco Cortex:

```bash
sudo nano /etc/thehive/application.conf
```

```hocon
cortex.servers = [
  {
    name = cortex
    url = "http://127.0.0.1:9001"
    auth {
      type = bearer
      key = "<CORTEX_API_KEY_DA_STEP_6_8>"
    }
    wsConfig {}
  }
]
```

```bash
sudo systemctl restart thehive

# Verifica connessione TheHive → Cortex dalla UI TheHive:
# Admin → Platform → Cortex → status deve mostrare "Connected"
```

### 6.10 Criterio di completamento T-02

- [ ] `http://192.168.68.205:9000` raggiungibile da MacBook, login funziona
- [ ] `http://192.168.68.205:9001` raggiungibile da MacBook, login funziona
- [ ] TheHive mostra Cortex "Connected" in Admin → Platform
- [ ] Creazione case di test manuale dalla UI → case visibile nella dashboard

---

## 7. T-03 — Integrazione Wazuh → TheHive

### 7.1 Meccanismo integrazione

Wazuh supporta script di integrazione custom: per ogni alert che soddisfa i criteri, `wazuh-integratord` chiama lo script con i dati dell'alert come argomento. Lo script `custom-thehive.py` traduce l'alert JSON in una chiamata API TheHive v1.

**Flusso:**
```
wazuh-analysisd → alert level ≥ 10
     → wazuh-integratord
         → custom-thehive.py <alert_file> <api_key> <thehive_url>
             → POST http://192.168.68.205:9000/api/v1/case
             → POST http://192.168.68.205:9000/api/v1/case/{id}/observable
```

### 7.2 Script di integrazione

**File:** `/var/ossec/integrations/custom-thehive.py`  
**Su:** vm-103 (192.168.68.204)

```python
#!/usr/bin/env python3
"""
Wazuh → TheHive 5 integration script
HomeSOC Project — Fase 4
"""

import sys
import json
import datetime
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Mapping Wazuh level → TheHive severity (1=Low, 2=Medium, 3=High, 4=Critical)
# ---------------------------------------------------------------------------
def _severity(level: int) -> int:
    if level >= 14:
        return 4  # Critical
    if level >= 12:
        return 3  # High
    if level >= 10:
        return 2  # Medium
    return 1      # Low


# ---------------------------------------------------------------------------
# Mapping Wazuh level → TheHive TLP (0=WHITE, 1=GREEN, 2=AMBER, 3=RED)
# ---------------------------------------------------------------------------
def _tlp(level: int) -> int:
    if level >= 14:
        return 3  # RED
    if level >= 12:
        return 2  # AMBER
    return 1      # GREEN


def _post(url: str, data: dict, api_key: str) -> dict:
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_err = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} → {body_err}") from e


def create_case(alert: dict, api_key: str, thehive_url: str) -> str:
    rule_id   = alert.get("rule", {}).get("id", "?")
    rule_desc = alert.get("rule", {}).get("description", "Unknown alert")
    level     = int(alert.get("rule", {}).get("level", 10))
    agent     = alert.get("agent", {}).get("name", "unknown-agent")
    timestamp = alert.get("timestamp", datetime.datetime.utcnow().isoformat())

    # MITRE tags
    mitre_ids = [
        t.get("id", "")
        for t in alert.get("rule", {}).get("mitre", {}).get("technique", [])
        if t.get("id")
    ]

    tags = ["wazuh", f"rule:{rule_id}", f"agent:{agent}"] + mitre_ids

    # Build description (markdown in TheHive)
    groups = alert.get("rule", {}).get("groups", [])
    src_ip  = alert.get("data", {}).get("srcip", "") or \
              alert.get("decoder", {}).get("parent", "")

    desc_lines = [
        f"**Alert Wazuh** — rule `{rule_id}` livello `{level}`",
        f"**Agent:** `{agent}`",
        f"**Timestamp:** `{timestamp}`",
    ]
    if src_ip:
        desc_lines.append(f"**Source IP:** `{src_ip}`")
    if groups:
        desc_lines.append(f"**Groups:** `{', '.join(groups)}`")
    if mitre_ids:
        desc_lines.append(f"**MITRE ATT&CK:** `{', '.join(mitre_ids)}`")
    desc_lines.append(f"\n```json\n{json.dumps(alert, indent=2)}\n```")

    case_payload = {
        "title": f"HomeSOC — {rule_desc} [rule {rule_id}]",
        "description": "\n".join(desc_lines),
        "severity": _severity(level),
        "tlp": _tlp(level),
        "tags": tags,
        "flag": False,
    }

    result = _post(f"{thehive_url}/api/v1/case", case_payload, api_key)
    return result.get("_id", "")


def add_observable(case_id: str, obs_type: str, obs_value: str,
                   message: str, api_key: str, thehive_url: str) -> None:
    if not obs_value or not obs_value.strip():
        return
    payload = {
        "dataType": obs_type,
        "data": obs_value.strip(),
        "message": message,
        "tlp": 2,
        "ioc": False,
        "tags": ["wazuh-auto"],
    }
    _post(f"{thehive_url}/api/v1/case/{case_id}/observable", payload, api_key)


def main():
    if len(sys.argv) < 4:
        sys.exit(0)

    alert_file   = sys.argv[1]
    api_key      = sys.argv[2]
    thehive_url  = sys.argv[3].rstrip("/")

    try:
        with open(alert_file, encoding="utf-8") as fh:
            alert = json.load(fh)
    except Exception:
        sys.exit(0)

    try:
        case_id = create_case(alert, api_key, thehive_url)
    except Exception as exc:
        # Log su stderr — wazuh-integratord lo scrive in ossec.log
        print(f"[custom-thehive] ERROR creating case: {exc}", file=sys.stderr)
        sys.exit(1)

    if not case_id:
        sys.exit(0)

    # Aggiungi osservabili estratti dall'alert
    src_ip   = alert.get("data", {}).get("srcip", "")
    src_host = alert.get("data", {}).get("src_host", "")
    file_hash = (
        alert.get("syscheck", {}).get("md5_after", "") or
        alert.get("data", {}).get("sha256", "")
    )
    domain   = alert.get("data", {}).get("hostname", "")

    if src_ip:
        add_observable(case_id, "ip", src_ip,
                       "Source IP from Wazuh alert", api_key, thehive_url)
    elif src_host:
        add_observable(case_id, "ip", src_host,
                       "Source host from Wazuh alert", api_key, thehive_url)
    if file_hash:
        obs_type = "hash" if len(file_hash) == 64 else "hash"
        add_observable(case_id, obs_type, file_hash,
                       "File hash from FIM alert", api_key, thehive_url)
    if domain and "." in domain:
        add_observable(case_id, "domain", domain,
                       "Domain from DNS alert", api_key, thehive_url)

    print(f"[custom-thehive] Case created: {case_id}", file=sys.stderr)


if __name__ == "__main__":
    main()
```

```bash
# Su vm-103 — deploy script
sudo cp custom-thehive.py /var/ossec/integrations/custom-thehive.py
sudo chmod 750 /var/ossec/integrations/custom-thehive.py
sudo chown root:wazuh /var/ossec/integrations/custom-thehive.py

# Test manuale (verifica syntax)
python3 /var/ossec/integrations/custom-thehive.py 2>&1
# Atteso: uscita senza errori (sys.exit(0) per argomenti mancanti)
```

### 7.3 Configurazione ossec.conf

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Aggiungere nel blocco `<ossec_config>`, dopo le integration Slack esistenti:

```xml
<!-- TheHive — case management per alert level >= 10 -->
<integration>
  <name>custom-thehive</name>
  <hook_url>http://192.168.68.205:9000</hook_url>
  <api_key><WAZUH_INTEGRATION_API_KEY_DA_STEP_6_5></api_key>
  <alert_format>json</alert_format>
  <level>10</level>
</integration>
```

```bash
# Verifica configurazione Wazuh
sudo /var/ossec/bin/wazuh-analysisd -t
# Atteso: nessun errore di configurazione

sudo systemctl restart wazuh-manager

# Verifica integratord attivo
sudo grep -i "thehive\|integrat" /var/ossec/logs/ossec.log | tail -10
```

### 7.4 Criterio di completamento T-03

- [ ] `wazuh-analysisd -t` pulito dopo modifica ossec.conf
- [ ] Test manuale: triggera rule 100001 (5 SSH falliti verso SOC-01) → case TheHive creato
- [ ] Case TheHive contiene: titolo corretto, livello severità, tag `rule:100001`, observable `ip`
- [ ] Alert Slack continua ad arrivare invariato (le due integrazioni sono indipendenti)

---

## 8. T-04 — Cortex Analyzers — VirusTotal, AbuseIPDB, Shodan

### 8.1 Installazione analyzer package

```bash
# Su vm-104
sudo apt install -y cortex-analyzers

# Verifica percorso analyzer
ls /opt/cortex/analyzers/
# Devono essere presenti: VirusTotal, AbuseIPDB, Shodan (tra gli altri)
```

> Se il pacchetto non è disponibile via apt, installare da repo ufficiale:
> ```bash
> sudo pip3 install cortexutils
> sudo git clone https://github.com/TheHive-Project/Cortex-Analyzers.git /opt/cortex/analyzers
> ```

### 8.2 Configurazione analyzers in Cortex UI

Accedere a `http://192.168.68.205:9001` come `cortex-admin`.

**Admin → Organizations → HomeSOC → Analyzers**

Abilitare e configurare i seguenti:

#### VirusTotal_GetReport_3_1

| Parametro | Valore |
|---|---|
| API Key | `<VT_API_KEY>` — account free su virustotal.com |
| Rate (req/min) | 4 (limite free tier) |
| Input types | ip, domain, hash, url |

#### AbuseIPDB_1_0

| Parametro | Valore |
|---|---|
| API Key | `<ABUSEIPDB_API_KEY>` — account free su abuseipdb.com |
| Max age (giorni) | 30 |
| Input types | ip |

#### Shodan_Host_1_0

| Parametro | Valore |
|---|---|
| API Key | `<SHODAN_API_KEY>` — account free su shodan.io |
| Input types | ip |

> **API Key storage:** Le chiavi vengono salvate nella configurazione Cortex (database locale). Non vengono mai esposte sulla LAN né committate su Git. Rigenera se compromesse.

### 8.3 Auto-run analyzers su observable creation

In TheHive UI: **Admin → Organizations → HomeSOC → Analyzers**  
Per ogni observable aggiunto automaticamente dall'integration Wazuh, abilitare il trigger automatico:

- Observable type `ip` → esegui automaticamente: VirusTotal, AbuseIPDB, Shodan
- Observable type `hash` → esegui automaticamente: VirusTotal
- Observable type `domain` → esegui automaticamente: VirusTotal

Questa configurazione fa sì che ogni observable inserito dallo script Wazuh venga arricchito senza azione manuale.

### 8.4 Criterio di completamento T-04

- [ ] Test manuale Cortex: inserire IP noto malevolo (es. `1.2.3.4`) in un case di test → risultati da tutti e 3 gli analyzer visibili nel case
- [ ] AbuseIPDB restituisce confidence score
- [ ] VirusTotal restituisce detection ratio
- [ ] Shodan restituisce porte/banner (anche `No information available` è un risultato valido)

---

## 9. T-05 — Playbook IR — 4 Scenari

I playbook sono documenti operativi standalone committati in `playbooks/`. Questa sezione contiene la struttura completa di ciascuno.

**File prodotti da questa fase:**
- `playbooks/PB-01-ssh-brute-force.md`
- `playbooks/PB-02-rogue-device.md`
- `playbooks/PB-03-greenbone-critical.md`
- `playbooks/PB-04-honeypot-interaction.md`

**Template struttura playbook:**

```
Trigger → Triage → Containment → Eradication → Recovery → Lessons Learned
```

---

### PB-01 — SSH Brute Force

**File:** `playbooks/PB-01-ssh-brute-force.md`  
**Trigger:** Rule 100001 (level 10) — ≥5 SSH failures in 60s  
**MITRE:** T1110.001 — Brute Force: Password Guessing  
**Asset esposto:** SOC-01 (192.168.68.200:2222)

#### Triage (5 min)

```bash
# 1. Identifica IP sorgente dal case TheHive o da alerts.json
sudo grep '"id":"100001"' /var/ossec/logs/alerts/alerts.json \
  | tail -5 | python3 -c "
import sys, json
for line in sys.stdin:
    a = json.loads(line)
    print(a['timestamp'], a['data'].get('srcip','?'), a['rule']['description'])
"

# 2. Verifica se l'IP è già bloccato da CrowdSec
sudo cscli decisions list | grep <IP_SORGENTE>

# 3. Verifica se ci sono login riusciti dopo il brute force
sudo grep "Accepted" /var/log/auth.log | grep <IP_SORGENTE>
```

**Domande triage:**
- L'IP è interno (192.168.68.0/24)? → possibile device compromesso, escalate a PB-02
- Ci sono login riusciti dallo stesso IP? → severity Critical, containment immediato
- Il pattern è distribuito (molti IP diversi)? → possibile password spray coordinato

#### Containment

```bash
# CrowdSec Active Response già attivo (Fase 3b) — blocco automatico
# Verifica che il ban sia stato applicato
sudo cscli decisions list | grep <IP_SORGENTE>

# Se non presente (es. IP interno non coperto da CrowdSec):
sudo iptables -I INPUT -s <IP_SORGENTE> -j DROP
# Documentare nel case TheHive come azione manuale

# Endlessh già attivo su :22 — eventuali retry futuri vengono intrappolati
```

#### Eradication

- Se IP esterno: nessuna azione aggiuntiva richiesta (ban CrowdSec temporaneo sufficiente)
- Se IP interno: identificare il device (`rogue-device-check.sh` o arp-scan), seguire PB-02
- Aumentare threshold temporaneamente se rumore eccessivo: edit rule 100001 `<frequency>10</frequency>`

#### Recovery

```bash
# Verifica che il server sia operativo
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 "uptime"

# Controlla audit log per accessi avvenuti durante l'attacco
sudo last -20 | head -20
```

#### Chiusura case TheHive

- Tag aggiunto: `resolved`, `external-brute-force` o `internal-compromise`
- Severity finale documentata
- Action summary: ban CrowdSec confermato / ban manuale applicato
- Lessons learned: note su IP, volume tentativi, orario

---

### PB-02 — Rogue Device Detected

**File:** `playbooks/PB-02-rogue-device.md`  
**Trigger:** Rule 100040 (level 12, MAC non in whitelist) o 100041 (level 8, primo accesso MAC noto)  
**MITRE:** T1078 — Valid Accounts (uso rete con credenziale SSID)  
**Asset esposto:** Tutta la LAN flat 192.168.68.0/24

#### Triage (10 min)

```bash
# 1. Identifica MAC e IP del device da alert
sudo grep '"id":"100040"\|"id":"100041"' /var/ossec/logs/alerts/alerts.json \
  | tail -3 | python3 -c "
import sys, json
for line in sys.stdin:
    a = json.loads(line)
    d = a.get('data', {})
    print(a['timestamp'], 'MAC:', d.get('mac','?'), 'IP:', d.get('ip','?'), 'OUI:', d.get('vendor','?'))
"

# 2. Lookup vendor MAC
curl -s "https://api.macvendors.com/<MAC_SENZA_COLONS>" 2>/dev/null || \
  echo "Query vendor API"

# 3. Cerca device nella LAN via arp
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "arp -n | grep <IP_DEVICE>"
```

**Domande triage:**
- Il vendor MAC corrisponde a un dispositivo atteso (es. Apple = iPhone ospite)?
- Il device è presente fisicamente o è accesso remoto?
- L'orario corrisponde a un accesso noto (ospite di casa)?

#### Containment

```bash
# Se device non riconoscibile: isolare via SSID guest (manuale su Deco app)
# Nessun isolamento automatico disponibile in flat network senza OPNsense
# Documentare limitazione R-05 nel case

# Rotazione password WiFi se compromissione SSID confermata
# (operazione manuale — Deco app)
```

> **Nota limitazione:** In assenza di OPNsense e VLAN, il contenimento si limita alla rotazione password SSID. Questa limitazione è documentata come R-05 e R-07 nel risk register. Il case TheHive documenta l'evento anche se containment completo non è possibile.

#### Recovery

- Whitelist MAC se device legittimo: aggiungere in `/var/ossec/etc/lists/mac-whitelist.txt` su vm-103
- Ricarica regola: `sudo systemctl restart wazuh-manager`

---

### PB-03 — Greenbone Critical CVE

**File:** `playbooks/PB-03-greenbone-critical.md`  
**Trigger:** Rule 100070 (level 14) — Greenbone finding CVSS ≥ 7.0  
**MITRE:** T1190 — Exploit Public-Facing Application  
**Asset esposto:** host scansionato (variabile — dipende da scan target)

#### Triage (15 min)

```bash
# 1. Identifica CVE e asset dall'alert
sudo grep '"id":"100070"' /var/ossec/logs/alerts/alerts.json \
  | tail -3 | python3 -c "
import sys, json
for line in sys.stdin:
    a = json.loads(line)
    d = a.get('data', {})
    print(a['timestamp'])
    print('  CVE:', d.get('cve','?'), 'CVSS:', d.get('cvss','?'))
    print('  Host:', d.get('host','?'), 'Port:', d.get('vuln_port','?'))
    print('  Name:', d.get('name','?'))
"

# 2. Verifica se il servizio vulnerabile è esposto in LAN o solo localhost
nmap -p <PORTA> <IP_HOST> --open

# 3. Verifica versione del pacchetto incriminato
ssh <HOST> "dpkg -l | grep <PACCHETTO>" 2>/dev/null || \
  echo "Accesso manuale richiesto"
```

**Domande triage:**
- Il servizio è esposto su LAN o solo localhost? (impatto diverso)
- Esiste exploit pubblico noto per la CVE? (NVD, Exploit-DB)
- Greenbone ha già suggerito un fix (patch disponibile)?

#### Containment

- Valuta se il servizio può essere temporaneamente disabilitato
- Se servizio critico: aumenta monitoring (Uptime Kuma alert + Wazuh FIM su file di configurazione)

#### Eradication

```bash
# Applica patch — dipende dall'host e dal servizio
# Esempio host Linux:
sudo apt update && sudo apt upgrade -y <PACCHETTO>

# Verifica post-patch
dpkg -l | grep <PACCHETTO>
```

#### Recovery

- Triggera re-scan Greenbone manuale per verificare che la finding sia sparita
- Greenbone UI → Scans → New scan su IP specifico
- Verifica che la rule 100070 non si riattivi entro 24h

---

### PB-04 — Honeypot Interaction

**File:** `playbooks/PB-04-honeypot-interaction.md`  
**Trigger:** Rules 100080–100085 (level 10–14) — OpenCanary o Endlessh  
**MITRE:** T1046 (Discovery), T1021.004 (SSH), T1110 (Brute Force)  
**Asset:** ct-104 backup-srv (192.168.68.206), SOC-01 Endlessh (:22)

> **Premessa:** Qualsiasi interazione con il honeypot è per definizione non autorizzata. Non esistono falsi positivi strutturali per questo playbook. La severità è sempre almeno High (level 12).

#### Triage (5 min)

```bash
# 1. Identifica source e tipo di interazione
sudo grep '"id":"1008[0-5]"' /var/ossec/logs/alerts/alerts.json \
  | tail -5 | python3 -c "
import sys, json
for line in sys.stdin:
    a = json.loads(line)
    d = a.get('data', {})
    print(a['timestamp'], 'Rule:', a['rule']['id'])
    print('  Src:', d.get('src_host', d.get('srcip','?')), 'Port:', d.get('dst_port','?'))
    print('  Type:', d.get('logtype','?'), 'Node:', d.get('node_id','?'))
"

# 2. IP sorgente — è interno o esterno?
# Interno (192.168.68.x): device LAN compromesso o utente non autorizzato
# Esterno: accesso da internet (porta NON esposta su router — vedere nota)
```

> **Nota:** Il router Deco non espone la porta 22 di ct-104 verso internet. Una sorgente esterna indica traffico Tailscale oppure un problema di configurazione NAT da investigare urgentemente.

**Scenario A — IP sorgente interno:** Priorità Alta. Device LAN che scansiona attivamente la rete o tenta accesso. Può indicare: device compromesso, accesso non autorizzato da ospite, malware laterale.

**Scenario B — IP sorgente Tailscale (100.x.x.x):** Verifica se sei stato tu. Se no: credenziali Tailscale compromesse. Priorità Critica.

#### Containment

```bash
# Scenario A — IP interno
# Identifica device tramite MAC (Deco app o arp-scan)
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "arp -n | grep <IP_SORGENTE>"

# Isola manualmente via Deco app se confermato device compromesso
# Documenta nel case TheHive

# Scenario B — Tailscale compromesso
tailscale logout   # revoca session attiva
# Poi accedere a https://login.tailscale.com → revoca tutti i device
# Riabilita con nuova autenticazione
```

#### Eradication

- Scenario A: identifica e rimuovi malware dal device compromesso (fuori scope HomeSOC — procedura dipende dal device)
- Scenario B: rigenera chiavi Tailscale, abilita 2FA su account Tailscale

#### Recovery

- Verifica che il honeypot sia ancora attivo: `ssh testuser@192.168.68.206` (da vm-103) → deve rispondere con fake banner
- Verifica Endlessh: `ssh root@192.168.68.200` (da MacBook) → deve time out

---

## 10. Verifica End-to-End

### 10.1 Test integrazione completa

```bash
# Su MacBook (END-05) — genera alert SSH brute force verso SOC-01
for i in $(seq 1 6); do
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
    fakeuser@192.168.68.200 -p 2222 exit 2>/dev/null
done

# Attendi 30 secondi
sleep 30
```

**Verifica sequenziale:**

```bash
# 1. Alert in alerts.json
sudo grep '"id":"100001"' /var/ossec/logs/alerts/alerts.json | tail -1 | \
  python3 -c "import sys,json; a=json.loads(sys.stdin.read()); print('✅ Alert:', a['rule']['description'], 'Level:', a['rule']['level'])"

# 2. Notifica Slack ricevuta (verifica manuale su #homesoc-alerts)
echo "Controlla Slack #homesoc-alerts per messaggio SSH brute force"

# 3. Case TheHive creato
curl -s -H "Authorization: Bearer <WAZUH_INTEGRATION_API_KEY>" \
  "http://192.168.68.205:9000/api/v1/case?range=0-5&sort=-_createdAt" \
  | python3 -c "
import sys, json
cases = json.loads(sys.stdin.read())
for c in cases:
    print('✅ Case:', c['title'], '| Severity:', c['severity'], '| Status:', c['status'])
"

# 4. Observable ip aggiunto al case
# (verificare manualmente in TheHive UI — tab Observables del case)
```

### 10.2 Test Cortex analyzer

```bash
# In TheHive UI: aprire il case creato nel test 10.1
# Tab Observables → click sull'IP sorgente → "Run analyzers"
# Selezionare: VirusTotal, AbuseIPDB, Shodan
# Attendi 30-60 secondi → risultati devono apparire nei mini-report
```

**Atteso:**
- AbuseIPDB: confidence score (anche 0% se IP pulito)
- VirusTotal: detection ratio (es. `0/94`)
- Shodan: informazioni host o `No information available`

### 10.3 Test playbook PB-01

Aprire il case TheHive generato nel test 10.1.  
Seguire il playbook PB-01 dall'inizio: eseguire ogni comando di triage, documentare le risposte nel case come note.  
Chiudere il case con status `Resolved` e tag `test`.

---

## 11. MITRE ATT&CK Mapping

| Tecnica | ID | Copertura aggiunta in Fase 4 | Componente |
|---|---|---|---|
| Brute Force: Password Guessing | T1110.001 | IR strutturato — case + playbook | PB-01, TheHive |
| Valid Accounts | T1078 | IR strutturato — case + playbook | PB-02, TheHive |
| Exploit Public-Facing Application | T1190 | IR strutturato — case + playbook | PB-03, TheHive |
| Network Service Discovery | T1046 | IR strutturato — case + playbook | PB-04, TheHive |
| Remote Services: SSH | T1021.004 | IR strutturato — case + playbook | PB-04, TheHive |
| Command & Control (generic) | — | Arricchimento IoC via Cortex → VirusTotal/Shodan | Cortex analyzers |

> **ATT&CK Navigator:** aggiornare `configs/attack-navigator/homesoc-layer-v1.json` → aggiungere T1078, T1190 al tier "High" (caso management attivo) per le tecniche già mappate in Fase 3.

---

## 12. Aggiornamenti Threat Model e Risk Register

### Risk register — impatto Fase 4

| Rischio | Stato pre-Fase 4 | Stato post-Fase 4 | Note |
|---|---|---|---|
| R-10 — SSH brute force | Mitigato ✅ (CrowdSec + Endlessh) | Mitigato ✅ (+ IR strutturato) | Ogni evento genera case TheHive con arricchimento automatico |
| R-05 — Lateral movement | Open (no VLAN) | Parzialmente mitigato | Honeypot rileva, PB-04 guida risposta; VLAN rimane deferred |
| R-09 — Accesso non auth SOC | Mitigato ✅ (Fase 3d) | Mitigato ✅ (+ playbook) | PB-04 formalizza la risposta all'alert honeypot |
| R-06 — WD NAS cloud relay | Parziale | Parziale | CVE su NAS documentate in PB-03 con procedura di triage |

### Aggiornamento `01-threat-model.md`

Sezione Controlli Attivi: aggiungere voce **Incident Response Layer**:
- TheHive 5: case management automatico per alert level ≥ 10
- Cortex 3: arricchimento automatico IP/hash/domain via VirusTotal, AbuseIPDB, Shodan
- 4 Playbook IR operativi: SSH brute force, rogue device, CVE critica, honeypot

### Aggiornamento `02-architecture.md`

Sezione 3 (Logical Security Architecture): aggiornare layer L4 e L5 da "Fase 4 — Planned" a "Fase 4 — Operational".  
Sezione 5 (Proxmox VM/CT Layout): aggiornare vm-104 IP a `192.168.68.205` e status a "Deployed".

---

## Checklist finale Fase 4

| # | Verifica | Stato |
|---|---|---|
| 1 | vm-104 operativa — IP .205, SSH, Wazuh agent ID 005 | ⬜ |
| 2 | TheHive 5 raggiungibile su :9000, login funziona | ⬜ |
| 3 | Cortex 3 raggiungibile su :9001, connesso a TheHive | ⬜ |
| 4 | Wazuh integration script deployato, `wazuh-analysisd -t` pulito | ⬜ |
| 5 | Test alert SSH → case TheHive creato automaticamente | ⬜ |
| 6 | Observable IP aggiunto al case automaticamente | ⬜ |
| 7 | Cortex analyzers (VT, AbuseIPDB, Shodan) testati su observable IP | ⬜ |
| 8 | 4 playbook committati in `playbooks/` | ⬜ |
| 9 | PB-01 eseguito su case di test end-to-end | ⬜ |
| 10 | `01-threat-model.md` e `02-architecture.md` aggiornati | ⬜ |
| 11 | CHANGELOG.md aggiornato con voce `[1.0.0]` | ⬜ |
| 12 | README.md: Phase 4 status → ✅ Complete | ⬜ |

---

*File: `docs/phase4-incident-response.md` · v1.0 · Maggio 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
