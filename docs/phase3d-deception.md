# Fase 3d — Deception Layer
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `docs/phase3d-deception.md`  
**Versione:** 1.1 — Maggio 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 3d — Advanced Detection tramite Threat Deception  
**Prerequisiti:** `phase3b-hardening.md` v1.2 ✅ · `wazuh-deploy.md` v1.3 ✅ · `phase3c-consolidation.md` v1.0 ✅

> **Scopo:** Aggiungere un livello di detection basato su deception — tecniche che non cercano pattern noti ma aspettano che l'attaccante si tradisca interagendo con risorse che nessun utente legittimo dovrebbe mai toccare. A differenza di signature e threshold, la deception scala con la sofisticazione dell'avversario: più un attore è metodico nell'esplorare la rete, più è probabile che interagisca con le trappole. Al termine di questa fase il HomeSOC è in grado di rilevare accesso non autorizzato anche da attori che bypassano completamente lo stack di detection tradizionale.

**Changelog:**
- v1.1 — Maggio 2026 — Deploy completato in produzione; documentate deviazioni dal piano originale
- v1.0 — Aprile 2026 — Prima stesura (scoping)

---

## Indice

1. [Principio — Perché la Deception](#1-principio--perché-la-deception)
2. [Architettura del Deception Layer](#2-architettura-del-deception-layer)
3. [Task Overview](#3-task-overview)
4. [T-01 — Canarytoken — File e Credenziali Esca](#4-t-01--canarytoken--file-e-credenziali-esca)
5. [T-02 — OpenCanary — Honeypot di Rete](#5-t-02--opencanary--honeypot-di-rete)
6. [T-03 — Endlessh — SSH Tarpit su SOC-01](#6-t-03--endlessh--ssh-tarpit-su-soc-01)
7. [T-04 — Wazuh Integration — Decoder e Regole](#7-t-04--wazuh-integration--decoder-e-regole)
8. [T-05 — Red Team Hardening](#8-t-05--red-team-hardening)
9. [Verifica End-to-End](#9-verifica-end-to-end)
10. [MITRE ATT&CK Mapping](#10-mitre-attck-mapping)
11. [Aggiornamenti Threat Model e Risk Register](#11-aggiornamenti-threat-model-e-risk-register)
12. [Note di Deployment — Deviazioni dal Piano](#12-note-di-deployment--deviazioni-dal-piano)

---

## 1. Principio — Perché la Deception

Lo stack di detection tradizionale (Wazuh, CrowdSec, Greenbone) rileva per **riconoscimento**: identifica pattern noti, supera soglie, matcha signature. Un attore avanzato bypassa questo semplicemente non generando pattern noti — movimento lento, strumenti del sistema operativo, canali legittimi.

La deception funziona al contrario: non cerca nulla, aspetta. Crea risorse che non hanno nessuna ragione legittima di essere toccate — file, credenziali, host, servizi. Qualsiasi interazione con queste risorse è per definizione non autorizzata. Non ci sono falsi positivi strutturali. Non ci sono soglie da calibrare.

**La proprietà chiave:** un attore sofisticato che procede metodicamente nella ricognizione è *più* probabile di toccare una trappola, non meno — la metodicità è essa stessa il vettore di detection.

### 1.1 Confronto con detection tradizionale

| Proprietà | Detection tradizionale | Deception |
|---|---|---|
| Meccanismo | Riconoscimento pattern noti | Attivazione su azione non autorizzata |
| Falsi positivi | Presenti — richiedono tuning | Strutturalmente zero |
| Scalabilità con sofisticazione avversario | Inversamente proporzionale | Direttamente proporzionale |
| Richiede aggiornamenti continui | Sì (signature, threshold) | No |
| Visibilità sul movimento laterale | Parziale | Alta |

---

## 2. Architettura del Deception Layer

### 2.1 Componenti

```
DECEPTION LAYER — HomeSOC Fase 3d

┌─────────────────────────────────────────────────────────────────────┐
│ TRAPPOLE ENDPOINT                                                    │
│                                                                     │
│  END-05 (MacBook .108)              NAS-01 (WD .90)                │
│  ├── ~/Desktop/VPN_Config.docx      ├── /shares/Backup_Creds.docx  │
│  ├── ~/.aws/credentials (fake)      └── /shares/README_Accesso.txt │
│                                                                     │
│  Tipo: Canarytoken (canarytokens.org)                              │
│  Trigger: apertura file → callback HTTP/CloudTrail → Slack         │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│ TRAPPOLE DI RETE                                                     │
│                                                                     │
│  ct-104 / OpenCanary (192.168.68.206) — hostname: backup-srv       │
│  ├── SSH :22    → fake OpenSSH_8.9p1 Ubuntu-3ubuntu0.6             │
│  ├── HTTP :8080 → fake Apache/2.4.57 admin panel                   │
│  ├── FTP :21    → fake ProFTPD 1.3.5e                              │
│  ├── Telnet :23 → fake Ubuntu 22.04 device                         │
│  ├── MySQL :3306 → fake MySQL 8.0.36                               │
│  └── sshd reale :2222 (admin access)                               │
│                                                                     │
│  SOC-01 (192.168.68.200)                                           │
│  └── Endlessh :22 → SSH tarpit (SSH reale su :2222)               │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Wazuh agent (ID 004)
┌──────────────────────────────▼──────────────────────────────────────┐
│ WAZUH SIEM (vm-103 192.168.68.204)                                  │
│  ├── Agent ct-104-opencanary (ID 004) legge opencanary.log         │
│  ├── Decoder: opencanary-decoder.xml (json + endlessh)             │
│  ├── Rules: deception-rules.xml (100080–100085)                    │
│  └── Integration: slack.py routing deception rules                 │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│ SLACK #homesoc-alerts                                               │
│  Canarytoken → Slack (diretto via canarytokens.org webhook)        │
│  OpenCanary → Wazuh agent → slack.py → Slack                       │
│  Endlessh → journald → Wazuh agent → slack.py → Slack              │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Infrastruttura nuova

| ID | Tipo | IP | Hostname | Ruolo | Wazuh Agent |
|---|---|---|---|---|---|
| ct-104 | LXC Debian 12 | 192.168.68.206 | backup-srv | OpenCanary honeypot | ID 004 |

---

## 3. Task Overview

| ID | Titolo | Effort | Detection gain | Dipendenze |
|---|---|---|---|---|
| T-01 | Canarytoken — file e credenziali esca | 30 min | Alto — zero false positive | Nessuna |
| T-02 | OpenCanary — honeypot di rete | 2h | Alto — lateral movement detection | LXC su Proxmox |
| T-03 | Endlessh — SSH tarpit SOC-01 | 30 min | Medio — friction + detection :22 | SOC-01 SSH su :2222 ✅ |
| T-04 | Wazuh integration — decoder e regole | 1h | Prerequisito alert OpenCanary/Endlessh | T-02 e T-03 operativi |
| T-05 | Red team hardening | 30 min | Riduce fingerprinting honeypot | T-02 operativo |

**Ordine eseguito:** T-01 → T-02 → T-03 → T-04 → T-05

---

## 4. T-01 — Canarytoken — File e Credenziali Esca

### 4.1 Principio

Un canarytoken è un token univoco incorporato in un file, una credenziale, o una query DNS. Quando la risorsa viene usata (file aperto, credenziale inviata, dominio risolto), genera un callback verso canarytokens.org che notifica via webhook Slack.

Non richiede infrastruttura locale. Funziona anche da dietro NAT.

### 4.2 Token deployati

| # | Tipo | Filename | Posizione | Trigger |
|---|---|---|---|---|
| TK-01 | Word (.docx) | `Backup_Credenziali_Servizi_2026.docx` | NAS `backup cartella "personale" macbook pro ale /` | Apertura file — qualsiasi Word-compatible viewer |
| TK-02 | Word (.docx) | `VPN_Configurazione_Accesso_Remoto.docx` | MacBook `~/Desktop/` | Apertura file (sostituisce PDF — vedi nota) |
| TK-03 | AWS Keys | `credentials` | MacBook `~/.aws/credentials` | Uso chiave con qualsiasi AWS-compatible tool |
| TK-04 | DNS | dominio `*.canarytokens.com` | Embedded in TK-05 | Risoluzione DNS del record incorporato nel README |
| TK-05 | Plain text | `README_Accesso_Rete.txt` | NAS `backup cartella "personale" macbook pro ale /` | Lettura + risoluzione DNS embedded |

> **Nota TK-02:** Il token PDF non si attiva su macOS con Preview (non carica risorse remote). Sostituito con token Word (.docx) che funziona con Microsoft Word e altri viewer compatibili. Il token PDF rimane valido per attaccanti su Windows con Adobe Acrobat.

### 4.3 Procedura generazione token

**Vai su:** [https://canarytokens.org/generate](https://canarytokens.org/generate)

Per ogni token:
1. Seleziona tipo
2. Webhook: stesso URL Slack usato da Wazuh (`https://hooks.slack.com/services/...`)
3. Memo: `[HomeSOC] TK-0X <descrizione>`
4. Generate → scarica il file

### 4.4 Placement e timestamp

```bash
# NAS — path reale (attenzione: spazio in coda nel nome cartella)
cp ~/Downloads/<token>.docx $'/Volumes/WS_my_cloud_home/backup cartella "personale" macbook pro ale /Backup_Credenziali_Servizi_2026.docx'
touch -t 202510151430 $'/Volumes/WS_my_cloud_home/backup cartella "personale" macbook pro ale /Backup_Credenziali_Servizi_2026.docx'

# MacBook Desktop
cp ~/Downloads/<token>.docx ~/Desktop/VPN_Configurazione_Accesso_Remoto.docx
touch -t 202509201000 ~/Desktop/VPN_Configurazione_Accesso_Remoto.docx

# AWS credentials — formato file
mkdir -p ~/.aws
cat > ~/.aws/credentials << 'EOF'
[default]
aws_access_key_id = <AKID_DA_CANARYTOKENS>
aws_secret_access_key = <SECRET_DA_CANARYTOKENS>
output = json
region = us-east-2
EOF

# README con DNS token incorporato
cat > /tmp/README_Accesso_Rete.txt << 'EOF'
ACCESSO RETE INTERNA — HomeSOC
================================

Server di backup:   backup-srv.local  (192.168.68.206)
NAS principale:     192.168.68.90
Dashboard SOC:      http://192.168.68.204

Per sincronizzazione automatica usare:
  rsync -avz /data/ backup@<TOKEN>.canarytokens.com:/var/backups/homesoc/

Credenziali di servizio in: Backup_Credenziali_Servizi_2026.docx
Accesso remoto VPN: vedere VPN_Configurazione_Accesso_Remoto.docx

Ultimo aggiornamento: 15 ottobre 2025
EOF

cp /tmp/README_Accesso_Rete.txt $'/Volumes/WS_my_cloud_home/backup cartella "personale" macbook pro ale /README_Accesso_Rete.txt'
touch -t 202510151000 $'/Volumes/WS_my_cloud_home/backup cartella "personale" macbook pro ale /README_Accesso_Rete.txt'
```

> **Nota path NAS:** il nome cartella sul WD My Cloud Home ha uno spazio in coda (`ale `) — usare `$'...'` quoting per gestire spazi e virgolette nel path.

---

## 5. T-02 — OpenCanary — Honeypot di Rete (ct-104)

### 5.1 Creazione LXC ct-104

```bash
# Su SOC-01 (porta 2222)
pveam update
pveam download local debian-12-standard_12.12-1_amd64.tar.zst

pct create 104 local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst \
  --hostname backup-srv \
  --memory 512 \
  --swap 256 \
  --cores 1 \
  --net0 name=eth0,bridge=vmbr0,ip=192.168.68.206/24,gw=192.168.68.1 \
  --storage local-lvm \
  --rootfs local-lvm:4 \
  --unprivileged 1 \
  --start 1

pct status 104
ping -c 2 192.168.68.206
```

### 5.2 Installazione OpenCanary

```bash
# Su ct-104 (pct enter 104 da SOC-01)

# Fix DNS — necessario su LXC Debian 12
echo "nameserver 8.8.8.8" > /etc/resolv.conf

apt update && apt install -y python3 python3-pip python3-venv libssl-dev libffi-dev curl

python3 -m venv /opt/opencanary-env
source /opt/opencanary-env/bin/activate
pip install opencanary

opencanaryd --version  # atteso: 0.9.8
mkdir -p /var/log/opencanary
```

### 5.3 Configurazione OpenCanary

> **Nota:** la configurazione viene scritta con Python per evitare problemi di heredoc in terminali interattivi.

```bash
python3 << 'PYEOF'
import json

config = {
    "device.node_id": "backup-srv",
    "ip.ignorelist": [],
    "git.enabled": False,
    "ftp.enabled": True,
    "ftp.port": 21,
    "ftp.banner": "220 ProFTPD 1.3.5e Server (ProFTPD) [192.168.68.206]",
    "http.enabled": True,
    "http.port": 8080,
    "http.banner": "Apache/2.4.57 (Ubuntu)",
    "http.skin": "nasLogin",
    "mysql.enabled": True,
    "mysql.port": 3306,
    "mysql.banner": "5.5.5-8.0.36-0ubuntu0.22.04.1",
    "ssh.enabled": True,
    "ssh.port": 22,
    "ssh.version": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "telnet.enabled": True,
    "telnet.port": 23,
    "telnet.banner": "Ubuntu 22.04.3 LTS",
    "telnet.honeycreds": [{"username": "admin", "password": "admin123"}],
    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {
                "plain": {"format": "%(message)s"}
            },
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": "/var/log/opencanary/opencanary.log",
                    "formatter": "plain"
                }
            }
        }
    }
}

with open('/etc/opencanaryd/opencanary.conf', 'w') as f:
    json.dump(config, f, indent=4)
print("OK")
PYEOF
```

> **Note importanti su OpenCanary 0.9.8:**
> - Il config va in `/etc/opencanaryd/opencanary.conf` (non `/etc/opencanary.conf`)
> - Il MySQL banner richiede il prefisso `5.5.5-` altrimenti OpenCanary lo rifiuta con `ConfigException: Invalid MySQL Banner`
> - Il `SysLogHandler` con host remoto non è supportato nella versione 0.9.8 — il forward syslog viene gestito dal Wazuh agent (vedi T-04)

### 5.4 Spostamento sshd su porta 2222

La porta 22 deve essere libera per OpenCanary. sshd viene spostato su 2222:

```bash
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
# Verificare che non ci siano doppie sostituzioni:
grep -n "Port" /etc/ssh/sshd_config  # deve mostrare: Port 2222
systemctl restart ssh
ss -tlnp | grep ssh  # deve mostrare 2222
```

### 5.5 Avvio OpenCanary

```bash
mkdir -p /etc/opencanaryd

cat > /etc/systemd/system/opencanary.service << 'EOF'
[Unit]
Description=OpenCanary Honeypot
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/opencanary-env/bin/opencanaryd --dev
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable opencanary
systemctl start opencanary
sleep 10
ss -tlnp | grep -E ':21|:22|:23|:3306|:8080'
```

**Output atteso:**
```
LISTEN 0  50  0.0.0.0:21    (twistd)
LISTEN 0  50  0.0.0.0:22    (twistd)
LISTEN 0  50  0.0.0.0:23    (twistd)
LISTEN 0  50  0.0.0.0:3306  (twistd)
LISTEN 0  50  0.0.0.0:8080  (twistd)
LISTEN 0 128  0.0.0.0:2222  (sshd)
```

---

## 6. T-03 — Endlessh — SSH Tarpit su SOC-01

### 6.1 Installazione e configurazione

```bash
# Su SOC-01 (porta 2222)
apt install -y endlessh

mkdir -p /etc/endlessh
cat > /etc/endlessh/config << 'EOF'
Port 22
Delay 10000
MaxClients 4096
LogLevel 1
EOF
```

### 6.2 Systemd service

Il service di default di Endlessh non ha i permessi per bindare porta 22. Sovrascrivere il service file:

```bash
cat > /etc/systemd/system/endlessh.service << 'EOF'
[Unit]
Description=Endlessh SSH Tarpit
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/endlessh -p 22
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable endlessh
systemctl start endlessh
ss -tlnp | grep :22  # deve mostrare endlessh
```

> **Nota:** Il path del binario è `/usr/bin/endlessh` su Debian 12, non `/usr/sbin/endlessh`.

### 6.3 Verifica

```bash
# Da MacBook — deve bloccarsi senza mai mostrare prompt
ssh -o ConnectTimeout=5 root@192.168.68.200
# Atteso: "Connection timed out during banner exchange"

# Log su SOC-01
journalctl -u endlessh -n 5
# Atteso: ACCEPT host=<ip> port=<port> fd=<n> n=1/4096
```

---

## 7. T-04 — Wazuh Integration

### 7.1 Installazione Wazuh agent su ct-104

> **Nota architetturale:** il piano originale prevedeva forward syslog UDP da ct-104 a vm-103. Non implementato perché `wazuh-remoted` occupa già UDP 514 su vm-103 (IPv4) e il `SysLogHandler` remoto non è supportato da OpenCanary 0.9.8. Soluzione: Wazuh agent diretto su ct-104.

```bash
# Su ct-104
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | tee /etc/apt/sources.list.d/wazuh.list

apt update && WAZUH_MANAGER="192.168.68.204" WAZUH_AGENT_NAME="ct-104-opencanary" apt install -y wazuh-agent

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

### 7.2 Configurazione logcollector su ct-104

Aggiungere alla fine di `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/opencanary/opencanary.log</location>
  </localfile>
</ossec_config>
```

> **Nota:** `log_format` deve essere `json`, non `syslog` — il file OpenCanary è JSON puro.

```bash
systemctl restart wazuh-agent

# Verifica su vm-103 che l'agent sia registrato
sudo /var/ossec/bin/agent_control -l
# Atteso: ID 004, Name: ct-104-opencanary, Active
```

### 7.3 Decoder — `opencanary-decoder.xml`

File: `/var/ossec/etc/decoders/opencanary-decoder.xml` su vm-103

```xml
<!-- Decoder Endlessh tarpit -->
<decoder name="endlessh">
  <prematch>endlessh</prematch>
</decoder>

<decoder name="endlessh-fields">
  <parent>endlessh</parent>
  <regex offset="after_parent">ACCEPT host=(\S+) port=(\d+)</regex>
  <order>srcip, srcport</order>
</decoder>
```

> **Nota:** il decoder OpenCanary non è necessario — i log JSON vengono parsati dal decoder `json` nativo di Wazuh. Il file contiene solo il decoder Endlessh.

### 7.4 Regole — `deception-rules.xml`

File: `/var/ossec/etc/rules/deception-rules.xml` su vm-103

Vedere file allegato `detection-rules/deception-rules.xml`.

> **Nota chiave:** la regola 100080 usa `<decoded_as>json</decoded_as>` e `<field name="node_id">backup-srv</field>` — non `<decoded_as>opencanary</decoded_as>` come nel piano originale. Il decoder nativo `json` di Wazuh parsa i log OpenCanary; il campo `node_id` identifica la sorgente.

### 7.5 Aggiornamento slack.py

Aggiungere nella sezione if/elif di routing (prima del blocco `else` finale):

```python
# ---- Deception Layer (Fase 3d) ----
elif rule_id in ("100080", "100082", "100083"):
    msg = _msg_deception_honeypot(alert, data, rule_id)
elif rule_id == "100081":
    msg = _msg_deception_ssh(alert, data, rule_id)
elif rule_id in ("100084", "100085"):
    msg = _msg_deception_tarpit(alert, data, rule_id)
```

Funzioni helper da aggiungere prima di `_msg_generic`:

```python
def _msg_deception_honeypot(alert, data, rule_id):
    src = data.get("src_host", alert.get("agent", {}).get("ip", "N/A"))
    port = data.get("dst_port", "N/A")
    return {
        "color": "#FF4500",
        "title": "🕳️ HONEYPOT INTERACTION",
        "details": f"*Host sorgente:* `{src}`\n*Porta target:* `{port}`\n*Servizio:* OpenCanary — backup-srv"
    }

def _msg_deception_ssh(alert, data, rule_id):
    src = data.get("src_host", alert.get("agent", {}).get("ip", "N/A"))
    return {
        "color": "#FF0000",
        "title": "🚨 HONEYPOT SSH — ALTO RISCHIO",
        "details": f"*Host sorgente:* `{src}`\n*Target:* backup-srv:22 (honeypot SSH)\n*Azione:* Investigare immediatamente"
    }

def _msg_deception_tarpit(alert, data, rule_id):
    srcip = alert.get("data", {}).get("srcip", "N/A")
    return {
        "color": "#FF8C00",
        "title": "🕷️ SSH TARPIT — CONNESSIONE INTRAPPOLATA",
        "details": f"*Sorgente:* `{srcip}`\n*Target:* SOC-01:22 (Endlessh)\n*Stato:* Connessione attiva"
    }
```

### 7.6 Reload Wazuh

```bash
# Su vm-103
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -5  # deve essere silenzioso
sudo systemctl reload wazuh-manager
sudo systemctl is-active wazuh-manager
```

---

## 8. T-05 — Red Team Hardening

### 8.1 Filesystem realistico su ct-104

```bash
mkdir -p /var/backups/homesoc/{daily,weekly}

cat > /var/backups/homesoc/schedule.conf << 'EOF'
# Backup schedule — DO NOT MODIFY
daily=02:00
weekly=Sun 03:00
target=192.168.68.90:/shares/Backup
retention_days=30
EOF

# Log di backup storici (datati)
touch -t 202604200200 /var/log/backup-2026-04-20.log
touch -t 202604210200 /var/log/backup-2026-04-21.log
touch -t 202604220200 /var/log/backup-2026-04-22.log
touch -t 202604230200 /var/log/backup-2026-04-23.log
echo "backup completed: 4 files, 2.3GB" > /var/log/backup-2026-04-24.log
touch -t 202604240200 /var/log/backup-2026-04-24.log
```

### 8.2 MOTD realistico

```bash
cat > /etc/motd << 'EOF'

  backup-srv.local — HomeSOC Backup Server
  ==========================================
  Role:     Automated backup destination
  Storage:  /var/backups/homesoc/
  Schedule: daily 02:00 · weekly Sun 03:00
  Contact:  admin@homesoc.local

  WARNING: Authorized access only.
  All sessions are logged and monitored.

EOF
```

### 8.3 Kernel hardening

```bash
cat >> /etc/sysctl.conf << 'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF
sysctl -p
```

### 8.4 DNS entries

```bash
# Su ct-104
echo "192.168.68.206 backup-srv backup-srv.local" >> /etc/hosts

# Su vm-103
echo "192.168.68.206 backup-srv backup-srv.local" | sudo tee -a /etc/hosts

# Su MacBook END-05
echo "192.168.68.206 backup-srv backup-srv.local" | sudo tee -a /etc/hosts
```

### 8.5 Verifica fingerprint banner

```bash
# Da vm-103 — simula fingerprinting avversario
ssh-keyscan -p 22 192.168.68.206 2>&1 | grep openssh
# Atteso: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 (nessun riferimento a OpenCanary)

echo "QUIT" | nc 192.168.68.206 21
# Atteso: 220 ProFTPD 1.3.5e Server...

curl -sI http://192.168.68.206:8080/ | grep Server
# Atteso: Apache/2.4.57 (Ubuntu)
```

---

## 9. Verifica End-to-End

### 9.1 Test Canarytoken

```bash
# MacBook END-05
open ~/Desktop/VPN_Configurazione_Accesso_Remoto.docx
```

**Atteso:** entro 30 secondi, notifica Slack in `#homesoc-alerts` con source IP e user-agent.

### 9.2 Test OpenCanary SSH → Wazuh → Slack

```bash
# Da vm-103
ssh testuser@192.168.68.206
# Ctrl+C dopo il prompt password

# Verifica alert (attendere 15 secondi)
sudo grep '"id":"100081"' /var/ossec/logs/alerts/alerts.json | tail -1 | \
  python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['rule']['id'], d['rule']['level'], d['rule']['description'][:50])"
# Atteso: 100081 14 OpenCanary: SSH connection attempt on honeypot...
```

**Atteso su Slack:** alert `🚨 HONEYPOT SSH — ALTO RISCHIO` con src_host `192.168.68.204`.

### 9.3 Test OpenCanary HTTP

```bash
# Da vm-103
curl -s http://192.168.68.206:8080/ | head -5
# Atteso: HTML fake login panel

sudo grep '"id":"100082"' /var/ossec/logs/alerts/alerts.json | tail -1
```

### 9.4 Test Endlessh

```bash
# Da MacBook
ssh -o ConnectTimeout=5 root@192.168.68.200
# Atteso: "Connection timed out during banner exchange"

# Verifica log SOC-01
journalctl -u endlessh -n 5 --no-pager
# Atteso: ACCEPT host=::ffff:192.168.68.108 ... CLOSE ... time=<sec> bytes=4
```

---

## 10. MITRE ATT&CK Mapping

| Tecnica | ID | Componente | Regola |
|---|---|---|---|
| Network Service Discovery | T1046 | OpenCanary port probe | 100080, 100083 |
| Remote Services: SSH | T1021.004 | OpenCanary SSH | 100081 |
| Brute Force | T1110 | OpenCanary SSH + Endlessh | 100081, 100084 |
| Brute Force: Password Spraying | T1110.001 | Endlessh multiple connections | 100085 |
| Network Share Discovery | T1135 | OpenCanary HTTP/FTP | 100080, 100082 |
| Exploit Public-Facing Application | T1190 | OpenCanary HTTP | 100082 |
| Unsecured Credentials | T1552 | Canarytoken AWS credentials | TK-03 (direct Slack) |

---

## 11. Aggiornamenti Threat Model e Risk Register

### Risk register — impatto Fase 3d

| Rischio | Stato pre-3d | Stato post-3d | Note |
|---|---|---|---|
| R-09 — Accesso non autorizzato server SOC | Parziale Mitigato | **Mitigato ✅** | Endlessh su :22 + alert immediato |
| R-10 — Brute force SSH | Mitigato ✅ (CrowdSec) | Mitigato ✅ (doppio layer) | CrowdSec ban + Endlessh tarpit su :22 |
| Lateral movement generico | Non coperto | **Coperto** | OpenCanary su 5 porte chiave |
| Credential exposure | Parziale | **Coperto** | Canarytoken AWS — alert anche offline/NAT |

### Aggiornamento `01-threat-model.md`

Sezione 2 (Controlli attivi): aggiungere voce **Deception Layer**:
- Canarytoken: 5 token su MacBook e NAS
- OpenCanary: honeypot ct-104 su 5 porte (SSH/FTP/HTTP/Telnet/MySQL)
- Endlessh: SSH tarpit su SOC-01:22

---

## 12. Note di Deployment — Deviazioni dal Piano

Questa sezione documenta le differenze tra il piano originale (v1.0) e il deployment effettivo, con la motivazione tecnica.

| # | Piano v1.0 | Deployment effettivo | Motivazione |
|---|---|---|---|
| 1 | TK-02 token PDF | Token Word (.docx) | macOS Preview non carica risorse remote — il token PDF non si attiva. Word funziona correttamente |
| 2 | Forward syslog UDP ct-104 → vm-103:514 | Wazuh agent (ID 004) su ct-104 | `wazuh-remoted` occupa UDP 514 IPv4 su vm-103; `SysLogHandler` remoto non supportato in OpenCanary 0.9.8 |
| 3 | Decoder custom `<decoded_as>opencanary</decoded_as>` | `<decoded_as>json</decoded_as>` + `<field name="node_id">backup-srv</field>` | I log OpenCanary sono JSON puro — il decoder `json` nativo di Wazuh li parsa automaticamente; il prematch `opencanary` non trova match nel corpo JSON |
| 4 | MySQL banner `8.0.36-0ubuntu0.22.04.1` | `5.5.5-8.0.36-0ubuntu0.22.04.1` | OpenCanary 0.9.8 richiede il prefisso `5.5.5-` per accettare il banner MySQL — senza genera `ConfigException: Invalid MySQL Banner` |
| 5 | sshd su ct-104 implicito su :22 | sshd spostato su :2222 | OpenCanary deve bindare :22; sshd e OpenCanary non possono coesistere sulla stessa porta |
| 6 | Config OpenCanary via heredoc | Config via script Python | Il terminale interattivo (pct enter) corrompe gli heredoc con testo > ~20 righe — Python `json.dump()` è deterministico e immune |
| 7 | Gestione log syslog | `log_format: json` nel localfile Wazuh | Il formato del file OpenCanary è JSON — `syslog` non lo parsa correttamente |

---

*File: `docs/phase3d-deception.md` · v1.1 · Maggio 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
