# Fase 3d — Deception Layer
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `docs/phase3d-deception.md`  
**Versione:** 1.0 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 3d — Advanced Detection tramite Threat Deception  
**Prerequisiti:** `phase3b-hardening.md` v1.2 ✅ · `wazuh-deploy.md` v1.3 ✅ · `crowdsec-deploy.md` v1.2 ✅

> **Scopo:** Aggiungere un livello di detection basato su deception — tecniche che non cercano pattern noti ma aspettano che l'attaccante si tradisca interagendo con risorse che nessun utente legittimo dovrebbe mai toccare. A differenza di signature e threshold, la deception scala con la sofisticazione dell'avversario: più un attore è metodico nell'esplorare la rete, più è probabile che interagisca con le trappole. Al termine di questa fase il HomeSOC è in grado di rilevare accesso non autorizzato anche da attori che bypassano completamente lo stack di detection tradizionale.

**Changelog:**
- v1.0 — Aprile 2026 — Prima stesura

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
│  END-05 (MacBook .108)          NAS-01 (WD .90)                    │
│  ├── ~/Desktop/VPN_Config.pdf   ├── /shares/Backup_Creds.docx      │
│  ├── ~/.aws/credentials (fake)  └── /shares/README_Accesso.txt     │
│  └── ~/Documents/SSH_Keys.txt                                       │
│                                                                     │
│  Tipo: Canarytoken (canarytokens.org)                              │
│  Trigger: apertura file → callback HTTP → Slack                     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│ TRAPPOLE DI RETE                                                     │
│                                                                     │
│  ct-104 / OpenCanary (192.168.68.206)                              │
│  ├── SSH :22   → fake Ubuntu server (banner customizzato)          │
│  ├── HTTP :8080 → fake admin panel                                 │
│  ├── FTP :21   → fake file server                                  │
│  ├── Telnet :23 → vecchio device IoT                               │
│  └── MySQL :3306 → fake database                                   │
│                                                                     │
│  SOC-01 (192.168.68.200)                                           │
│  └── Endlessh :22 → SSH tarpit (SSH reale su :2222)               │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ syslog / file
┌──────────────────────────────▼──────────────────────────────────────┐
│ WAZUH SIEM (vm-103 192.168.68.204)                                  │
│  ├── Decoder: opencanary-decoder.xml                               │
│  ├── Decoder: endlessh-decoder.xml                                 │
│  ├── Rules: 100080–100085                                          │
│  └── Integration: slack.py (alert level ≥ 12)                     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│ SLACK #homesoc-alerts                                               │
│  Canarytoken → Slack (diretto via canarytokens.org webhook)        │
│  OpenCanary → Wazuh → slack.py → Slack                            │
│  Endlessh → Wazuh → slack.py → Slack                              │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Infrastruttura nuova

| ID | Tipo | IP | Hostname | Ruolo |
|---|---|---|---|---|
| ct-104 | LXC Debian 12 | 192.168.68.206 | backup-srv | OpenCanary honeypot |

---

## 3. Task Overview

| ID | Titolo | Effort | Detection gain | Dipendenze |
|---|---|---|---|---|
| T-01 | Canarytoken — file e credenziali esca | 30 min | Alto — zero false positive, detection garantita vs qualsiasi attore | Nessuna |
| T-02 | OpenCanary — honeypot di rete | 2h | Alto — lateral movement, port scan interno, ricognizione servizi | LXC su Proxmox |
| T-03 | Endlessh — SSH tarpit SOC-01 | 30 min | Medio — friction + detection su porta 22 | SOC-01 SSH su :2222 (✅ già fatto) |
| T-04 | Wazuh integration — decoder e regole | 1h | Prerequisito per alert OpenCanary/Endlessh | T-02 e T-03 operativi |
| T-05 | Red team hardening | 30 min | Riduce fingerprinting honeypot | T-02 operativo |

**Ordine:** T-01 → T-03 → T-02 → T-04 → T-05

---

## 4. T-01 — Canarytoken — File e Credenziali Esca

### 4.1 Principio

Un canarytoken è un token univoco incorporato in un file, una credenziale, o una query DNS. Quando la risorsa viene usata (file aperto, credenziale inviata, dominio risolto), genera un callback HTTP verso canarytokens.org che notifica immediatamente via webhook Slack.

Non richiede nessuna infrastruttura locale. Il callback avviene anche se l'host che apre il file è dietro NAT — il token è nel payload del file stesso, non nell'IP sorgente.

### 4.2 Token da deployare

| # | Tipo token | Filename | Posizione | Attore simulato |
|---|---|---|---|---|
| TK-01 | Microsoft Word | `Backup_Credenziali_Servizi_2026.docx` | NAS `/shares/Documenti/` | Attaccante che esplora share di rete |
| TK-02 | PDF | `VPN_Configurazione_Accesso_Remoto.pdf` | MacBook `~/Desktop/` | Attaccante con accesso endpoint |
| TK-03 | Credenziali AWS | `credentials` (fake `~/.aws/credentials`) | MacBook `~/.aws/` | Attaccante che cerca chiavi cloud |
| TK-04 | DNS | record `soc-internal.homesoc.local` | — embedded in TK-05 | Attaccante che analizza traffico DNS |
| TK-05 | Plain text | `README_Accesso_Rete.txt` | NAS `/shares/` | Attaccante che legge file di configurazione |

### 4.3 Procedura — generazione token

**Vai su:** [https://canarytokens.org/generate](https://canarytokens.org/generate)

Per ogni token:
1. Seleziona tipo
2. Inserisci Slack webhook URL (stesso usato da Wazuh: `https://hooks.slack.com/services/...`)
3. Inserisci memo descrittivo — es: `[HomeSOC] TK-01 Word NAS /shares/Documenti/`
4. Genera e scarica

### 4.4 Naming e placement — red team

**Nomi convincenti:** il nome del file deve attirare un attaccante in fase di ricognizione. Evitare nomi ovvi (`honeypot.pdf`, `trap.docx`). Usare naming realistico che suggerisca credenziali, accesso remoto, configurazioni.

**Timestamp realistico:** dopo aver piazzato il file, modificare il timestamp per non sembrare appena creato:
```bash
# MacBook — timestamp: 6 mesi fa
touch -t 202510151430 ~/Desktop/VPN_Configurazione_Accesso_Remoto.pdf

# MacBook — credenziali AWS fake
mkdir -p ~/.aws
touch -t 202508201200 ~/.aws/credentials
```

**Credenziali AWS fake (TK-03) — formato:**
```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = <TOKEN_GENERATO_DA_CANARYTOKENS>
region = eu-west-1
```

Il token generato da canarytokens di tipo "AWS Keys" è funzionante come formato ma non dà accesso reale — qualsiasi tool che tenta di usarla genera il callback.

### 4.5 Alert Canarytoken → Slack

canarytokens.org supporta webhook Slack nativamente. Il webhook viene configurato al momento della generazione del token. Non richiede Wazuh — l'alert è diretto.

**Formato alert atteso in `#homesoc-alerts`:**
```
🪤 CANARYTOKEN TRIGGERED
Token: Backup_Credenziali_Servizi_2026.docx
Time: 2026-04-24T14:32:11Z
Source IP: 192.168.68.77
User-Agent: Microsoft Word/16.0
Memo: [HomeSOC] TK-01 Word NAS /shares/Documenti/
```

---

## 5. T-02 — OpenCanary — Honeypot di Rete

### 5.1 Creazione LXC ct-104

**Su SOC-01 (Proxmox host):**

```bash
# Scarica template Debian 12 se non presente
pveam update
pveam download local debian-12-standard_12.7-1_amd64.tar.zst

# Crea LXC ct-104
pct create 104 local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  --hostname backup-srv \
  --memory 512 \
  --swap 256 \
  --cores 1 \
  --net0 name=eth0,bridge=vmbr0,ip=192.168.68.206/24,gw=192.168.68.1 \
  --storage local-lvm \
  --rootfs local-lvm:4 \
  --unprivileged 1 \
  --start 1
```

> **Hostname `backup-srv`:** scelto deliberatamente — sembra un server di backup legittimo, non un honeypot. Un attaccante che enumera la rete lo considererà un target interessante.

### 5.2 Installazione OpenCanary

**Su ct-104:**

```bash
# Aggiornamento sistema
apt update && apt upgrade -y
apt install -y python3 python3-pip python3-venv libssl-dev libffi-dev git

# Ambiente virtuale
python3 -m venv /opt/opencanary-env
source /opt/opencanary-env/bin/activate
pip install opencanary

# Verifica installazione
opencanaryd --version
```

### 5.3 Configurazione — file opencanary.conf

La configurazione è critica per l'efficacia. Ogni banner deve sembrare un servizio reale.

```bash
# Genera configurazione di default
opencanaryd --copyconfig
cp ~/.opencanary.conf /etc/opencanary.conf
```

**Modifica `/etc/opencanary.conf`:**

```json
{
    "device.node_id": "backup-srv",
    "git.enabled": false,
    "ftp.enabled": true,
    "ftp.port": 21,
    "ftp.banner": "220 ProFTPD 1.3.5e Server (ProFTPD) [192.168.68.206]",
    "http.enabled": true,
    "http.port": 8080,
    "http.banner": "Apache/2.4.57 (Ubuntu)",
    "http.skin": "basicLogin",
    "mysql.enabled": true,
    "mysql.port": 3306,
    "mysql.banner": "8.0.36-0ubuntu0.22.04.1",
    "ssh.enabled": true,
    "ssh.port": 22,
    "ssh.version": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "telnet.enabled": true,
    "telnet.port": 23,
    "telnet.banner": "Ubuntu 20.04.6 LTS",
    "telnet.honeycreds": [
        {"username": "admin", "password": "admin"},
        {"username": "root", "password": "toor"},
        {"username": "ubuntu", "password": "ubuntu"}
    ],
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
                },
                "syslog-unix": {
                    "class": "logging.handlers.SysLogHandler",
                    "address": ["192.168.68.204", 514],
                    "formatter": "plain",
                    "socktype": "SOCK_DGRAM"
                }
            }
        }
    }
}
```

> **Log doppio:** file locale + syslog UDP verso vm-103 (Wazuh). Il file è backup in caso di problemi di rete; il syslog è il canale di alerting real-time.

```bash
# Crea directory log
mkdir -p /var/log/opencanary
```

### 5.4 Systemd service

```bash
cat > /etc/systemd/system/opencanary.service << 'EOF'
[Unit]
Description=OpenCanary Honeypot
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/opencanary-env/bin/opencanaryd --dev
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable opencanary
systemctl start opencanary
systemctl status opencanary
```

### 5.5 Verifica porte attive

```bash
# Da vm-103 o MacBook
nmap -p 21,22,23,3306,8080 192.168.68.206
```

Output atteso: tutte le porte `open` con i banner corretti.

---

## 6. T-03 — Endlessh — SSH Tarpit su SOC-01

### 6.1 Principio

Endlessh risponde alle connessioni SSH con un banner infinitamente lento — invia un carattere ogni N secondi, tenendo il client bloccato in attesa. Un attaccante che tenta SSH sulla porta 22 di SOC-01 rimane intrappolato per ore, loggando ogni connessione a Wazuh.

SSH reale su SOC-01 è già sulla porta 2222 — la porta 22 è libera.

### 6.2 Installazione

**Su SOC-01:**

```bash
apt install -y endlessh

# Configurazione
cat > /etc/endlessh/config << 'EOF'
Port 22
Delay 10000
MaxLineLength 32
MaxClients 4096
LogLevel 1
BindFamily 0
EOF

systemctl enable endlessh
systemctl start endlessh
systemctl status endlessh
```

> **`Delay 10000`:** 10 secondi per carattere. Un client SSH aspetta il banner completo prima di procedere — rimane bloccato indefinitamente. **`MaxClients 4096`:** accetta migliaia di connessioni simultanee senza impatto sulle risorse.

### 6.3 Verifica

```bash
# Da vm-103 — deve bloccarsi (Ctrl+C per uscire)
ssh -p 22 192.168.68.200
# Output atteso: connessione stabilita, nessun prompt, cursore bloccato

# Log Endlessh su SOC-01
journalctl -u endlessh -f
```

---

## 7. T-04 — Wazuh Integration — Decoder e Regole

### 7.1 Logcollector — ingest OpenCanary

**Su vm-103 — aggiungi a `/var/ossec/etc/ossec.conf` nella sezione `<ossec_config>`:**

```xml
<!-- OpenCanary honeypot log -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/opencanary/opencanary.log</location>
</localfile>
```

> **Nota:** OpenCanary su ct-104 invia log via syslog UDP a vm-103:514. Il file `/var/log/opencanary/opencanary.log` su vm-103 viene scritto dal syslog daemon locale. Verificare che rsyslog su vm-103 accetti UDP 514 e scriva i messaggi OpenCanary nel file corretto.

**Aggiungi a `/etc/rsyslog.conf` su vm-103:**

```
# Ricezione syslog UDP da ct-104 (OpenCanary)
module(load="imudp")
input(type="imudp" port="514")

# Scrivi log OpenCanary in file dedicato
if $fromhost-ip == '192.168.68.206' then /var/log/opencanary/opencanary.log
& stop
```

```bash
# Su vm-103
mkdir -p /var/log/opencanary
systemctl restart rsyslog
```

### 7.2 Decoder OpenCanary

**File:** `/var/ossec/etc/decoders/opencanary-decoder.xml` su vm-103

```xml
<!-- Decoder OpenCanary JSON -->
<decoder name="opencanary">
  <prematch>opencanary</prematch>
</decoder>

<decoder name="opencanary-fields">
  <parent>opencanary</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

> **OpenCanary loga in JSON** — il decoder JSON nativo di Wazuh estrae automaticamente i campi: `src_host`, `dst_port`, `logtype`, `utc_time`.

### 7.3 Decoder Endlessh

**Aggiunta a** `/var/ossec/etc/decoders/local_decoder.xml` su vm-103:

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

### 7.4 Regole Wazuh — deception layer

**File:** `/var/ossec/etc/rules/deception-rules.xml` su vm-103

```xml
<!-- ============================================================ -->
<!-- HomeSOC — Fase 3d — Deception Layer Rules                    -->
<!-- Range ID: 100080–100089                                       -->
<!-- ============================================================ -->

<!-- OpenCanary — qualsiasi trigger -->
<rule id="100080" level="12">
  <decoded_as>opencanary</decoded_as>
  <description>OpenCanary: honeypot interaction detected from $(src_host)</description>
  <options>alert_by_email</options>
  <group>honeypot,deception,lateral_movement</group>
  <mitre>
    <id>T1046</id>
    <id>T1135</id>
  </mitre>
</rule>

<!-- OpenCanary — SSH specifico (più grave — potenziale accesso credenziali) -->
<rule id="100081" level="14" overwrite="no">
  <if_sid>100080</if_sid>
  <field name="dst_port">22</field>
  <description>OpenCanary: SSH connection attempt on honeypot from $(src_host)</description>
  <group>honeypot,deception,ssh,lateral_movement</group>
  <mitre>
    <id>T1110</id>
    <id>T1021.004</id>
  </mitre>
</rule>

<!-- OpenCanary — HTTP (potenziale web exploitation) -->
<rule id="100082" level="12" overwrite="no">
  <if_sid>100080</if_sid>
  <field name="dst_port">8080</field>
  <description>OpenCanary: HTTP access on honeypot admin panel from $(src_host)</description>
  <group>honeypot,deception,http</group>
  <mitre>
    <id>T1190</id>
  </mitre>
</rule>

<!-- OpenCanary — altri servizi (FTP, Telnet, MySQL) -->
<rule id="100083" level="12" overwrite="no">
  <if_sid>100080</if_sid>
  <description>OpenCanary: service probe on honeypot port $(dst_port) from $(src_host)</description>
  <group>honeypot,deception,service_probe</group>
  <mitre>
    <id>T1046</id>
  </mitre>
</rule>

<!-- Endlessh — SSH tarpit connection -->
<rule id="100084" level="10">
  <decoded_as>endlessh</decoded_as>
  <description>Endlessh: SSH tarpit connection from $(srcip):$(srcport) on SOC-01:22</description>
  <group>honeypot,tarpit,ssh</group>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>

<!-- Endlessh — multiple connections (scan o brute force) -->
<rule id="100085" level="12" frequency="5" timeframe="60">
  <if_matched_sid>100084</if_matched_sid>
  <same_source_ip/>
  <description>Endlessh: multiple SSH tarpit connections from $(srcip) — possible scan/brute force</description>
  <group>honeypot,tarpit,ssh,brute_force</group>
  <mitre>
    <id>T1110.001</id>
  </mitre>
</rule>
```

### 7.5 Aggiornamento slack.py — routing alert deception

**Su vm-103 — aggiorna `/var/ossec/integrations/slack.py`:**

Aggiungere nella sezione di routing per rule ID:

```python
# ---- Deception Layer (Fase 3d) ----
elif rule_id in ("100080", "100082", "100083"):
    emoji = "🕳️"
    title = "HONEYPOT INTERACTION"
    color = "#FF4500"
    details = f"*Host:* `{data.get('data', {}).get('src_host', srcip)}`\n*Porta:* `{data.get('data', {}).get('dst_port', 'N/A')}`\n*Servizio:* OpenCanary"

elif rule_id == "100081":
    emoji = "🚨"
    title = "HONEYPOT SSH ATTEMPT — ALTO RISCHIO"
    color = "#FF0000"
    details = f"*Host sorgente:* `{data.get('data', {}).get('src_host', srcip)}`\n*Servizio:* SSH su honeypot\n*Azione:* Investigare immediatamente"

elif rule_id in ("100084", "100085"):
    emoji = "🕷️"
    title = "SSH TARPIT — CONNESSIONE INTRAPPOLATA"
    color = "#FF8C00"
    details = f"*Sorgente:* `{srcip}`\n*Target:* SOC-01:22 (Endlessh)\n*Servizio:* SSH tarpit attivo"
```

### 7.6 Reload Wazuh

```bash
# Su vm-103
systemctl reload wazuh-manager
systemctl is-active wazuh-manager
```

---

## 8. T-05 — Red Team Hardening

Questa sezione elenca le misure per rendere il deception layer resistente all'evasione. Un honeypot riconoscibile come tale da un attaccante esperto non solo non rileva — avvisa l'attaccante che è monitorato.

### 8.1 OpenCanary — fingerprint avversario

**Problema:** OpenCanary ha banner di default noti. Scanner specializzati (Shodan, strumenti red team) possono riconoscerlo tramite fingerprint del processo o del comportamento del banner.

**Misure già applicate nella config sezione 5.3:**
- Banner SSH personalizzato con versione Ubuntu LTS specifica
- Banner FTP ProFTPD realistico
- Banner MySQL versione Ubuntu realistica
- Hostname `backup-srv` convincente

**Misure aggiuntive:**

```bash
# Su ct-104 — Disabilita IPv6 (riduce superficie di fingerprint)
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p

# Aggiungi entry /etc/hosts per rendere il sistema più realistico
echo "192.168.68.1 gateway.local" >> /etc/hosts
echo "192.168.68.200 soc-server.local" >> /etc/hosts
```

### 8.2 OpenCanary — coerenza dell'identità

Il sistema deve sembrare coerente con la sua identità di "backup server":

```bash
# Su ct-104 — crea file che un backup server avrebbe
mkdir -p /var/backups/homesoc
echo "# Backup schedule — DO NOT MODIFY" > /var/backups/homesoc/schedule.txt
echo "daily 02:00 → NAS /shares/Backup" >> /var/backups/homesoc/schedule.txt

# Modifica MOTD per sembrare un server reale
cat > /etc/motd << 'EOF'

  Backup Server — uso interno
  Accesso riservato al personale autorizzato.

EOF
```

### 8.3 Canarytoken — evasione sandbox

Alcuni attori avanzati aprono i file in sandbox offline prima di farlo su macchine reali. Il token DNS (TK-04) è più robusto in questo scenario perché:
- Viene risolto anche se il file viene aperto in ambienti con blocco HTTP
- Molte sandbox consentono DNS outbound anche con HTTP bloccato
- Il callback avviene alla risoluzione del record, non all'apertura del payload HTTP

**Inserire il record DNS canary anche dentro altri file come riferimento:**

Nel file `README_Accesso_Rete.txt` (TK-05):
```
Gateway interno: soc-internal.homesoc.local
Dashboard SOC: http://soc-internal.homesoc.local:443
```

Quando l'attaccante tenta di risolvere `soc-internal.homesoc.local`, il DNS canary scatta.

### 8.4 Endlessh — non esporre su WAN

Endlessh deve rimanere esclusivamente su LAN. Se il progetto evolverà verso esposizione internet di servizi, aggiungere regola firewall:

```bash
# Su SOC-01 — blocca endlessh su interfaccia WAN (se applicabile)
# Attualmente non necessario — tutto dietro NAT Deco BE65
```

### 8.5 Alerting — nessun delay

Per la deception, l'alert deve essere immediato — qualsiasi interazione con honeypot è un evento di sicurezza reale. Verificare che le regole 100080-100085 abbiano `level ≥ 10` per passare il threshold Slack (`≥ 10` configurato in phase3b).

Le regole 100080-100084 sono a `level 12` — alert immediato garantito.

---

## 9. Verifica End-to-End

### 9.1 Test Canarytoken

```bash
# Da MacBook END-05 — apri il file PDF esca
open ~/Desktop/VPN_Configurazione_Accesso_Remoto.pdf
```

**Atteso:** entro 30 secondi, notifica Slack con source IP del MacBook.

### 9.2 Test OpenCanary — SSH

```bash
# Da vm-103 — tenta SSH sull'honeypot
ssh -p 22 root@192.168.68.206
# Risponde con banner SSH fake — non inserire credenziali reali
```

**Atteso:** log in `/var/log/opencanary/opencanary.log`, alert Wazuh rule 100081 level 14, notifica Slack.

### 9.3 Test OpenCanary — HTTP

```bash
# Da vm-103
curl -s http://192.168.68.206:8080/
```

**Atteso:** risposta HTML fake login panel, rule 100082 level 12, notifica Slack.

### 9.4 Test OpenCanary — port scan (simula ricognizione)

```bash
# Da vm-103 — simula ricognizione interna
nmap -p 21,22,23,3306,8080 192.168.68.206
```

**Atteso:** ogni porta connessa genera un log OpenCanary → Wazuh rule 100080 o specifica.

### 9.5 Test Endlessh

```bash
# Da vm-103 — tenta SSH su porta 22 SOC-01
timeout 10 ssh -p 22 192.168.68.200
# Deve bloccarsi — il timeout forza chiusura dopo 10s
```

**Atteso:** log in `journalctl -u endlessh` su SOC-01, regola 100084 su Wazuh.

### 9.6 Wazuh logtest

```bash
# Su vm-103 — verifica decoder OpenCanary
echo '{"utc_time": "2026-04-24 14:00:00.000000", "src_host": "192.168.68.77", "dst_port": 22, "logtype": 1001}' | /var/ossec/bin/wazuh-logtest
```

---

## 10. MITRE ATT&CK Mapping

| Tecnica | ID | Componente | Regola |
|---|---|---|---|
| Network Service Discovery | T1046 | OpenCanary port probe | 100080, 100083 |
| Remote Services: SSH | T1021.004 | OpenCanary SSH | 100081 |
| Brute Force | T1110 | OpenCanary SSH + Endlessh | 100081, 100084 |
| Brute Force: Password Spraying | T1110.001 | Endlessh multiple | 100085 |
| Network Share Discovery | T1135 | OpenCanary SMB / HTTP | 100080, 100082 |
| Exploit Public-Facing Application | T1190 | OpenCanary HTTP | 100082 |

---

## 11. Aggiornamenti Threat Model e Risk Register

### Risk register — impatto Fase 3d

| Rischio | Stato pre-3d | Stato post-3d | Note |
|---|---|---|---|
| R-09 — Accesso non autorizzato server SOC | Parziale Mitigato | **Mitigato ✅** | Endlessh su :22 + alert immediato |
| R-10 — Brute force SSH | Mitigato ✅ (CrowdSec) | Mitigato ✅ (doppio layer) | CrowdSec + Endlessh su :22 |
| Laterale movement generico | Non coperto | **Coperto** | OpenCanary su tutte le porte chiave |

### Nuovo controllo da aggiungere a `01-threat-model.md`

Sezione 2 (controlli): aggiungere voce "Deception Layer" con componenti Canarytoken, OpenCanary, Endlessh.

---

**Commit:** `git add docs/phase3d-deception.md && git commit -m "feat(phase3d): add deception layer scope — canarytoken, opencanary, endlessh"`

---

*File: `docs/phase3d-deception.md` · v1.0 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
