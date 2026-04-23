# Fase 3b — Hardening & Integration
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `docs/phase3b-hardening.md`  
**Versione:** 1.1 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 3b — Consolidamento pre-Phase 4  
**Prerequisiti:** `wazuh-deploy.md` v1.2 ✅ · `wazuh-slack.md` v1.0 ✅ · `crowdsec-deploy.md` v1.1 ✅

> **Scopo:** Prima di procedere con la Fase 4 (TheHive, Cortex, OpenCTI), questa fase intermedia porta l'infrastruttura esistente dalla condizione *"deployata e funzionante"* alla condizione *"operativa e difensivamente efficace"*. Ogni tool già installato viene integrato, chiusi i gap di visibilità identificati post-deploy, e aggiunta la capacità di risposta attiva. Al termine di questa fase il HomeSOC produce **protezione reale e misurabile**, non solo alert.

**Changelog:**
- v1.1 — Aprile 2026 — T-01/T-02/T-03/T-04 completati e verificati. Fix path health check (tutti i log in `/var/log/homesoc/`, rim. fim-macos non monitorabile da vm-103). T-02: decisione documentata — 100010 commentato in ossec.conf, solo 100011 (>20 query/min) notifica Slack. T-03: Uptime Kuma → Slack operativo. T-04: Active Response deployato su SOC-01 (agent ID 002, porta SSH 2222); nota limitazione macOS SSH (sshd-session non logga auth failures standard); rule 100001 riconosce sia 5710 (utente inesistente) sia 5720 (password errata); whitelist IP interni configurata; blocco firewall-drop verificato con test live.
- v1.0 — Aprile 2026 — Prima stesura post gap-analysis Fase 3

---

## Indice

1. [Gap Analysis — Stato attuale vs. obiettivo](#1-gap-analysis--stato-attuale-vs-obiettivo)
2. [Task Overview](#2-task-overview)
3. [T-01 — Health Check sorgenti log](#3-t-01--health-check-sorgenti-log)
4. [T-02 — Fix threshold UC-02 per Slack](#4-t-02--fix-threshold-uc-02-per-slack)
5. [T-03 — Uptime Kuma → Slack](#5-t-03--uptime-kuma--slack)
6. [T-04 — Wazuh Active Response (UC-01)](#6-t-04--wazuh-active-response-uc-01)
7. [T-05 — Wazuh Vulnerability Detector](#7-t-05--wazuh-vulnerability-detector)
8. [T-06 — Greenbone → Wazuh Pipeline](#8-t-06--greenbone--wazuh-pipeline)
9. [T-07 — HomeSOC Security Dashboard](#9-t-07--homesoc-security-dashboard)
10. [Checklist pre-Phase 4](#10-checklist-pre-phase-4)
11. [Aggiornamenti threat model e risk register](#11-aggiornamenti-threat-model-e-risk-register)

---

## 1. Gap Analysis — Stato attuale vs. obiettivo

### 1.1 Stato post-Fase 3

| Componente | Stato | Tipo |
|---|---|---|
| Wazuh SIEM (vm-103) | ✅ Operativo | Detection |
| Wazuh Agent END-05 (MacBook) | ✅ Operativo | Detection |
| UC-01 SSH brute force | ✅ Alert Slack | Detection only |
| UC-02 IoT beaconing (NextDNS) | ⚠️ Alert Wazuh, **no Slack** | Detection — soglia errata |
| UC-03 FIM macOS | ✅ Alert Slack | Detection only |
| UC-04 NAS port monitor | ✅ Alert Slack | Detection only |
| UC-06 Rogue device | ✅ Alert Slack | Detection only |
| CrowdSec (SOC-01) | ✅ Blocca brute force SSH host | Prevention attiva |
| Greenbone (ct-102) | ✅ Scan settimanale | Awareness — non integrato |
| Uptime Kuma (ct-101) | ✅ Monitor tutti i servizi | Availability — no Slack |
| Wazuh Active Response | ❌ Non configurato | Gap critico |
| Wazuh Vulnerability Detector | ❌ Non abilitato | Gap — funzionalità nativa |
| Greenbone → Wazuh | ❌ Non integrato | Gap — silos separati |
| Log source watchdog | ❌ Assente | Gap operativo silenzioso |

### 1.2 Problemi identificati

**Gap 1 — UC-02 silenzioso su Slack.** Rule 100010 è level 8; la threshold della `<integration>` Wazuh → Slack è `≥ 10`. Il beaconing IoT non genera mai notifica. Il rischio R-01 (IoT C2) rimane non notificato in tempo reale.

**Gap 2 — Nessuna risposta attiva a livello SIEM.** Wazuh rileva SSH brute force (UC-01) ma non blocca. L'unica prevenzione attiva è CrowdSec su SOC-01, che copre solo l'host Proxmox. vm-103 e il MacBook non hanno active response. Un attaccante che punta la dashboard Wazuh (porta 443) o END-05 non viene bloccato.

**Gap 3 — Log source senza watchdog.** I tre script cron (NextDNS polling, nmap ARP scan, NAS port monitor) non hanno meccanismo di verifica. Un reboot, un errore silenzioso, o un cambio di permessi fa smettere l'ingest senza che Wazuh mostri alcun segnale di allerta. Il SIEM continua ad apparire sano mentre ha perso sorgenti dati.

**Gap 4 — Greenbone e Wazuh non si parlano.** Un host che da pulito diventa vulnerabile (nuovo servizio, firmware non aggiornato) non genera nessun alert Wazuh. I report PDF di Greenbone vengono letti solo manualmente.

**Gap 5 — Nessuna dashboard operativa unificata.** La visibilità è frammentata su quattro interfacce separate: Wazuh Dashboard (443/vm-103), Greenbone (9392/ct-102), Uptime Kuma (3001/ct-101), HAOS (8123/vm-100). Non esiste una vista consolidata dello stato di sicurezza.

---

## 2. Task Overview

| ID | Titolo | Priorità | Effort | Gap chiuso | Dipendenze |
|---|---|---|---|---|---|
| T-01 | Health check sorgenti log | 🔴 Alta | 30 min | Gap 3 | Nessuna |
| T-02 | Fix threshold UC-02 Slack | 🔴 Alta | 5 min | Gap 1 | T-01 verificato |
| T-03 | Uptime Kuma → Slack | 🔴 Alta | 15 min | Gap 5 (parziale) | Nessuna |
| T-04 | Wazuh Active Response UC-01 | 🔴 Alta | 45 min | Gap 2 | T-01 verificato |
| T-05 | Wazuh Vulnerability Detector | 🟡 Media | 45 min | Gap 4 (parziale) | T-04 stabile |
| T-06 | Greenbone → Wazuh pipeline | 🟡 Media | 2 h | Gap 4 | T-05 stabile |
| T-07 | HomeSOC Security Dashboard | 🟢 Bassa | 1 h | Gap 5 | T-01…T-06 stabili |

**Ordine di esecuzione consigliato:** T-01 → T-02 → T-03 → T-04 → T-05 → T-06 → T-07

---

## 3. T-01 — Health Check sorgenti log

**Obiettivo:** Verificare che tutti e tre gli script cron di ingest stiano girando e scrivendo dati aggiornati. Questo è il pre-requisito per tutti gli altri task.

**Dove:** vm-103 (verifica log) + MacBook END-05 (verifica cron)

### 3.1 Verifica cron NextDNS (UC-02)

```bash
# Su vm-103
# Verifica crontab attivo (gira come root)
sudo crontab -l | grep nextdns
# Output atteso: */15 * * * * /opt/homesoc/scripts/nextdns-fetch.sh ...

# Verifica log recente — path reale in /var/log/homesoc/
sudo ls -lh /var/log/homesoc/nextdns.log
sudo stat /var/log/homesoc/nextdns.log | grep Modify
# La data di modifica deve essere recente (entro 15 minuti)

# Verifica contenuto ultimo evento — formato syslog
sudo tail -3 /var/log/homesoc/nextdns.log
# Formato atteso: Apr 23 17:48:40 homesoc nextdns: domain="..." device="..." blocked="..." reason="..."
```

### 3.2 Verifica cron nmap rogue device (UC-06)

```bash
# Su vm-103
sudo crontab -l | grep rogue
# Output atteso: 0 8-23 * * * /opt/homesoc/scripts/rogue-device-check.sh ...

# Verifica log recente — path reale in /var/log/homesoc/
sudo ls -lh /var/log/homesoc/rogue-device.log
sudo tail -3 /var/log/homesoc/rogue-device.log
```

### 3.3 Verifica NAS port monitor (UC-04)

```bash
# Su vm-103 — path reale in /var/log/homesoc/
sudo ls -lh /var/log/homesoc/nas-monitor.log
sudo tail -3 /var/log/homesoc/nas-monitor.log
# L'ultimo check deve essere recente (script gira ogni 30 min da cron)
```

### 3.4 Verifica FIM workaround macOS (UC-03)

```bash
# Su MacBook (END-05)
crontab -l | grep fim
ls -lh /var/log/fim-macos.log
tail -3 /var/log/fim-macos.log
```

### 3.5 Verifica Wazuh riceve dati da END-05

```bash
# Su vm-103
sudo tail -f /var/ossec/logs/archives/archives.log | grep "END-05\|alessandrogaburro"
# Ctrl+C dopo 30 secondi — deve mostrare eventi recenti
```

### 3.6 Script di health check automatizzato

Creare `/usr/local/bin/homesoc-healthcheck.sh` su vm-103 per eseguire i check periodicamente:

```bash
sudo tee /usr/local/bin/homesoc-healthcheck.sh > /dev/null << 'EOF'
#!/bin/bash
# HomeSOC Log Source Health Check
# Verifica che i log delle sorgenti critiche siano stati aggiornati
# di recente. Se un file non viene modificato entro la soglia, scrive
# un evento nel syslog che Wazuh legge e può alertare.

THRESHOLD_MIN=120  # Alert se il log non viene aggiornato da più di 2 ore
LOG_FILE="/var/log/homesoc-healthcheck.log"
TIMESTAMP=$(date '+%Y-%m-%dT%H:%M:%S')

check_log_freshness() {
  local name="$1"
  local path="$2"
  
  if [ ! -f "$path" ]; then
    echo "${TIMESTAMP} HOMESOC_HEALTH source=${name} status=MISSING path=${path}" >> "$LOG_FILE"
    return
  fi
  
  local age_min=$(( ( $(date +%s) - $(stat -c %Y "$path") ) / 60 ))
  
  if [ "$age_min" -gt "$THRESHOLD_MIN" ]; then
    echo "${TIMESTAMP} HOMESOC_HEALTH source=${name} status=STALE age_min=${age_min} threshold=${THRESHOLD_MIN}" >> "$LOG_FILE"
  else
    echo "${TIMESTAMP} HOMESOC_HEALTH source=${name} status=OK age_min=${age_min}" >> "$LOG_FILE"
  fi
}

# Path verificati in produzione (Aprile 2026) — tutti i log in /var/log/homesoc/
check_log_freshness "nextdns"      "/var/log/homesoc/nextdns.log"
check_log_freshness "rogue-device" "/var/log/homesoc/rogue-device.log"
check_log_freshness "nas-monitor"  "/var/log/homesoc/nas-monitor.log"
# Nota: fim-macos NON monitorato qui — il log vive su END-05 (MacBook), non su vm-103.
# La freschezza del FIM macOS è verificata indirettamente dall'agent Wazuh (END-05 active).
EOF

sudo chmod +x /usr/local/bin/homesoc-healthcheck.sh
```

Aggiungere al crontab di root su vm-103 (ogni 30 minuti):

```bash
(sudo crontab -l 2>/dev/null; echo "*/30 * * * * /usr/local/bin/homesoc-healthcheck.sh") | sudo crontab -
```

Aggiungere il file al logcollector Wazuh (in `ossec.conf` su vm-103, sezione `<localfile>`):

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/homesoc-healthcheck.log</location>
</localfile>
```

Aggiungere la rule in `/var/ossec/etc/rules/local_rules.xml`:

```xml
<!-- T-01: Log source health check -->
<rule id="100060" level="12">
  <decoded_as>json</decoded_as>
  <field name="status">STALE|MISSING</field>
  <description>HomeSOC: sorgente log inattiva o mancante — $(source) da $(age_min) minuti</description>
  <group>homesoc,health,</group>
</rule>
```

> ✅ **Checkpoint T-01:** Script `/usr/local/bin/homesoc-healthcheck.sh` gira via cron ogni 30 minuti. Eseguire manualmente `sudo /usr/local/bin/homesoc-healthcheck.sh` e verificare che `/var/log/homesoc-healthcheck.log` mostri `status=OK` per nextdns, rogue-device e nas-monitor. `fim-macos` non è monitorato da questo script (log remoto su END-05).

---

## 4. T-02 — Fix threshold UC-02 per Slack

**Obiettivo:** La rule UC-02 (100010, beaconing IoT) è level 8. La `<integration>` Wazuh → Slack usa `<level>10</level>` come threshold. Garantire che il beaconing IoT ad alta frequenza (rule 100011, level 10) generi notifica Slack senza spam per query singole e isolate.

**Decisione di design (Aprile 2026):** la rule 100010 (singola query verso dominio cinese, level 8) **non** viene aggiunta alla `<integration>` Slack. Motivo: i robot IoT (Dreame/Narwal) fanno query periodiche verso CDN Alibaba/Baidu che sono normali per il firmware — aggiungerle a Slack genera spam. La notifica aggregata 100011 (>20 query/min dallo stesso device, level 10) è il segnale realmente significativo di beaconing attivo.

**Configurazione ossec.conf (già applicata):**

```xml
<!-- Integrazione Slack principale — threshold level 10 copre 100011 e tutti gli altri UC -->
<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/...</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>

<!--
  UC-02 — Notifica Slack per singola query IoT verso dominio cinese (rule 100010, level 8).
  DISABILITATO: genera spam per query isolate e innocue (es. CDN Alibaba da firmware Dreame/Narwal).
  La notifica aggregata è gestita dalla rule 100011 (>20 query/min, level 10) coperta dal
  blocco <integration> con <level>10</level> sopra. La 100010 resta visibile in Dashboard.
  Riabilitare solo se si vuole visibilità immediata su ogni singola query sospetta.
-->
```

**Dove:** vm-103 (`/var/ossec/etc/ossec.conf`)

> ✅ **Checkpoint T-02:** Iniettare una riga di test in `/var/log/homesoc/nextdns.log` con `blocked="ok"` e dominio cinese. Verificare che rule 100010 scatti in `alerts.log`. Verificare che **non** arrivi notifica Slack (la 100010 è level 8, sotto threshold). Per testare la 100011 iniettare >20 righe identiche in 60 secondi dallo stesso device. Aggiungere un secondo blocco dedicato a UC-02:

```xml
<!-- Integrazione Slack — rule_id specifici sotto threshold level -->
<integration>
  <name>slack</name>
  <hook_url>SLACK_WEBHOOK_URL_PLACEHOLDER</hook_url>
  <rule_id>100010</rule_id>
  <alert_format>json</alert_format>
</integration>
```

> ℹ️ Il blocco `<rule_id>` bypassa il filtro `<level>` per quella specifica rule. Il level 8 rimane corretto semanticamente — è il canale di notifica che viene esteso, non la severity dell'evento.

### 4.2 Riavvio e test

```bash
# Su vm-103
sudo systemctl restart wazuh-manager
sleep 10
sudo systemctl is-active wazuh-manager  # Deve essere: active

# Test sintetico — iniettare un log NextDNS di test
echo "$(date '+%Y-%m-%dT%H:%M:%S') query domain=malware-c2-test.io device=IOT-03 status=blocked" \
  | sudo tee -a /var/log/nextdns-queries.log

sleep 15
sudo grep "100010" /var/ossec/logs/alerts/alerts.log | tail -3
sudo tail -10 /var/ossec/logs/integrations.log
```

> ✅ **Checkpoint T-02:** Un evento NextDNS genera un alert rule 100010 E una notifica Slack nel canale `#homesoc-alerts`.

---

## 5. T-03 — Uptime Kuma → Slack

**Obiettivo:** Configurare l'integrazione nativa Slack di Uptime Kuma per ricevere notifiche di down/up dei servizi critici direttamente su Slack, senza passare da Wazuh.

**Dove:** Uptime Kuma Web UI — `http://192.168.68.202:3001`

### 5.1 Creazione notifica Slack in Uptime Kuma

1. **Web UI Uptime Kuma:** `Settings` → `Notifications` → **Add Notification**

| Campo | Valore |
|---|---|
| Notification Type | `Slack` |
| Friendly Name | `HomeSOC Slack #alerts` |
| Webhook URL | `<SLACK_WEBHOOK_URL>` |
| Username | `Uptime Kuma` |
| Icon Emoji | `:heartpulse:` |
| Channel | `#homesoc-alerts` |
| Notify on Recovery | ✅ Abilitato |

2. Click **Test** → verificare che arrivi un messaggio di test nel canale Slack.

3. Click **Save**.

### 5.2 Associare la notifica ai monitor critici

Per ogni monitor critico, aggiungere la notifica Slack:

**Web UI Uptime Kuma:** Selezionare il monitor → **Edit** → sezione `Notifications` → aggiungere `HomeSOC Slack #alerts`

Monitor prioritari da aggiornare:

| Monitor | IP/URL | Motivo |
|---|---|---|
| SOC-01 Host | `192.168.68.200` | Infrastruttura base |
| Wazuh Dashboard | `https://192.168.68.204` | SIEM disponibile |
| Greenbone Web UI | `https://192.168.68.203:9392` | Scanner disponibile |
| Home Assistant | `http://192.168.68.201:8123` | IoT monitoring |
| NAS WD | `192.168.68.90` | Asset critico |
| Gateway Deco | `192.168.68.1` | Infrastruttura rete |

> ✅ **Checkpoint T-03:** Spegnere temporaneamente Uptime Kuma stesso e verificare che... no — simulare portando un monitor in manutenzione e riportandolo online. Verificare la notifica Slack.

---

## 6. T-04 — Wazuh Active Response (UC-01)

**Obiettivo:** Configurare Wazuh Active Response per bloccare automaticamente gli IP che scatenano la rule 100001/100002 (SSH brute force, UC-01). Trasforma UC-01 da "detection + alert" a "detection + response + alert". L'IP viene bloccato via `firewall-drop` sull'agent target e notificato via Slack.

**Dove:** vm-103 (ossec.conf manager) + SOC-01 (agent ID 002, target principale)

> ⚠️ **Attenzione:** Prima di abilitare Active Response, configurare sempre la whitelist degli IP interni. Un falso positivo potrebbe bloccare SOC-01 o il proprio MacBook.

### 6.1 Prerequisiti — Wazuh Agent su SOC-01

L'Active Response richiede un Wazuh Agent sull'host target. Il MacBook (END-05) ha limitazioni SSH (sshd-session su macOS non logga auth failures in modo compatibile con le rule built-in Wazuh). SOC-01 è il target primario per il test e la produzione.

```bash
# Su SOC-01 — installazione agent Wazuh v4.14.4
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
  chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | tee /etc/apt/sources.list.d/wazuh.list

apt-get update && apt-get install -y wazuh-agent=4.14.4-1

# Enrollment
WAZUH_MANAGER="192.168.68.204" WAZUH_AGENT_NAME="SOC-01" \
  /var/ossec/bin/agent-auth -m 192.168.68.204

# Fix: sostituire il placeholder MANAGER_IP nel config
sed -i 's/MANAGER_IP/192.168.68.204/' /var/ossec/etc/ossec.conf

# Aggiungere /var/log/auth.log al logcollector (non presente nel template default)
sed -i 's|</ossec_config>|  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n\n</ossec_config>|' /var/ossec/etc/ossec.conf

# Abilitare PasswordAuthentication per test brute force (rimuovere dopo il test)
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
systemctl restart ssh

systemctl enable wazuh-agent && systemctl start wazuh-agent
systemctl is-active wazuh-agent  # deve essere: active
```

> ℹ️ SSH su SOC-01 è in ascolto sulla **porta 2222** (non 22 standard). Verificare con `ss -tlnp | grep :22`.

> ⚠️ **Nota macOS (END-05):** `firewall-drop` esiste su macOS (`/Library/Ossec/active-response/bin/firewall-drop`) ma SSH su macOS con sshd-session non genera log di autenticazione fallita compatibili con le rule Wazuh built-in (5710/5720). Il blocco su END-05 è configurato ma non testabile con il metodo standard. SOC-01 è il target verificato in produzione.

### 6.2 Configurazione ossec.conf — Manager

```bash
# Su vm-103
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-$(date +%Y%m%d)-t04
sudo nano /var/ossec/etc/ossec.conf
```

Aggiungere le whitelist nel blocco `<global>` esistente (cercare `<white_list>127.0.0.1</white_list>`):

```xml
<white_list>192.168.68.200</white_list>  <!-- SOC-01 -->
<white_list>192.168.68.108</white_list>  <!-- MacBook END-05 -->
<white_list>192.168.68.1</white_list>    <!-- Gateway Deco -->
```

Sostituire il blocco `<active-response>` placeholder con:

```xml
<!-- T-04: Active Response — SSH brute force UC-01 -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100001,100002</rules_id>
  <timeout>3600</timeout>
</active-response>
```

> ℹ️ `<location>local</location>` esegue il blocco sull'agent che ha generato l'evento. `<timeout>3600</timeout>` blocca per 1 ora, poi `firewall-drop` rimuove automaticamente la regola iptables.

### 6.3 Riavvio e verifica

```bash
# Su vm-103
sudo systemctl restart wazuh-manager
sleep 15
sudo systemctl is-active wazuh-manager  # Deve essere: active

# Verifica agent SOC-01 visibile
sudo /var/ossec/bin/agent_control -l
# Output atteso: ID 002, soc-01, Active
```

### 6.4 Test Active Response

Il test viene eseguito da vm-103 (IP 192.168.68.204, **non in whitelist**) verso SOC-01 (porta 2222):

```bash
# Su vm-103 — prerequisito
sudo apt-get install -y sshpass

# Generare 8+ tentativi SSH falliti verso SOC-01
for i in {1..8}; do
  sshpass -p "passwordsbagliata" ssh -o ConnectTimeout=3 \
    -o StrictHostKeyChecking=no \
    -p 2222 \
    invaliduser99@192.168.68.200 2>/dev/null
  sleep 1
done

sleep 10

# Verifica alert UC-01
sudo grep "100001\|100002" /var/ossec/logs/alerts/alerts.log | tail -5
```

Su SOC-01, verificare il blocco:

```bash
# Su SOC-01
iptables -L INPUT -n | grep 192.168.68.204
# Output atteso: DROP all -- 192.168.68.204 0.0.0.0/0

# Sblocco manuale dopo il test (opzionale — scade automaticamente dopo 1h)
iptables -D INPUT -s 192.168.68.204 -j DROP
```

> ⚠️ **Cleanup post-test:** rimuovere `PasswordAuthentication yes` da `/etc/ssh/sshd_config` su SOC-01 dopo il test e riavviare SSH.

```bash
# Su SOC-01 — cleanup
sed -i '/^PasswordAuthentication yes/d' /etc/ssh/sshd_config
systemctl restart ssh
```

> ✅ **Checkpoint T-04:** Rule 100001 scatta in `alerts.log`. Iptables su SOC-01 mostra `DROP` per l'IP attaccante. Notifica Slack arriva nel canale `#homesoc-alerts`.

### 6.5 Slack notification per Active Response

Aggiungere in `/var/ossec/etc/rules/local_rules.xml` una rule che scatta quando l'active response viene eseguito:

```xml
<!-- T-04: Active Response executed -->
<rule id="100061" level="12">
  <if_sid>601</if_sid>
  <match>firewall-drop</match>
  <description>HomeSOC: Active Response — IP bloccato da firewall-drop (UC-01)</description>
  <group>homesoc,active_response,uc01,</group>
</rule>
```

Aggiungere `100061` alla `<integration>` Slack in ossec.conf (come fatto in T-02 per 100010).

---

## 7. T-05 — Wazuh Vulnerability Detector

**Obiettivo:** Abilitare il modulo `vulnerability-detector` nativo di Wazuh sul manager. Il modulo interroga periodicamente gli agent per l'inventario software installato e lo correla con i feed NVD/OSV, producendo alert per CVE con CVSS ≥ 7.0. Questo è **complementare** a Greenbone: Greenbone vede la rete, il vulnerability detector vede i pacchetti installati sull'agent (END-05).

**Dove:** vm-103 (ossec.conf manager)

### 7.1 Abilitazione vulnerability-detector

```bash
# Su vm-103
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-$(date +%Y%m%d)-t05
sudo nano /var/ossec/etc/ossec.conf
```

Aggiungere il blocco (o decommentare se già presente):

```xml
<!-- T-05: Vulnerability Detector -->
<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>12h</interval>
  <ignore_time>6h</ignore_time>
  <run_on_start>yes</run_on_start>

  <!-- Feed NVD — National Vulnerability Database -->
  <provider name="nvd">
    <enabled>yes</enabled>
    <schedule>5 1 * * *</schedule>   <!-- Aggiornamento NVD ogni notte all'01:05 -->
    <update_interval>1h</update_interval>
  </provider>

  <!-- Feed Canonical — Ubuntu (per vm-103 stessa) -->
  <provider name="canonical">
    <enabled>yes</enabled>
    <os>jammy</os>                   <!-- Ubuntu 22.04 LTS -->
    <schedule>10 1 * * *</schedule>
    <update_interval>1h</update_interval>
  </provider>

  <!-- Feed RedHat/macOS tramite NVD -->
  <provider name="redhat">
    <enabled>no</enabled>
  </provider>
</vulnerability-detector>
```

### 7.2 Verifica supporto agent macOS

Il vulnerability detector su macOS richiede Wazuh Agent ≥ 4.2 e rileva i pacchetti tramite il syscollector. Verificare che il modulo sia attivo su END-05:

```bash
# Su MacBook (END-05)
grep -A5 "syscollector" /Library/Ossec/etc/ossec.conf
# Deve mostrare <disabled>no</disabled>

# Su vm-103 — verifica che il manager riceva l'inventario
sudo sqlite3 /var/ossec/queue/db/000.db \
  "SELECT name, version FROM sys_packages LIMIT 10;"
# Output: lista pacchetti rilevati sull'agent
```

### 7.3 Riavvio e prima scansione

```bash
# Su vm-103
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/ossec.log | grep -i "vulnerab"
# La prima scansione parte entro 5 minuti (run_on_start: yes)
# Il feed NVD può richiedere 10-20 minuti per il download iniziale
```

### 7.4 Verifica alert in Dashboard

```bash
# Su vm-103
sudo grep "vulnerability" /var/ossec/logs/alerts/alerts.log | tail -10
```

In Wazuh Dashboard: `Threat Intelligence` → `Vulnerabilities` — dopo la prima scansione compare il report per END-05.

### 7.5 Slack alert per CVE critiche

Aggiungere regola in `local_rules.xml` per forwardare le vulnerabilità critiche su Slack:

```xml
<!-- T-05: Vulnerability — CVSS critica o alta -->
<rule id="100062" level="12">
  <if_sid>23501</if_sid>
  <field name="vulnerability.severity">Critical|High</field>
  <description>HomeSOC: CVE $(vulnerability.cve) su $(agent.name) — severity $(vulnerability.severity) CVSS $(vulnerability.cvss.cvss3.base_score)</description>
  <group>homesoc,vulnerability,</group>
</rule>
```

Aggiungere `100062` al blocco `<integration>` Slack in ossec.conf.

> ✅ **Checkpoint T-05:** Wazuh Dashboard → `Threat Intelligence` → `Vulnerabilities` mostra i CVE rilevati su END-05. Una vulnerabilità High/Critical genera alert in Wazuh e notifica Slack.

---

## 8. T-06 — Greenbone → Wazuh Pipeline

**Obiettivo:** Creare una pipeline automatizzata che estrae i finding CVSS ≥ 7.0 dai report XML di Greenbone e li injetta in Wazuh come eventi strutturati. Al termine di ogni scan settimanale, Wazuh Dashboard mostra i finding Greenbone e genera alert Slack per le vulnerabilità critiche.

**Dove:** ct-102 (script Python + Wazuh Agent) + vm-103 (decoder + rules)

### 8.1 Installazione Wazuh Agent su ct-102

ct-102 (Greenbone) non ha ancora un Wazuh Agent. Installarlo per permettere il logcollector su log locali.

```bash
# Su ct-102
# Aggiungere repo Wazuh (stesso processo di END-05, versione Linux)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | tee /etc/apt/sources.list.d/wazuh.list

apt-get update && apt-get install wazuh-agent -y

# Configurazione agent
WAZUH_MANAGER='192.168.68.204' WAZUH_AGENT_NAME='ct-102-greenbone' \
  apt-get install wazuh-agent -y

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Su vm-103 — accettare la chiave dell'agent
sudo /var/ossec/bin/manage_agents
# Opzione A: aggiungere agent → nome ct-102-greenbone → IP 192.168.68.203
# Poi su ct-102: importare la chiave
```

### 8.2 Script Python — greenbone-to-wazuh.py

```bash
# Su ct-102
pip3 install python-gvm --break-system-packages

tee /opt/greenbone-to-wazuh.py > /dev/null << 'PYEOF'
#!/usr/bin/env python3
"""
greenbone-to-wazuh.py
HomeSOC — Greenbone → Wazuh Pipeline
Legge l'ultimo report completato dalla GVM API,
estrae finding con CVSS >= 7.0 e li scrive in
/var/log/greenbone-findings.log per ingest Wazuh.

Autore: Alessandro · HomeSOC Project
"""

import json
import logging
import sys
from datetime import datetime, timezone
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree

LOG_FILE    = "/var/log/greenbone-findings.log"
CVSS_THRESH = 7.0
GVM_SOCKET  = "/run/gvmd/gvmd.sock"

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def get_latest_report(gmp):
    """Recupera l'ID del report più recente nello stato 'Done'."""
    reports = gmp.get_reports(filter_string="sort-reverse=date rows=5")
    for report in reports.findall(".//report"):
        status = report.find(".//scan_run_status")
        if status is not None and status.text == "Done":
            return report.get("id")
    return None

def extract_findings(gmp, report_id):
    """Estrae i finding con CVSS >= CVSS_THRESH dal report."""
    report = gmp.get_report(report_id=report_id, filter_string="min_qod=70")
    findings = []
    for result in report.findall(".//result"):
        severity_el = result.find("severity")
        if severity_el is None:
            continue
        try:
            cvss = float(severity_el.text)
        except (TypeError, ValueError):
            continue
        if cvss < CVSS_THRESH:
            continue
        host_el   = result.find("host")
        name_el   = result.find("name")
        nvt_el    = result.find("nvt")
        cve_el    = nvt_el.find("cve") if nvt_el is not None else None
        findings.append({
            "timestamp":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source":       "greenbone",
            "report_id":    report_id,
            "host":         host_el.text if host_el is not None else "unknown",
            "vuln_name":    name_el.text if name_el is not None else "unknown",
            "cvss":         cvss,
            "severity":     "Critical" if cvss >= 9.0 else "High",
            "cve":          cve_el.text if cve_el is not None else "N/A",
        })
    return findings

def main():
    try:
        connection = UnixSocketConnection(path=GVM_SOCKET)
        transform  = EtreeCheckCommandTransform()
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate("admin", "GREENBONE_ADMIN_PASSWORD")
            report_id = get_latest_report(gmp)
            if not report_id:
                logging.warning("Nessun report completato trovato.")
                sys.exit(0)
            logging.info(f"Report ID: {report_id}")
            findings = extract_findings(gmp, report_id)
            logging.info(f"Finding CVSS >= {CVSS_THRESH}: {len(findings)}")
            with open(LOG_FILE, "a") as f:
                for finding in findings:
                    f.write(json.dumps(finding) + "\n")
    except Exception as e:
        logging.error(f"Errore pipeline Greenbone: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
PYEOF

chmod +x /opt/greenbone-to-wazuh.py
```

> ⚠️ Sostituire `GREENBONE_ADMIN_PASSWORD` con la password admin di Greenbone configurata in `greenbone-deploy.md`.

### 8.3 Schedulazione cron — lunedì mattina post-scan

Il cron Greenbone esegue lo scan domenica alle 02:00. Lo script viene eseguito il lunedì alle 08:00 per lasciare tempo allo scan di completarsi.

```bash
# Su ct-102
(crontab -l 2>/dev/null; echo "0 8 * * 1 /usr/bin/python3 /opt/greenbone-to-wazuh.py >> /var/log/greenbone-to-wazuh-cron.log 2>&1") | crontab -
```

### 8.4 Logcollector su ct-102

Aggiungere in `/var/ossec/etc/ossec.conf` sull'agent ct-102:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/greenbone-findings.log</location>
</localfile>
```

```bash
# Su ct-102
systemctl restart wazuh-agent
```

### 8.5 Decoder e rule su vm-103

Aggiungere decoder in `/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<!-- T-06: Greenbone findings decoder -->
<decoder name="greenbone-findings">
  <prematch>{"source":"greenbone"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

Aggiungere rule in `local_rules.xml`:

```xml
<!-- T-06: Greenbone finding High/Critical -->
<rule id="100050" level="12">
  <decoded_as>json</decoded_as>
  <field name="source">greenbone</field>
  <field name="severity">High|Critical</field>
  <description>HomeSOC: Greenbone finding $(severity) — CVE $(cve) su host $(host) (CVSS $(cvss))</description>
  <group>homesoc,vulnerability,greenbone,uc05,</group>
</rule>

<rule id="100051" level="15">
  <if_sid>100050</if_sid>
  <field name="cvss">^(9|10)\.</field>
  <description>HomeSOC: Greenbone finding CRITICO — $(vuln_name) su $(host) CVSS $(cvss)</description>
  <group>homesoc,vulnerability,greenbone,uc05,critical,</group>
</rule>
```

Aggiungere `100050,100051` al blocco `<integration>` Slack in ossec.conf.

```bash
# Su vm-103
sudo systemctl restart wazuh-manager
```

> ✅ **Checkpoint T-06:** Eseguire lo script manualmente (`python3 /opt/greenbone-to-wazuh.py`) con dati di test. Verificare che il finding appaia in `/var/log/greenbone-findings.log`, che Wazuh generi l'alert rule 100050, e che la notifica Slack arrivi.

---

## 9. T-07 — HomeSOC Security Dashboard

**Obiettivo:** Creare una dashboard operativa unificata in **Wazuh Dashboard** (OpenSearch Dashboards, già disponibile su vm-103 porta 443) che mostri in una sola schermata lo stato di sicurezza del HomeSOC. Non richiede nuovo software.

**Dove:** Wazuh Dashboard — `https://192.168.68.204` (browser)

### 9.1 Visualizzazioni da creare

Creare ciascuna visualizzazione da `Analytics` → `Visualize Library` → **Create visualization**.

#### VIZ-01 — UC Events Timeline (7 giorni)

| Campo | Valore |
|---|---|
| Tipo | Line / Bar chart |
| Index pattern | `wazuh-alerts-*` |
| Asse X | `@timestamp` (date histogram, interval: 1 day) |
| Asse Y | `Count` |
| Split series | `rule.id` — valori: 100001, 100010, 100020, 100023, 100030, 100040, 100050, 100060, 100061, 100062 |
| Time range | Last 7 days |
| Nome | `[HomeSOC] UC Events — 7 Days` |

#### VIZ-02 — Alert Level Distribution

| Campo | Valore |
|---|---|
| Tipo | Donut chart |
| Index pattern | `wazuh-alerts-*` |
| Slice | `rule.level` (terms aggregation, top 10) |
| Filter | `rule.groups: homesoc` |
| Nome | `[HomeSOC] Alert Level Distribution` |

#### VIZ-03 — Top Source IPs (attacco/brute force)

| Campo | Valore |
|---|---|
| Tipo | Horizontal bar |
| Index pattern | `wazuh-alerts-*` |
| Asse Y | `Count` |
| Asse X | `data.srcip` (terms, top 10) |
| Filter | `rule.id: 100001` |
| Nome | `[HomeSOC] Top Attacker IPs — UC-01` |

#### VIZ-04 — FIM Events by File

| Campo | Valore |
|---|---|
| Tipo | Data table |
| Index pattern | `wazuh-alerts-*` |
| Columns | `@timestamp`, `agent.name`, `syscheck.path`, `syscheck.event`, `rule.description` |
| Filter | `rule.groups: uc03` |
| Sort | `@timestamp` DESC |
| Nome | `[HomeSOC] FIM Events — UC-03` |

#### VIZ-05 — Vulnerability Summary (Greenbone + VulnDetector)

| Campo | Valore |
|---|---|
| Tipo | Data table |
| Index pattern | `wazuh-alerts-*` |
| Columns | `@timestamp`, `data.host`, `data.cve`, `data.cvss`, `data.severity`, `rule.description` |
| Filter | `rule.id: (100050 OR 100051 OR 100062)` |
| Sort | `data.cvss` DESC |
| Nome | `[HomeSOC] Vulnerability Findings` |

#### VIZ-06 — Active Response Log

| Campo | Valore |
|---|---|
| Tipo | Data table |
| Index pattern | `wazuh-alerts-*` |
| Columns | `@timestamp`, `data.srcip`, `agent.name`, `rule.description` |
| Filter | `rule.id: 100061` |
| Sort | `@timestamp` DESC |
| Nome | `[HomeSOC] Active Response — Blocked IPs` |

#### VIZ-07 — Log Source Health

| Campo | Valore |
|---|---|
| Tipo | Data table |
| Index pattern | `wazuh-alerts-*` |
| Columns | `@timestamp`, `data.source`, `data.status`, `data.age_min` |
| Filter | `rule.id: 100060` |
| Sort | `@timestamp` DESC |
| Nome | `[HomeSOC] Log Source Health` |

### 9.2 Assemblaggio dashboard

1. `Analytics` → `Dashboards` → **Create dashboard**
2. **Add from library** → aggiungere le 7 visualizzazioni create sopra
3. Layout suggerito:

```
┌─────────────────────────────────────────────────────────┐
│ [HomeSOC] UC Events — 7 Days          (full width)      │
├───────────────────────┬─────────────────────────────────┤
│ Alert Level Donut     │ Top Attacker IPs                │
├───────────────────────┴─────────────────────────────────┤
│ FIM Events — UC-03              (half width)            │
│ Vulnerability Findings          (half width)            │
├─────────────────────────────────────────────────────────┤
│ Active Response Log             (half width)            │
│ Log Source Health               (half width)            │
└─────────────────────────────────────────────────────────┘
```

4. **Save** → Title: `HomeSOC Security Operations`
5. Click su ⋮ → **Add to menu** (opzionale) per rendere la dashboard il default all'apertura.

### 9.3 Bookmark e accesso rapido

```bash
# Aggiungere nel file /etc/hosts del MacBook per accesso mnemonico
echo "192.168.68.204 soc.local" | sudo tee -a /etc/hosts

# La dashboard sarà accessibile a:
# https://soc.local (Wazuh Dashboard)
```

> ✅ **Checkpoint T-07:** Wazuh Dashboard → `HomeSOC Security Operations` — tutte le 7 visualizzazioni mostrano dati. Almeno VIZ-01 mostra eventi degli UC attivi nell'ultima settimana.

---

## 10. Checklist pre-Phase 4

Completare questa checklist prima di procedere con il deployment di TheHive, Cortex e OpenCTI.

### Componenti infrastrutturali

- [x] T-01: Health check eseguito — nextdns, rogue-device, nas-monitor `status=OK`
- [x] T-01: Script `homesoc-healthcheck.sh` attivo via cron su vm-103 (ogni 30 min)
- [x] T-02: UC-02 Slack configurato — 100011 (>20 query/min) notifica Slack; 100010 commentato (decisione documentata)
- [x] T-03: Uptime Kuma invia notifica Slack per down/up servizi — testato
- [x] T-04: Wazuh Agent installato su SOC-01 (ID 002, Active)
- [x] T-04: Wazuh Active Response blocca IP brute force su SOC-01 — `iptables DROP` verificato
- [x] T-04: Rule 100061 aggiunta in `local_rules.xml`
- [ ] T-05: Vulnerability Detector attivo — primo report disponibile in Dashboard
- [ ] T-05: Rule 100062 genera alert per CVE High/Critical
- [ ] T-06: Wazuh Agent installato su ct-102 e visibile in Dashboard
- [ ] T-06: Pipeline `greenbone-to-wazuh.py` testata manualmente con successo
- [ ] T-06: Rule 100050/100051 generano alert per finding Greenbone
- [ ] T-07: Dashboard `HomeSOC Security Operations` accessibile con dati reali

### Stato Use Case post-Fase 3b

| Use Case | Detection | Notification | Active Response |
|---|---|---|---|
| UC-01 SSH brute force | ✅ | ✅ Slack | ✅ firewall-drop su SOC-01 (T-04) |
| UC-02 IoT beaconing | ✅ | ✅ Slack — 100011 >20q/min (T-02) | ❌ (non applicabile) |
| UC-03 FIM macOS | ✅ | ✅ Slack | ❌ (non applicabile) |
| UC-04 NAS port monitor | ✅ | ✅ Slack | ❌ futuro |
| UC-06 Rogue device | ✅ | ✅ Slack | ❌ futuro |
| Greenbone findings | ⏳ (T-06) | ⏳ Slack (T-06) | ❌ (manuale) |
| Vuln. Detector CVE | ⏳ (T-05) | ⏳ Slack (T-05) | ❌ (manuale) |
| Log source stale | ✅ (T-01) | ✅ Slack (T-01) | ❌ (non applicabile) |

### Protezione attiva post-Fase 3b

| Vettore | Protezione | Strumento |
|---|---|---|
| SSH brute force su SOC-01 | ✅ Blocco IP automatico | CrowdSec |
| SSH brute force su END-05 | ✅ Blocco IP automatico | Wazuh AR (T-04) |
| Vulnerabilità note (rete) | ✅ Alert settimanale | Greenbone → Wazuh |
| Vulnerabilità note (agent) | ✅ Alert ogni 12h | Wazuh Vuln. Detector |
| Device non autorizzati | ✅ Alert immediato | UC-06 + Slack |
| File critici modificati | ✅ Alert immediato | UC-03 + Slack |
| Servizi down | ✅ Alert immediato | Uptime Kuma + Slack |

---

## 11. Aggiornamenti threat model e risk register

Al termine di Fase 3b, aggiornare `docs/01-threat-model.md` v1.4:

| Rischio | Stato precedente | Stato nuovo | Motivazione |
|---|---|---|---|
| R-01 IoT C2 | Parziale (no Slack UC-02) | ✅ Mitigato | T-02: UC-02 ora su Slack |
| R-02 NAS accesso non auth | Parziale | Parziale → | Monitoring attivo, AR non applicabile a NAS |
| R-08 Modifiche file critici | Parziale | ✅ Mitigato | FIM + AR pipeline completa |
| R-10 SSH brute force | Parziale (solo detect) | ✅ Mitigato | T-04: active response attivo |

Commit al termine:

```bash
git add docs/phase3b-hardening.md
git add docs/01-threat-model.md
git commit -m "docs(phase3b): v1.0 — hardening plan, gap analysis, 7 task pre-Phase4"
git tag -a phase3b-plan -m "HomeSOC Phase 3b — Hardening Plan — Aprile 2026"
```

---

*File: `docs/phase3b-hardening.md` · v1.1 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
