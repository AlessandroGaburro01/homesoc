# Fase 3c — Consolidamento Finale
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `docs/phase3c-consolidation.md`  
**Versione:** 1.0 — Maggio 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 3c — Consolidamento deferred da 3b + estensioni detection  
**Prerequisiti:** `phase3b-hardening.md` v1.2 ✅

> **Scopo:** Chiudere i gap deferred dalla Fase 3b e completare l'estensione della copertura detection. Al termine di questa fase: pipeline Greenbone → OpenSearch funzionante, FIM esteso ai Linux host, SCA verificato, MITRE ATT&CK tags completi su tutte le custom rules, target Greenbone settimanale per asset critici SOC.

**Changelog:**
- v1.0 — Maggio 2026 — Prima stesura. 6/6 task completati e verificati in produzione.

---

## Indice

1. [Task Overview](#1-task-overview)
2. [T-01 — Fix OpenSearch Indexing Greenbone](#2-t-01--fix-opensearch-indexing-greenbone)
3. [T-02 — Target Greenbone Settimanale Asset Critici SOC](#3-t-02--target-greenbone-settimanale-asset-critici-soc)
4. [T-03 — Verifica Alert Vulnerability Detector](#4-t-03--verifica-alert-vulnerability-detector)
5. [T-04 — Wazuh FIM su vm-103 e SOC-01](#5-t-04--wazuh-fim-su-vm-103-e-soc-01)
6. [T-05 — Wazuh SCA su Host Linux](#6-t-05--wazuh-sca-su-host-linux)
7. [T-06 — MITRE ATT&CK Tagging Regole Custom](#7-t-06--mitre-attck-tagging-regole-custom)
8. [Fix accesso remoto vm-103](#8-fix-accesso-remoto-vm-103)
9. [Checklist finale Fase 3c](#9-checklist-finale-fase-3c)
10. [Note tecniche e lezioni apprese](#10-note-tecniche-e-lezioni-apprese)

---

## 1. Task Overview

| Task | Priorità | Asset | Stato |
|---|---|---|---|
| T-01 Fix OpenSearch Indexing Greenbone | Alta | vm-103, ct-102 | ✅ Completato |
| T-02 Target Greenbone Settimanale Asset Critici SOC | Media | ct-102 (Greenbone UI) | ✅ Completato |
| T-03 Verifica Alert Vulnerability Detector | Media | vm-103 | ✅ Verificato |
| T-04 Wazuh FIM su vm-103 e SOC-01 | Media | vm-103, SOC-01 | ✅ Completato |
| T-05 Wazuh SCA su Host Linux | Bassa | vm-103, SOC-01 | ✅ Verificato |
| T-06 MITRE ATT&CK Tagging Regole Custom | Bassa | vm-103 | ✅ Completato |

---

## 2. T-01 — Fix OpenSearch Indexing Greenbone

### Problema

Alert rule 100070 (Greenbone finding High/Critical) presenti in `alerts.log` e `alerts.json`, notificati correttamente su Slack, ma **non indicizzati** in `wazuh-alerts-*` su OpenSearch. VIZ-05 della dashboard rimasta vuota dalla Fase 3b.

### Diagnosi

```
# Output Filebeat logs — errore diagnostico
Cannot index event (status=400):
{"type":"mapper_parsing_exception","reason":"object mapping for [data.port]
tried to parse field [port] as object, but found a concrete value"}
```

**Causa root:** l'indice OpenSearch aveva un mapping preesistente dove `data.port` è atteso come oggetto JSON (da altri alert Wazuh), mentre lo script `greenbone-to-wazuh.py` mandava il campo come stringa (`"4430/tcp"`). Conflitto di tipo → OpenSearch rifiutava silenziosamente l'intero documento.

### Fix applicato

**File:** `/opt/greenbone-to-wazuh.py` su ct-102  
Rinominato campo `"port"` → `"vuln_port"` nel dizionario `entry`:

```python
# Prima (causa conflitto mapping)
entry = {
    ...
    "port": result.findtext("port") or "",
    ...
}

# Dopo (fix)
entry = {
    ...
    "vuln_port": result.findtext("port") or "",
    ...
}
```

**Verifica:**
```bash
# Da SOC-01 — inietta finding di test
pct exec 102 -- bash -c 'echo "{\"source\":\"greenbone\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)\",\"vuln_name\":\"Test-fix\",\"host\":\"192.168.68.90\",\"vuln_port\":\"4430/tcp\",\"cvss\":7.5,\"cve\":\"CVE-2016-2183\",\"severity\":\"High\"}" >> /var/log/greenbone-findings.log'

# Su vm-103 — query OpenSearch (attesa 15 secondi)
curl -sk -u admin:PASSWORD \
  "https://localhost:9200/wazuh-alerts-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{"query": {"match": {"rule.id": "100070"}}, "size": 3}'
# Atteso: hits.total.value >= 1
```

**Risultato verificato:** alert indicizzato in `wazuh-alerts-4.x-2026.05.14`, VIZ-05 dashboard operativa con finding CVE-2016-2183.

---

## 3. T-02 — Target Greenbone Settimanale Asset Critici SOC

### Obiettivo

Il baseline mensile /24 copre tutti gli asset ma con frequenza insufficiente per i componenti più critici dell'infrastruttura SOC. Target settimanale dedicato per vm-103, SOC-01, ct-102.

### Configurazione Greenbone

**Target creato:**
- **Name:** `HomeSOC Critical Assets`
- **Hosts:** `192.168.68.200, 192.168.68.203, 192.168.68.204`
- **Port List:** `All IANA Assigned TCP`

**Task creato:**
- **Name:** `HomeSOC Weekly - Critical Assets`
- **Scan Targets:** `HomeSOC Critical Assets`
- **Scanner:** `OpenVAS Default`
- **Scan Config:** `Full and fast`

**Schedule creato:**
- **Name:** `Weekly SOC Assets`
- **First Time:** `2026-05-22 04:00`
- **Timezone:** `Europe/Rome`
- **Period:** `1 week`

**Schedule collegato** al task `HomeSOC Weekly - Critical Assets`.

---

## 4. T-03 — Verifica Alert Vulnerability Detector

### Comportamento in Wazuh 4.8+

In Wazuh 4.8+ il modulo `vulnerability-scanner` (ex `vulnerability-detector`) usa un motore completamente nuovo che **scrive i risultati direttamente in OpenSearch** nell'indice `wazuh-states-vulnerabilities-*`, bypassando il sistema di alert tradizionale (`alerts.json`).

Di conseguenza, la rule 100062 basata su `if_sid: 23501` non genera mai alert in `alerts.json` — la rule padre 23501 ha `level="0"` e non produce output nel flusso tradizionale.

### Verifica effettuata

```bash
curl -sk -u admin:PASSWORD \
  "https://localhost:9200/wazuh-states-vulnerabilities-*/_count?pretty"
# Output: {"count": 366, ...}
```

**366 CVE indicizzate** — il modulo funziona correttamente.

### Stato rule 100062

La rule 100062 è stata aggiornata (approccio `decoded_as: json` + `field vulnerability.cve`) ma rimane **non funzionale per alert Slack** con l'architettura attuale di Wazuh 4.8+.

**Workaround documentato:** i dati CVE sono consultabili in:
- **Wazuh Dashboard → Vulnerability Detection → Dashboard**
- Indice OpenSearch `wazuh-states-vulnerabilities-*`

**Azione futura:** valutare integrazione via OpenSearch alerting (watcher) per notifiche Slack su nuove CVE High/Critical — fuori scope Fase 3c.

---

## 5. T-04 — Wazuh FIM su vm-103 e SOC-01

### Obiettivo

Estendere il File Integrity Monitoring ai Linux host (vm-103 come agente 000/local, SOC-01 come agente 002), monitorando path critici dell'infrastruttura SOC.

### Configurazione vm-103 (`/var/ossec/etc/ossec.conf`)

Path aggiunti al blocco `<syscheck>` (in aggiunta ai default `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/boot`):

```xml
<!-- HomeSOC T-04: path critici aggiuntivi -->
<directories check_all="yes" report_changes="yes" realtime="yes">/var/ossec/etc/rules</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/var/ossec/etc/decoders</directories>
<directories check_all="yes" report_changes="yes">/var/ossec/etc/ossec.conf</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/opt/homesoc/scripts</directories>
<directories check_all="yes" report_changes="yes">/etc/ssh/sshd_config</directories>
```

### Configurazione SOC-01 (`/var/ossec/etc/ossec.conf`)

```xml
<!-- HomeSOC T-04: path critici SOC-01 -->
<directories check_all="yes" report_changes="yes" realtime="yes">/var/ossec/etc/rules</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/var/ossec/etc/decoders</directories>
<directories check_all="yes" report_changes="yes">/var/ossec/etc/ossec.conf</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/opt/homesoc/scripts</directories>
<directories check_all="yes" report_changes="yes">/etc/ssh/sshd_config</directories>
<directories check_all="yes" report_changes="yes">/etc/pve</directories>
```

> **Nota:** `/etc/pve` è la directory di configurazione Proxmox VE — qualsiasi modifica è critica per la sicurezza dell'hypervisor.

### Test di verifica

```bash
# Su vm-103 — crea file nella directory monitorata in realtime
sudo touch /var/ossec/etc/rules/test-fim.tmp
sleep 30
sudo grep "test-fim" /var/ossec/logs/alerts/alerts.log | tail -3
# Atteso: alert syscheck "File added" entro 30 secondi
sudo rm /var/ossec/etc/rules/test-fim.tmp
```

**Risultato verificato:** alert generato in realtime (`ossec,syscheck,syscheck_entry_added`) entro 30 secondi dalla creazione del file.

---

## 6. T-05 — Wazuh SCA su Host Linux

### Verifica

SCA (Security Configuration Assessment) è attivo di default in Wazuh con configurazione:

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
  <skip_nfs>yes</skip_nfs>
</sca>
```

### Risultati verificati

**SOC-01 (agent 002) — CIS Debian Linux 13 Benchmark:**

| Passed | Failed | Not Applicable | Score |
|---|---|---|---|
| 79 | 107 | 21 | **42%** |

Ultima scansione: `2026-05-21 @ 10:11:30`

**MacBook (agent 001) — CIS Apple macOS 26.0 Tahoe Benchmark:**
- Check "Ensure Screen Sharing Is Disabled" → `passed`

> **Nota:** il punteggio 42% su SOC-01 è il baseline di partenza per un sistema non hardened. Costituisce una baseline documentata per future attività di hardening CIS.

**Dashboard:** Wazuh Dashboard → Security Configuration Assessment → seleziona agent → Inventory.

---

## 7. T-06 — MITRE ATT&CK Tagging Regole Custom

### Obiettivo

Aggiungere tag `<mitre>` a tutte le custom rules in `local_rules.xml` che ne erano prive, portando la copertura al 100% delle rule custom.

### Stato pre-patch (v1.3 del file)

Le rule 100020–100032 avevano già i tag (alcune con doppi tag). Mancavano: 100060, 100061, 100062, 100070, 100071.

### Patch applicata

```python
# Metodo: Python stdlib in-place replacement
patches = {
    '100060': '<mitre><id>T1562.006</id></mitre>',  # Impair Defenses — Log Tampering
    '100061': '<mitre><id>T1110.001</id></mitre>',  # Password Guessing (AR fired)
    '100062': '<mitre><id>T1190</id></mitre>',      # Exploit Public-Facing Application
    '100070': '<mitre><id>T1190</id></mitre>',      # Exploit Public-Facing Application
    '100071': '<mitre><id>T1190</id></mitre>',      # Exploit Public-Facing Application
}
```

### Stato finale `local_rules.xml` v1.5

| Rule ID | Use Case | MITRE Tag |
|---|---|---|
| 100001 | UC-01 SSH brute force (utente inesistente) | T1110.001 |
| 100002 | UC-01 SSH brute force (password errata) | T1110.001 |
| 100010 | UC-02 IoT beaconing DNS cinese | T1071.001 |
| 100011 | UC-02 IoT beaconing frequenza alta | T1071.001 |
| 100020 | UC-03 FIM macOS LaunchAgents | T1565.001, T1543.001 |
| 100021 | UC-03 FIM macOS .ssh | T1565.001, T1098.004 |
| 100022 | UC-03 FIM macOS file eliminato | T1565.001, T1070.004 |
| 100023 | UC-03 FIM macOS workaround | T1565.001 |
| 100030 | UC-04 NAS porta inattesa | T1078, T1571 |
| 100031 | UC-04 NAS SMB down | T1078 |
| 100032 | UC-04 NAS offline (informativo) | T1078 |
| 100040 | UC-06 Rogue device | T1200 |
| 100041 | UC-06 Rogue device persistente | T1200 |
| 100060 | Health check log source stale | T1562.006 |
| 100061 | Active Response fired | T1110.001 |
| 100062 | Vulnerability Detector CVE High/Critical | T1190 |
| 100070 | Greenbone finding High/Critical | T1190 |
| 100071 | Greenbone finding Critical | T1190 |

**Verifica:**
```bash
sudo grep -c '<mitre>' /var/ossec/etc/rules/local_rules.xml
# Atteso: 18
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -iE "error|warning"
# Atteso: nessun output
```

---

## 8. Fix accesso remoto vm-103

### Problema

Prima della Fase 3c, vm-103 era accessibile solo via GUI Proxmox da LAN. Da remoto (Tailscale) o via SSH da SOC-01 non era possibile accedere perché:
- Serial console non configurata su Proxmox
- QEMU guest agent non installato
- Chiave SSH non deployata su vm-103

### Fix applicato

```bash
# Da SOC-01 — aggiunge serial0 e riavvia vm-103
qm set 103 --serial0 socket && qm reboot 103

# Da terminale seriale su vm-103
sudo apt install qemu-guest-agent -y
sudo systemctl enable --now qemu-guest-agent

# Deploy chiave SSH (chiave pubblica da MacBook)
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILsW59CQJvLyySX2FM9Xp4045yDFc1dRdh5P0u5+ieWp homesoc-admin" \
  >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

**Accesso SSH verificato:**
```bash
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204
```

---

## 9. Checklist finale Fase 3c

### Task completati

- [x] T-01: Fix `mapper_parsing_exception` OpenSearch — campo `port` rinominato `vuln_port` in `greenbone-to-wazuh.py`
- [x] T-01: Alert rule 100070 indicizzati in `wazuh-alerts-4.x-*` — verificato con query curl
- [x] T-01: VIZ-05 dashboard `Vulnerability Findings` operativa con dati reali
- [x] T-02: Target `HomeSOC Critical Assets` creato (vm-103, SOC-01, ct-102)
- [x] T-02: Task `HomeSOC Weekly - Critical Assets` creato con Full and fast config
- [x] T-02: Schedule `Weekly SOC Assets` — venerdì 04:00, periodo 1 settimana, timezone Europe/Rome
- [x] T-03: 366 CVE indicizzate in `wazuh-states-vulnerabilities-*` — vulnerability scanner operativo
- [x] T-03: Comportamento Wazuh 4.8+ documentato — vulnerability scanner bypassa alerts.json
- [x] T-04: FIM esteso a vm-103 — path critici Wazuh rules/decoders/scripts in realtime
- [x] T-04: FIM esteso a SOC-01 — aggiunto `/etc/pve` per Proxmox config
- [x] T-04: Test realtime verificato — alert syscheck generato in < 30 secondi
- [x] T-05: SCA su SOC-01 — CIS Debian 13 Benchmark: 79 passed / 107 failed / Score 42%
- [x] T-05: SCA su MacBook — CIS Apple macOS 26.0 Tahoe Benchmark attivo
- [x] T-06: 18/18 custom rules con tag MITRE ATT&CK — copertura 100%
- [x] T-06: `local_rules.xml` versione aggiornata a v1.5
- [x] T-06: `wazuh-analysisd -t` — nessun errore di sintassi

### Fix infrastrutturali

- [x] Serial console configurata su vm-103 (`qm set 103 --serial0 socket`)
- [x] QEMU guest agent installato su vm-103
- [x] Chiave SSH deployata su vm-103 — accesso diretto operativo

### Stato Use Case post-Fase 3c

| Use Case | Detection | Notification | Active Response |
|---|---|---|---|
| UC-01 SSH brute force | ✅ | ✅ Slack | ✅ firewall-drop |
| UC-02 IoT beaconing | ✅ | ✅ Slack (>20q/min) | ❌ N/A |
| UC-03 FIM macOS | ✅ | ✅ Slack | ❌ N/A |
| UC-03 FIM Linux | ✅ | ✅ syscheck alert | ❌ N/A |
| UC-04 NAS port monitor | ✅ | ✅ Slack | ❌ futuro |
| UC-05 Greenbone findings | ✅ | ✅ Slack + OpenSearch | ❌ manuale |
| UC-06 Rogue device | ✅ | ✅ Slack | ❌ futuro |
| Vuln. Detector CVE | ✅ | ✅ Dashboard | ❌ manuale |
| SCA Linux | ✅ | ✅ Dashboard | ❌ N/A |

---

## 10. Note tecniche e lezioni apprese

### OpenSearch mapping conflict

**Problema:** campi con nomi identici a quelli già presenti nel mapping dell'indice OpenSearch devono essere dello stesso tipo. Il campo `data.port` è mappato come oggetto in Wazuh per altri alert — inviarlo come stringa causa `mapper_parsing_exception` silenzioso (status 400, nessun errore visibile in Wazuh, solo in `filebeat.log`).

**Diagnostica:** `sudo tail -100 /var/log/filebeat/filebeat | grep -iE "error|warn"` — il log Filebeat è in `/var/log/filebeat/filebeat`, non in `/var/ossec/logs/filebeat.log`.

**Regola:** per campi custom nei decoder Greenbone, usare nomi che non collidano con il mapping standard Wazuh (`data.port`, `data.user`, `data.srcip`, ecc.).

### Wazuh 4.8+ vulnerability scanner

Il modulo `vulnerability-scanner` (rinominato da `vulnerability-detector`) in Wazuh 4.8+ scrive i risultati in `wazuh-states-vulnerabilities-*` su OpenSearch — non genera alert in `alerts.json`. Le rule basate su `if_sid: 23501` (rule padre con `level="0"`) non producono output nel flusso tradizionale.

Per notifiche Slack su nuovi CVE serve un approccio alternativo (OpenSearch alerting / watcher) — deferred.

### Accesso remoto vm-103

vm-103 deve avere almeno uno di questi meccanismi abilitati:
1. `qm set 103 --serial0 socket` + getty su ttyS0 in Ubuntu
2. QEMU guest agent (`qemu-guest-agent`)
3. Chiave SSH deployata

Tutti e tre ora attivi. Serial console + QEMU guest agent garantiscono accesso di emergenza anche senza rete.
