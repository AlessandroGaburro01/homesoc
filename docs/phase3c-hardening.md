# Fase 3c — Consolidamento Finale pre-Phase 4
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `docs/phase3c-hardening.md`  
**Versione:** 1.0 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 3c — Consolidamento finale e hardening detection stack  
**Prerequisiti:** `phase3b-hardening.md` v1.2 ✅ — tutti e 7 i task completati

> **Scopo:** Chiudere i gap operativi rimasti aperti dalla Fase 3b e completare il detection stack con tre estensioni a basso effort e alto valore: FIM su host Linux critici, SCA sistematico, e MITRE ATT&CK tagging delle regole custom. Al termine di questa fase il HomeSOC è documentabile come stack di detection completo, con visibilità classificata per tattica e tecnica avversariale, pronto per la Fase 3d (Deception Layer) e la Fase 4 (TheHive, Cortex, OpenCTI).

**Changelog:**
- v1.0 — Aprile 2026 — Prima stesura

---

## Indice

1. [Contesto — Deferred da Fase 3b](#1-contesto--deferred-da-fase-3b)
2. [Task Overview](#2-task-overview)
3. [T-01 — Fix OpenSearch Indexing Greenbone](#3-t-01--fix-opensearch-indexing-greenbone)
4. [T-02 — Target Greenbone Settimanale Asset Critici SOC](#4-t-02--target-greenbone-settimanale-asset-critici-soc)
5. [T-03 — Verifica Alert Vulnerability Detector](#5-t-03--verifica-alert-vulnerability-detector)
6. [T-04 — Wazuh FIM su vm-103 e SOC-01](#6-t-04--wazuh-fim-su-vm-103-e-soc-01)
7. [T-05 — Wazuh SCA su Host Linux](#7-t-05--wazuh-sca-su-host-linux)
8. [T-06 — MITRE ATT&CK Tagging Regole Custom](#8-t-06--mitre-attck-tagging-regole-custom)
9. [Checklist pre-Phase 3d](#9-checklist-pre-phase-3d)
10. [Aggiornamenti threat model e risk register](#10-aggiornamenti-threat-model-e-risk-register)

---

## 1. Contesto — Deferred da Fase 3b

I seguenti item sono stati identificati durante la Fase 3b e rimandati:

| Item | Origine | Motivo rimando |
|---|---|---|
| Alert Greenbone non indicizzati in OpenSearch | T-06 | Latenza indexer-connector per agent ct-102 appena enrollato |
| Target Greenbone settimanale asset critici SOC | Decisione operativa | Out of scope Fase 3b |
| Verifica alert Vulnerability Detector in alerts.log | T-05 | Non verificato in sessione |

Gli item T-04/T-05/T-06 sono nuove estensioni identificate nell'analisi post-3b.

---

## 2. Task Overview

| ID | Titolo | Priorità | Effort | Valore | Dipendenze |
|---|---|---|---|---|---|
| T-01 | Fix OpenSearch indexing Greenbone | 🔴 Alta | 30 min | Operativo — VIZ-05 dashboard | T-06 Fase 3b |
| T-02 | Target Greenbone settimanale SOC | 🟡 Media | 15 min | Detection — frequenza scan | Greenbone operativo |
| T-03 | Verifica alert Vulnerability Detector | 🟡 Media | 15 min | Verifica — T-05 Fase 3b | T-05 Fase 3b |
| T-04 | Wazuh FIM su vm-103 e SOC-01 | 🟡 Media | 30 min | Detection — persistence Linux | Agenti vm-103/SOC-01 attivi |
| T-05 | Wazuh SCA su host Linux | 🟢 Bassa | 20 min | Hardening — CIS benchmark | Agenti Linux attivi |
| T-06 | MITRE ATT&CK tagging regole custom | 🟢 Bassa | 45 min | Portfolio — classificazione tattica | Tutte le regole custom esistenti |

**Ordine consigliato:** T-01 → T-02 → T-03 → T-04 → T-05 → T-06

---

## 3. T-01 — Fix OpenSearch Indexing Greenbone

**Problema:** Gli alert rule 100070 (Greenbone findings) vengono correttamente scritti in `alerts.json` e notificati su Slack, ma non risultano indicizzati nell'indice `wazuh-alerts-*` di OpenSearch. VIZ-05 della dashboard `HomeSOC Security Operations` rimane vuota.

**Causa ipotizzata:** Il connettore OpenSearch per gli alert dell'agent ct-102 (ID 003, enrollato a fine sessione Fase 3b) non era ancora inizializzato al momento del test. Il problema dovrebbe risolversi autonomamente al prossimo ciclo di alert; se persiste, la causa è nella configurazione dell'indexer-connector.

**Dove:** vm-103

### 3.1 Verifica stato attuale

```bash
# Su vm-103 — verifica che il connettore sia inizializzato per ct-102
sudo grep "ct-102\|IndexerConnector" /var/ossec/logs/ossec.log | grep -i "greenbone\|003" | tail -10

# Verifica indici presenti in OpenSearch
curl -sk -u admin:WAZUH_PASSWORD https://localhost:9200/_cat/indices/wazuh-alerts-* | grep -v "^$"
```

### 3.2 Test injection manuale

Inietta un nuovo evento da ct-102 e aspetta 60 secondi:

```bash
# Su ct-102
echo '{"source":"greenbone","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S)'+00:00","vuln_name":"Test injection Fase 3c","host":"192.168.68.90","port":"4430/tcp","cvss":7.5,"cve":"CVE-2016-2183","severity":"High"}' >> /var/log/greenbone-findings.log
```

```bash
# Su vm-103 — dopo 60 secondi
sudo grep "100070" /var/ossec/logs/alerts/alerts.json | tail -3
```

Poi verifica in **Wazuh Dashboard** → `Explore` → `Discover` → filtro `Add filter: rule.id is 100070`.

### 3.3 Se il problema persiste — riavvio indexer-connector

```bash
# Su vm-103
sudo systemctl restart wazuh-indexer
sleep 30
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-indexer wazuh-manager
```

> ⚠️ **Ordine critico:** riavviare sempre wazuh-indexer prima di wazuh-manager. L'ordine inverso causa `port 443 connection refused`.

Dopo il riavvio, ripeti il test injection del passo 3.2.

> ✅ **Checkpoint T-01:** Wazuh Dashboard → `Discover` → filtro `rule.id: 100070` mostra almeno 1 documento. VIZ-05 nella dashboard `HomeSOC Security Operations` mostra dati.

---

## 4. T-02 — Target Greenbone Settimanale Asset Critici SOC

**Obiettivo:** Aggiungere un target Greenbone dedicato agli asset critici SOC con scan settimanale — attualmente coperti solo dal baseline mensile /24.

**Asset target:**

| Asset | IP | Motivo priorità |
|---|---|---|
| vm-103 (Wazuh) | 192.168.68.204 | SIEM — compromissione → perdita totale visibilità |
| SOC-01 (Proxmox) | 192.168.68.200 | Hypervisor — compromissione → accesso a tutte le VM |
| ct-102 (Greenbone) | 192.168.68.203 | Scanner vulnerabilità — compromissione → blind spot |

**Dove:** Greenbone Web UI — `http://192.168.68.203:9392`

### 4.1 Crea target

`Configuration` → `Targets` → `+ New Target`

| Campo | Valore |
|---|---|
| Name | `HomeSOC — Asset Critici SOC` |
| Hosts | `192.168.68.200,192.168.68.203,192.168.68.204` |
| Exclude Hosts | *(vuoto)* |
| Port List | `All IANA assigned TCP` |
| Alive Test | `Consider Alive` |
| Comment | `vm-103 Wazuh + SOC-01 Proxmox + ct-102 Greenbone — scan settimanale Fase 3c` |

### 4.2 Crea schedule settimanale

`Configuration` → `Schedules` → `+ New Schedule`

| Campo | Valore |
|---|---|
| Name | `SOC Assets Weekly — Mercoledì 03:00` |
| Timezone | `Europe/Rome` |
| First Time | Prossimo mercoledì, 03:00 |
| Period | `1 week` |
| Duration | `4 hours` |

> ℹ️ Mercoledì scelto per evitare conflitti con la scan domenicale UC-05 (02:00) e il cron lunedì 08:00 dello script greenbone-to-wazuh.py.

### 4.3 Crea task

`Scans` → `Tasks` → `+ New Task`

| Campo | Valore |
|---|---|
| Name | `HomeSOC — Scan Settimanale Asset Critici SOC` |
| Scan Targets | `HomeSOC — Asset Critici SOC` |
| Scanner | `OpenVAS Default` |
| Scan Config | `Full and fast` |
| Schedule | `SOC Assets Weekly — Mercoledì 03:00` |
| Comment | `Fase 3c — Copertura settimanale asset critici SOC` |

> ✅ **Checkpoint T-02:** Task visibile in `Scans` → `Tasks` con schedule associata. Al prossimo mercoledì alle 03:00 la scan parte automaticamente.

---

## 5. T-03 — Verifica Alert Vulnerability Detector

**Obiettivo:** Confermare che le CVE High/Critical rilevate dal Vulnerability Detector generino alert in `alerts.log` e siano visibili in Dashboard, oltre che in `Threat Intelligence` → `Vulnerability Detection`.

**Dove:** vm-103

### 5.1 Verifica alerts.log

```bash
# Su vm-103
sudo grep "100062\|vulnerability.*High\|vulnerability.*Critical" \
  /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -5
```

### 5.2 Se vuoto — forza nuovo ciclo

Il Vulnerability Detector gira ogni 12h con `run_on_start: yes`. Se non ha ancora prodotto alert:

```bash
# Su vm-103 — verifica ultimo ciclo
sudo grep "vulnerability-scanner" /var/ossec/logs/ossec.log | tail -10

# Verifica che l'inventario software dell'agent MacBook sia nel DB
sudo sqlite3 /var/ossec/queue/db/001.db \
  "SELECT name, version FROM sys_packages LIMIT 5;" 2>/dev/null
```

### 5.3 Verifica in Dashboard

**Wazuh Dashboard** → `Explore` → `Discover` → filtro `rule.id: 100062`

Se non ci sono risultati ma la `Vulnerability Detection` mostra CVE: il modulo funziona ma non ha ancora generato un alert 100062. Rule 100062 scatta solo quando viene rilevata una CVE **nuova** o **aggiornata** — non ad ogni scan.

> ✅ **Checkpoint T-03:** `alerts.json` contiene almeno una riga con `rule.id: 100062` OPPURE la Vulnerability Detection mostra CVE in Dashboard e il log ossec.log mostra `Finished vulnerability scan` recente (< 12h).

---

## 6. T-04 — Wazuh FIM su vm-103 e SOC-01

**Obiettivo:** Estendere File Integrity Monitoring ai due host Linux critici. FIM è attivo solo su END-05 (macOS, UC-03). Monitorare `/etc/`, binari di sistema e chiavi SSH su vm-103 e SOC-01 rileva: persistence via cron/systemd, modifica di binari, aggiunta non autorizzata di chiavi SSH.

### 6.1 FIM su vm-103

**Host: vm-103** — modifica `ossec.conf` del manager (che è anche agent ID 000):

```bash
# Su vm-103
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-$(date +%Y%m%d)-t04-3c
sudo nano /var/ossec/etc/ossec.conf
```

Aggiungere nel blocco `<syscheck>` esistente (o crearlo se assente):

```xml
<!-- T-04 Fase 3c: FIM su vm-103 — percorsi critici Linux -->
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency><!-- ogni 12 ore -->

  <!-- Percorsi critici sistema -->
  <directories check_all="yes" report_changes="yes" realtime="yes">/etc</directories>
  <directories check_all="yes" report_changes="yes">/usr/bin</directories>
  <directories check_all="yes" report_changes="yes">/usr/sbin</directories>
  <directories check_all="yes" report_changes="yes">/lib/systemd/system</directories>

  <!-- SSH e credenziali -->
  <directories check_all="yes" report_changes="yes" realtime="yes">/root/.ssh</directories>
  <directories check_all="yes" report_changes="yes" realtime="yes">/home/alessandro/.ssh</directories>

  <!-- Wazuh config (integrità del SIEM stesso) -->
  <directories check_all="yes" report_changes="yes">/var/ossec/etc/rules</directories>
  <directories check_all="yes" report_changes="yes">/var/ossec/etc/decoders</directories>

  <!-- Esclusioni per ridurre il rumore -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <ignore>/etc/mail/statistics</ignore>
  <ignore>/etc/random-seed</ignore>
  <ignore>/etc/adjtime</ignore>
  <ignore>/etc/resolv.conf</ignore>
</syscheck>
```

```bash
sudo systemctl reload wazuh-manager
sudo systemctl is-active wazuh-manager
```

### 6.2 FIM su SOC-01

**Host: SOC-01** — modifica `ossec.conf` dell'agent (ID 002):

```bash
# Su SOC-01
ssh -p 2222 alessandro@192.168.68.200
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-$(date +%Y%m%d)-t04-3c
sudo nano /var/ossec/etc/ossec.conf
```

Aggiungere il blocco `<syscheck>`:

```xml
<!-- T-04 Fase 3c: FIM su SOC-01 (Proxmox host) -->
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>

  <!-- Sistema Proxmox -->
  <directories check_all="yes" report_changes="yes" realtime="yes">/etc</directories>
  <directories check_all="yes" report_changes="yes">/usr/bin</directories>
  <directories check_all="yes" report_changes="yes">/usr/sbin</directories>
  <directories check_all="yes" report_changes="yes">/lib/systemd/system</directories>

  <!-- SSH -->
  <directories check_all="yes" report_changes="yes" realtime="yes">/root/.ssh</directories>
  <directories check_all="yes" report_changes="yes" realtime="yes">/home/alessandro/.ssh</directories>

  <!-- Config Proxmox critica -->
  <directories check_all="yes" report_changes="yes">/etc/pve</directories>

  <!-- Esclusioni -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <ignore>/etc/adjtime</ignore>
  <ignore>/etc/resolv.conf</ignore>
</syscheck>
```

```bash
sudo systemctl restart wazuh-agent
sudo systemctl is-active wazuh-agent
```

### 6.3 Verifica

```bash
# Su vm-103 — dopo 5 minuti dalla riattivazione
sudo grep "syscheck\|FIM" /var/ossec/logs/ossec.log | grep -i "vm-103\|soc-01\|002\|000" | tail -10
```

In Dashboard: `Endpoint Security` → `File Integrity Monitoring` — devono comparire i nuovi agent.

> ✅ **Checkpoint T-04:** FIM attivo su vm-103 (agent 000) e SOC-01 (agent 002). Dashboard FIM mostra i percorsi `/etc` monitorati.

---

## 7. T-05 — Wazuh SCA su Host Linux

**Obiettivo:** Attivare Security Configuration Assessment con profilo CIS Level 1 su vm-103 e SOC-01. SCA è già integrato in Wazuh e gira di default — la verifica consiste nel confermare che il profilo corretto sia caricato e i risultati siano visibili in Dashboard.

**Dove:** vm-103 e SOC-01

### 7.1 Verifica SCA su vm-103

```bash
# Su vm-103
sudo grep "sca" /var/ossec/etc/ossec.conf | head -5

# Verifica policy disponibili
ls /var/ossec/ruleset/sca/
# Atteso: cis_debian12.yml (o ubuntu22-04.yml secondo la distro)

# Verifica ultimo scan SCA
sudo grep "sca.*Evaluation finished\|SCA scan" /var/ossec/logs/ossec.log | tail -5
```

### 7.2 Verifica SCA su SOC-01

```bash
# Su SOC-01
sudo grep "sca.*Evaluation finished" /var/ossec/logs/ossec.log | tail -3
ls /var/ossec/ruleset/sca/ | grep debian
```

### 7.3 Se SCA è disabilitato — abilitazione

Se `ossec.conf` contiene `<sca><enabled>no</enabled>`:

```bash
# Su vm-103 o SOC-01 secondo necessità
sudo sed -i 's/<enabled>no<\/enabled>/<enabled>yes<\/enabled>/g' /var/ossec/etc/ossec.conf
sudo systemctl reload wazuh-manager  # vm-103
# oppure
sudo systemctl restart wazuh-agent   # SOC-01
```

### 7.4 Verifica in Dashboard

**Wazuh Dashboard** → `Endpoint Security` → `Configuration Assessment` → seleziona agent.

Mostra punteggio CIS, check passati/falliti, e dettaglio per ogni controllo.

> ✅ **Checkpoint T-05:** Dashboard → `Configuration Assessment` mostra risultati SCA per vm-103 e SOC-01 con profilo CIS Debian attivo.

---

## 8. T-06 — MITRE ATT&CK Tagging Regole Custom

**Obiettivo:** Aggiungere tag `<mitre>` a tutte le regole custom HomeSOC in `local_rules.xml`. Questo sblocca la vista `Threat Intelligence` → `MITRE ATT&CK` in Dashboard, permettendo di visualizzare la copertura tattica del detection stack sulla matrice ATT&CK.

**Dove:** vm-103

**Valore:** trasforma il SIEM da "vedo log" a "vedo comportamenti avversariali classificati per tattica". Output direttamente spendibile in portfolio e in colloqui Blue Team.

### 8.1 Mapping regole → tecniche ATT&CK

| Rule ID | Descrizione | Tecnica ATT&CK | Tattica |
|---|---|---|---|
| 100001 | SSH brute force (UC-01) | T1110.001 — Brute Force: Password Guessing | Credential Access |
| 100011 | IoT beaconing >20 query/min (UC-02) | T1071.004 — App Layer Protocol: DNS | Command and Control |
| 100020 | FIM macOS — file modificato (UC-03) | T1565.001 — Data Manipulation: Stored Data | Impact |
| 100023 | FIM macOS — file critico (UC-03) | T1565.001 — Data Manipulation: Stored Data | Impact |
| 100030 | NAS port monitor — porta nuova (UC-04) | T1046 — Network Service Discovery | Discovery |
| 100031 | NAS port monitor — porta scomparsa (UC-04) | T1046 — Network Service Discovery | Discovery |
| 100040 | Rogue device rilevato (UC-06) | T1200 — Hardware Additions | Initial Access |
| 100041 | Rogue device multiplo (UC-06) | T1200 — Hardware Additions | Initial Access |
| 100051 | CrowdSec ban (da crowdsec-rules.xml) | T1110 — Brute Force | Credential Access |
| 100061 | Active Response firewall-drop | T1548.003 — Sudo and Sudo Caching | Privilege Escalation |
| 100062 | CVE High/Critical da Vuln Detector | T1190 — Exploit Public-Facing Application | Initial Access |
| 100070 | Greenbone finding High/Critical | T1190 — Exploit Public-Facing Application | Initial Access |

### 8.2 Aggiornamento local_rules.xml

```bash
# Su vm-103
sudo cp /var/ossec/etc/rules/local_rules.xml \
  /var/ossec/etc/rules/local_rules.xml.bak-$(date +%Y%m%d)-t06-3c
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Aggiungere il blocco `<mitre>` a ciascuna regola. Esempio per rule 100001:

```xml
<rule id="100001" level="10" frequency="5" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <!-- ...campi esistenti... -->
  <mitre>
    <id>T1110.001</id>
  </mitre>
</rule>
```

Aggiungere analogamente per tutte le rule del mapping sopra.

### 8.3 Reload e verifica

```bash
sudo systemctl reload wazuh-manager
sudo systemctl is-active wazuh-manager
```

Verifica con logtest che le regole carichino senza errori:

```bash
echo "test" | sudo /var/ossec/bin/wazuh-logtest 2>&1 | grep -i "error\|warning" | head -10
```

### 8.4 Verifica in Dashboard

**Wazuh Dashboard** → `Threat Intelligence` → `MITRE ATT&CK`

La matrice mostrerà le tecniche coperte dalle regole custom taggiate.

> ✅ **Checkpoint T-06:** Dashboard → `MITRE ATT&CK` mostra almeno le tecniche T1110/T1190/T1046/T1200/T1565 attive con alert associati.

---

## 9. Checklist pre-Phase 3d

### Componenti Fase 3c

- [ ] T-01: Alert Greenbone indicizzati in OpenSearch — VIZ-05 dashboard mostra dati
- [ ] T-02: Target `HomeSOC — Asset Critici SOC` creato con schedule settimanale mercoledì 03:00
- [ ] T-03: Alert Vulnerability Detector (rule 100062) confermato in alerts.json o scan recente verificata
- [ ] T-04: FIM attivo su vm-103 (agent 000) — percorsi `/etc`, `.ssh`, regole Wazuh monitorati
- [ ] T-04: FIM attivo su SOC-01 (agent 002) — percorsi `/etc`, `.ssh`, `/etc/pve` monitorati
- [ ] T-05: SCA con profilo CIS Debian visibile in Dashboard per vm-103 e SOC-01
- [ ] T-06: Tag `<mitre>` aggiunti a tutte le rule custom — MITRE ATT&CK Dashboard mostra copertura

### Stato detection stack post-Fase 3c

| Livello | Componente | Stato |
|---|---|---|
| Network perimeter | CrowdSec (SOC-01) | ✅ Operativo |
| SIEM & correlation | Wazuh Manager (vm-103) | ✅ Operativo |
| Vulnerability management | Greenbone (ct-102) + Vuln Detector | ✅ Operativo |
| Endpoint detection | Wazuh Agent END-05, SOC-01, ct-102 | ✅ Operativo |
| File integrity | FIM macOS + FIM Linux (vm-103, SOC-01) | ✅ Operativo post-T-04 |
| Configuration hardening | SCA CIS Debian su host Linux | ✅ Operativo post-T-05 |
| Threat classification | MITRE ATT&CK tagging regole custom | ✅ Operativo post-T-06 |
| Alerting | Slack `#homesoc-alerts` | ✅ Operativo |
| Dashboard | HomeSOC Security Operations (7 VIZ) | ✅ Operativo |
| Deception layer | Canarytoken, OpenCanary, Endlessh | ⏳ Fase 3d |

---

## 10. Aggiornamenti threat model e risk register

Aggiornare `docs/01-threat-model.md` v1.5 al termine di Fase 3c:

| Rischio | Stato pre-3c | Stato post-3c | Motivazione |
|---|---|---|---|
| R-09 Tampering SOC-01 | Parziale | **Mitigato ✅** | FIM su /etc e /etc/pve di SOC-01 attivo |
| R-02 Lateral movement END-05 | Parziale | Parziale → | FIM Linux aggiunto; OPNsense futuro per isolamento completo |
| R-08 Modifica file critici | Mitigato ✅ | Mitigato ✅ + | FIM esteso anche a vm-103 e SOC-01 |

---

*File: `docs/phase3c-hardening.md` · v1.0 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
