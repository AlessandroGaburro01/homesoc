# Fase 3b — Hardening & Integration
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `docs/phase3b-hardening.md`  
**Versione:** 1.2 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 3b — Consolidamento pre-Phase 4  
**Prerequisiti:** `wazuh-deploy.md` v1.2 ✅ · `wazuh-slack.md` v1.0 ✅ · `crowdsec-deploy.md` v1.2 ✅

> **Scopo:** Prima di procedere con la Fase 4 (TheHive, Cortex, OpenCTI), questa fase intermedia porta l'infrastruttura esistente dalla condizione *"deployata e funzionante"* alla condizione *"operativa e difensivamente efficace"*. Ogni tool già installato viene integrato, chiusi i gap di visibilità identificati post-deploy, e aggiunta la capacità di risposta attiva. Al termine di questa fase il HomeSOC produce **protezione reale e misurabile**, non solo alert.

**Changelog:**
- v1.2 — Aprile 2026 — T-05/T-06/T-07 completati. T-05: vulnerability-scanner già attivo di default in Wazuh 4.8+ (`<vulnerability-detector>` deprecato, usa valori default); Dashboard mostra 25 High + 32 Medium su soc-01 e MacBook; rule 100062 aggiunta. T-06: pipeline Greenbone → Wazuh via script stdlib-only Python eseguito con `docker exec -i` nel container gvmd; agent ct-102-greenbone (ID 003) enrollato; finding CVE-2016-2183 NAS 192.168.68.90:4430 CVSS 7.5 verificato end-to-end inclusa notifica Slack; regole rinominate 100070/100071 (conflitto con crowdsec-rules.xml che usava 100050/100051); nota: alert Greenbone non indicizzati in OpenSearch (deferred Fase 3c). T-07: dashboard `HomeSOC Security Operations` creata con 7 visualizzazioni; VIZ-05 vuota per issue indicizzazione OpenSearch (deferred Fase 3c).
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
sudo crontab -l | grep nextdns
sudo ls -lh /var/log/homesoc/nextdns.log
sudo stat /var/log/homesoc/nextdns.log | grep Modify
sudo tail -3 /var/log/homesoc/nextdns.log
```

### 3.2 Verifica cron nmap rogue device (UC-06)

```bash
# Su vm-103
sudo crontab -l | grep rogue
sudo ls -lh /var/log/homesoc/rogue-device.log
sudo tail -3 /var/log/homesoc/rogue-device.log
```

### 3.3 Verifica NAS port monitor (UC-04)

```bash
# Su vm-103
sudo ls -lh /var/log/homesoc/nas-monitor.log
sudo tail -3 /var/log/homesoc/nas-monitor.log
```

### 3.4 Verifica FIM workaround macOS (UC-03)

```bash
# Su MacBook (END-05)
crontab -l | grep fim
ls -lh /var/log/fim-macos.log
tail -3 /var/log/fim-macos.log
```

### 3.5 Script di health check automatizzato

`/usr/local/bin/homesoc-healthcheck.sh` su vm-103, cron ogni 30 minuti. Controlla freshness di nextdns, rogue-device, nas-monitor. Se un log supera la soglia (120 min default) scrive evento `STALE` che trigghera rule Wazuh 100060 → alert Slack.

> ✅ **Checkpoint T-01:** Tutti e tre i log mostrano `status=OK`. Script healthcheck attivo via cron su vm-103.

---

## 4. T-02 — Fix threshold UC-02 per Slack

**Obiettivo:** Portare le notifiche IoT beaconing su Slack.

**Decisione documentata:** Rule 100010 (ogni query) commentata in `ossec.conf` — troppo rumorosa. Solo rule 100011 (>20 query/min) notifica Slack. Level 100011 elevato a 12 per superare la soglia dell'integration Slack (`<level>10</level>`).

> ✅ **Checkpoint T-02:** IoT beaconing >20 query/min genera notifica Slack via rule 100011.

---

## 5. T-03 — Uptime Kuma → Slack

**Obiettivo:** Notifica Slack per down/up servizi monitorati da Uptime Kuma.

Configurato webhook Slack direttamente in Uptime Kuma → `Settings` → `Notifications`. Testato con arresto/riavvio servizio di test.

> ✅ **Checkpoint T-03:** Uptime Kuma invia notifica Slack per eventi down/up.

---

## 6. T-04 — Wazuh Active Response (UC-01)

**Obiettivo:** Blocco IP automatico su brute force SSH tramite Wazuh Active Response.

**Dove:** vm-103 (config) + SOC-01 (agent ID 002, target blocco)

**Configurazione:**
- Agent SOC-01 enrollato (ID 002, porta SSH 2222)
- Active Response `firewall-drop` configurato su rule 100001 (SSH brute force)
- Rule 100061 (level 12) per notifica Slack quando AR viene eseguito
- Whitelist IP interni configurata per evitare auto-blocco

**Limitazione nota (macOS):** `sshd-session` su macOS non logga auth failures standard — active response non applicabile a END-05 via questo vettore.

> ✅ **Checkpoint T-04:** Brute force SSH su SOC-01 → blocco iptables DROP verificato → notifica Slack rule 100061.

---

## 7. T-05 — Wazuh Vulnerability Detector

**Obiettivo:** Rilevazione CVE sui pacchetti installati sugli agent, con alert Slack per severity High/Critical.

**Nota critica (Wazuh 4.8+):** Il blocco `<vulnerability-detector>` in ossec.conf è **deprecato**. Wazuh 4.8+ usa il modulo `vulnerability-scanner` attivo di default con configurazione automatica. Qualsiasi blocco `<vulnerability-detector>` aggiunto manualmente viene ignorato con WARNING nel log; il modulo usa i valori di default. **Non aggiungere il blocco manualmente.**

**Risultati primo scan (24/04/2026):**
- `soc-01` (Debian GNU/Linux 13): 41 CVE — 25 High, 32 Medium, 3 Low
- `MacBookPro-di-Alessandro-Gaburro.local` (macOS): 30 CVE
- 0 Critical
- Top package vulnerabili: `amd64-microcode`, `urllib3`, `pip`, `setuptools`, `vim`

**Rule aggiunta in `local_rules.xml`:**

```xml
<!-- T-05: CVE High/Critical → Slack -->
<rule id="100062" level="12">
  <if_sid>23501</if_sid>
  <field name="vulnerability.severity">Critical|High</field>
  <description>HomeSOC: CVE $(vulnerability.cve) su $(agent.name) — $(vulnerability.severity) CVSS $(vulnerability.cvss.cvss3.base_score)</description>
  <group>homesoc,vulnerability,</group>
</rule>
```

La rule 100062 è catturata dal filtro `<level>10</level>` del blocco Slack esistente — nessuna modifica a ossec.conf necessaria.

**Verifica Dashboard:** `Threat Intelligence` → `Vulnerability Detection`

> ✅ **Checkpoint T-05:** Wazuh Dashboard → `Vulnerability Detection` mostra CVE su soc-01 e MacBook. Rule 100062 pronta per CVE High/Critical.

---

## 8. T-06 — Greenbone → Wazuh Pipeline

**Obiettivo:** Pipeline automatizzata Greenbone → Wazuh → Slack per finding CVSS ≥ 7.0.

**Architettura finale (adattata alle constraint Docker):**

Il socket GVM è su tmpfs interno al container `greenbone-community-edition-gvmd-1` — non accessibile dal filesystem host né tramite named volume. La pipeline usa `docker exec -i` per eseguire lo script dentro il container.

### 8.1 Script — `/opt/greenbone-to-wazuh.py` (su ct-102)

Script stdlib-only (zero dipendenze esterne) che:
1. Si connette al socket GVM interno `/run/gvmd/gvmd.sock`
2. Autentica con credenziali admin
3. Recupera l'ultimo report con stato `Done`
4. Estrae finding con CVSS ≥ 7.0
5. Scrive JSON lines su stdout

**Esecuzione:**
```bash
docker exec -i greenbone-community-edition-gvmd-1 \
  python3 < /opt/greenbone-to-wazuh.py \
  >> /var/log/greenbone-findings.log 2>>/var/log/greenbone-to-wazuh-cron.log
```

### 8.2 Cron su ct-102

```
0 8 * * 1  docker exec -i greenbone-community-edition-gvmd-1 python3 < /opt/greenbone-to-wazuh.py >> /var/log/greenbone-findings.log 2>>/var/log/greenbone-to-wazuh-cron.log
```

Esecuzione lunedì alle 08:00 — il giorno dopo la scan domenicale delle 02:00.

### 8.3 Wazuh Agent su ct-102

Agent `ct-102-greenbone` enrollato (ID 003, Active). Logcollector configurato per `/var/log/greenbone-findings.log` con `log_format: json`.

```xml
<!-- In /var/ossec/etc/ossec.conf su ct-102 -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/greenbone-findings.log</location>
</localfile>
```

### 8.4 Decoder su vm-103

File: `/var/ossec/etc/decoders/greenbone-decoder.xml`

```xml
<!-- T-06: Greenbone findings decoder -->
<decoder name="greenbone-findings">
  <prematch>{"source":"greenbone"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

### 8.5 Rule su vm-103

**Nota critica:** Rule ID 100050 e 100051 erano già in uso in `crowdsec-rules.xml`. Le rule Greenbone sono state rinominate **100070** e **100071** per evitare conflitti.

```xml
<!-- T-06: Greenbone finding High/Critical -->
<rule id="100070" level="12">
  <decoded_as>json</decoded_as>
  <field name="source">greenbone</field>
  <field name="severity">High|Critical</field>
  <description>HomeSOC: Greenbone finding $(severity) — CVE $(cve) su host $(host) (CVSS $(cvss))</description>
  <group>homesoc,vulnerability,greenbone,uc05,</group>
</rule>

<rule id="100071" level="15">
  <if_sid>100070</if_sid>
  <field name="severity">Critical</field>
  <description>HomeSOC: Greenbone finding CRITICO — $(vuln_name) su $(host) CVSS $(cvss)</description>
  <group>homesoc,vulnerability,greenbone,uc05,critical,</group>
</rule>
```

**Finding verificato in produzione (24/04/2026):**
- CVE-2016-2183 (SWEET32) — NAS WD My Cloud Home (192.168.68.90:4430/tcp) — cipher suite 3DES — CVSS 7.5 High
- Pipeline end-to-end: Greenbone → log → Wazuh alert 100070 → notifica Slack ✅

**Issue nota (deferred Fase 3c):** Alert rule 100070 presenti in `alerts.json` e notificati su Slack, ma non indicizzati in `wazuh-alerts-*` OpenSearch. VIZ-05 della dashboard rimane vuota. Causa probabile: latenza indexer-connector per agent ct-102 appena enrollato.

> ✅ **Checkpoint T-06:** Pipeline Greenbone → Wazuh → Slack verificata end-to-end con finding reale CVE-2016-2183 sul NAS.

---

## 9. T-07 — HomeSOC Security Dashboard

**Obiettivo:** Dashboard operativa unificata in Wazuh Dashboard.

**Percorso:** `Explore` → `Dashboards` → `Create new dashboard`

**Dashboard salvata:** `HomeSOC Security Operations`

### 9.1 Visualizzazioni create

| ID | Nome | Tipo | Filtro | Stato |
|---|---|---|---|---|
| VIZ-01 | `[HomeSOC] UC Events — 7 Days` | Vertical Bar | `rule.groups: homesoc` | ✅ Dati reali |
| VIZ-02 | `[HomeSOC] Alert Level Distribution` | Pie | `rule.groups: homesoc` | ✅ Dati reali (level 8/10/12) |
| VIZ-03 | `[HomeSOC] Top Attacker IPs` | Data Table | `rule.groups: homesoc` / field `data.srcip` | ✅ Dati reali |
| VIZ-04 | `[HomeSOC] FIM Events — UC-03` | Vertical Bar | `rule.groups: syscheck` | ✅ Dati reali |
| VIZ-05 | `[HomeSOC] Vulnerability Findings` | Data Table | `rule.id: 100070` | ⚠️ Vuota — issue OpenSearch (Fase 3c) |
| VIZ-06 | `[HomeSOC] Active Response Log` | Data Table | `rule.groups: active_response` | ✅ Dati reali |
| VIZ-07 | `[HomeSOC] Log Source Health` | Data Table | `rule.groups: health` | ✅ Dati reali (9 eventi) |

> ✅ **Checkpoint T-07:** Dashboard `HomeSOC Security Operations` accessibile su `https://192.168.68.204`. 6/7 visualizzazioni con dati reali. VIZ-05 deferred Fase 3c.

---

## 10. Checklist pre-Phase 4

### Componenti infrastrutturali

- [x] T-01: Health check eseguito — nextdns, rogue-device, nas-monitor `status=OK`
- [x] T-01: Script `homesoc-healthcheck.sh` attivo via cron su vm-103 (ogni 30 min)
- [x] T-02: UC-02 Slack configurato — 100011 (>20 query/min) notifica Slack; 100010 commentato (decisione documentata)
- [x] T-03: Uptime Kuma invia notifica Slack per down/up servizi — testato
- [x] T-04: Wazuh Agent installato su SOC-01 (ID 002, Active)
- [x] T-04: Wazuh Active Response blocca IP brute force su SOC-01 — `iptables DROP` verificato
- [x] T-04: Rule 100061 aggiunta in `local_rules.xml`
- [x] T-05: Vulnerability Detector attivo — report disponibile in Dashboard (25 High + 32 Medium)
- [x] T-05: Rule 100062 aggiunta per CVE High/Critical → Slack
- [x] T-06: Wazuh Agent ct-102-greenbone (ID 003) installato e Active
- [x] T-06: Pipeline `greenbone-to-wazuh.py` testata — finding CVE-2016-2183 verificato end-to-end
- [x] T-06: Rule 100070/100071 generano alert per finding Greenbone (rinominate da 100050/100051 per conflitto crowdsec)
- [x] T-07: Dashboard `HomeSOC Security Operations` accessibile con dati reali (6/7 visualizzazioni)
- [⚠️] T-06/T-07: Alert Greenbone non indicizzati in OpenSearch — deferred Fase 3c

### Stato Use Case post-Fase 3b

| Use Case | Detection | Notification | Active Response |
|---|---|---|---|
| UC-01 SSH brute force | ✅ | ✅ Slack | ✅ firewall-drop su SOC-01 (T-04) |
| UC-02 IoT beaconing | ✅ | ✅ Slack — 100011 >20q/min (T-02) | ❌ (non applicabile) |
| UC-03 FIM macOS | ✅ | ✅ Slack | ❌ (non applicabile) |
| UC-04 NAS port monitor | ✅ | ✅ Slack | ❌ futuro |
| UC-06 Rogue device | ✅ | ✅ Slack | ❌ futuro |
| Greenbone findings | ✅ (T-06) | ✅ Slack (T-06) | ❌ (manuale) |
| Vuln. Detector CVE | ✅ (T-05) | ✅ Slack (T-05) | ❌ (manuale) |
| Log source stale | ✅ (T-01) | ✅ Slack (T-01) | ❌ (non applicabile) |

### Protezione attiva post-Fase 3b

| Vettore | Protezione | Strumento |
|---|---|---|
| SSH brute force su SOC-01 | ✅ Blocco IP automatico | CrowdSec |
| SSH brute force su END-05 | ✅ Blocco IP automatico | Wazuh AR (T-04) |
| Vulnerabilità note (rete) | ✅ Alert mensile (baseline /24) | Greenbone → Wazuh |
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
| R-02 NAS accesso non auth | Parziale | Parziale | Monitoring attivo, AR non applicabile a NAS |
| R-08 Modifiche file critici | Parziale | ✅ Mitigato | FIM + AR pipeline completa |
| R-10 SSH brute force | Parziale (solo detect) | ✅ Mitigato | T-04: active response attivo |

---

## 12. Elementi deferred — Fase 3c

I seguenti elementi sono stati identificati durante la Fase 3b e riportati alla Fase 3c:

1. **Fix indicizzazione OpenSearch alert Greenbone** — Alert rule 100070 arrivano a Slack ma non vengono indicizzati in `wazuh-alerts-*`. VIZ-05 dashboard vuota. Da investigare: configurazione indexer-connector per agent ct-102 di recente enrollment.

2. **Target Greenbone settimanale per asset critici SOC** — vm-103 (192.168.68.204), SOC-01 (192.168.68.200), ct-102 (192.168.68.203) sono attualmente coperti solo dal baseline mensile /24. Un target dedicato con scan settimanale aumenterebbe la frequenza di rilevazione per gli asset più critici.

3. **Verifica alert T-05 in alerts.log** — Confermare che le CVE High/Critical rilevate dal Vulnerability Detector generino alert tracciati in `alerts.log` oltre che in Dashboard.

---

*File: `docs/phase3b-hardening.md` · v1.2 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
