# Changelog

All notable changes to this project are documented here.
Format: [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)  — `type(scope): description`

---

## [Unreleased]

## [0.9.1] — 2026-05-22

### Added
- `docs/phase4-incident-response.md` v1.0 — design document completo Fase 4: TheHive 5 + Cortex 3, script Wazuh integration, 4 playbook IR, 5 ADR
- `vm-105` (vm-ir, `192.168.68.205`) — VM Ubuntu 22.04 su Proxmox ID 105 (ID 104 occupato da ct-104 OpenCanary)
- TheHive 5.7.2 installato via `.deb` manuale (`thehive.download.strangebee.com`) con LocalDB/BerkeleyDB
- Wazuh agent ID 005 (`vmir`) su vm-105 — Active

### Changed
- `docs/02-architecture.md` v1.1 → v1.2: tabella VM layout aggiornata con ID reali (ct-104 OpenCanary, vm-105 vm-ir), riferimenti vm-104 → vm-105, colonna Stato aggiunta
- `Inventario_IP_Pulito.csv`: aggiunte righe infrastruttura SOC (.200–.206)

### Notes
- ADR-04-02 deviazione: script automatico StrangeBee installa Cassandra+Elasticsearch (OOM con 4 GB RAM); soluzione: `.deb` manuale + LocalDB. Funzionalità identiche, consumo RAM ~1.3 GB vs ~4-6 GB
- T-01 ✅ completo — T-02 in corso (TheHive up, Cortex pending)

## [0.9.0] — 2026-05-21

### Added
- `docs/phase3d-deception.md` v1.1 — Fase 3d completata: deception layer operativo in produzione
- `ct-104` LXC Debian 12 (`192.168.68.206`, hostname `backup-srv`) — nuovo asset infrastruttura
- OpenCanary 0.9.8 su ct-104: honeypot 5 porte (SSH:22, FTP:21, HTTP:8080, Telnet:23, MySQL:3306) con banner Ubuntu 22.04 LTS convincenti
- Endlessh SSH tarpit su SOC-01:22 (SSH reale confermato su :2222)
- Wazuh agent ID 004 (`ct-104-opencanary`) su ct-104 — logcollector JSON per `/var/log/opencanary/opencanary.log`
- 5 Canarytoken deployati: TK-01 Word (NAS), TK-02 Word (MacBook Desktop), TK-03 AWS Keys (`~/.aws/credentials`), TK-04 DNS (embedded in README), TK-05 README (NAS)
- `detection-rules/deception-rules.xml` — regole Wazuh 100080–100085 con MITRE ATT&CK mapping
- `detection-rules/opencanary-decoder.xml` — decoder Endlessh (OpenCanary usa decoder json nativo)
- Slack routing per regole deception in `/var/ossec/integrations/slack.py`: funzioni `_msg_deception_honeypot`, `_msg_deception_ssh`, `_msg_deception_tarpit`
- Entry `/etc/hosts` su ct-104, vm-103, MacBook: `backup-srv backup-srv.local → 192.168.68.206`

### Changed
- `docs/phase3d-deception.md` v1.0 → v1.1: runbook aggiornato con deployment effettivo e sezione deviazioni dal piano (§12)
- ct-104 sshd spostato su porta 2222 per liberare :22 a OpenCanary

### Fixed
- OpenCanary MySQL banner: aggiunto prefisso `5.5.5-` richiesto da versione 0.9.8 (`ConfigException: Invalid MySQL Banner`)
- Wazuh decoder OpenCanary: sostituito `<decoded_as>opencanary</decoded_as>` con `<decoded_as>json</decoded_as>` + `<field name="node_id">backup-srv</field>` — il prematch non trovava match nel corpo JSON puro
- ct-104 DNS resolution: aggiunto `nameserver 8.8.8.8` in `/etc/resolv.conf` (LXC unprivileged non eredita DNS dall'host)

### Verified
- **T-01:** TK-02 Word aperto su MacBook → alert Slack ricevuto in `#homesoc-alerts` entro 30 secondi ✅
- **T-02:** OpenCanary SSH su ct-104:22 → log JSON in `/var/log/opencanary/opencanary.log` ✅
- **T-03:** Endlessh SOC-01:22 → "Connection timed out during banner exchange" da MacBook, log ACCEPT/CLOSE in journald ✅
- **T-04:** Rule 100081 level 14 in `alerts.json` con `src_host: 192.168.68.204`, `mail: true` ✅
- **T-04:** Alert Slack `🚨 HONEYPOT SSH — ALTO RISCHIO` ricevuto in `#homesoc-alerts` ✅
- **T-05:** Banner check — SSH: `OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`, FTP: `ProFTPD 1.3.5e`, HTTP: `Apache/2.4.57 (Ubuntu)` ✅

### Notes
- Forward syslog UDP ct-104 → vm-103:514 non implementato: `wazuh-remoted` occupa UDP 514 IPv4, `SysLogHandler` remoto non supportato in OpenCanary 0.9.8. Soluzione: Wazuh agent diretto su ct-104
- TK-02 token PDF sostituito con Word: macOS Preview non attiva il token PDF (non carica risorse remote)
- Config OpenCanary scritta via Python `json.dump()` — heredoc in terminale interattivo (pct enter) corrompe testo > ~20 righe
- Wazuh agent ID 004 aggiunto agli agent monitorati (precedenti: 001 MacBook, 002 SOC-01, 003 ct-102-greenbone)

## [0.8.0] — 2026-05-21

### Added
- `docs/phase3c-consolidation.md` v1.0 — Fase 3c completata: tutti e 6 i task eseguiti e verificati in produzione
- Serial console configurata su vm-103 (`qm set 103 --serial0 socket`) — accesso headless ora disponibile
- QEMU guest agent installato su vm-103 — `qm agent 103 ping` operativo
- Chiave SSH deployata su vm-103 — accesso diretto `ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204` operativo
- Target Greenbone `HomeSOC Critical Assets` (vm-103/SOC-01/ct-102) con scan settimanale venerdì 04:00 Europe/Rome
- FIM esteso a vm-103: path `/var/ossec/etc/rules`, `/var/ossec/etc/decoders`, `/opt/homesoc/scripts` in realtime
- FIM esteso a SOC-01: stessi path + `/etc/pve` (configurazione Proxmox) in realtime
- MITRE ATT&CK tags su tutte le 18 custom rule — copertura 100% (5 rule aggiunte: 100060/61/62/70/71)

### Changed
- `detection-rules/local_rules.xml` v1.3 → v1.5: MITRE tags aggiunti a 100060/100061/100062/100070/100071; rule 100062 riscritta (rimozione `if_sid:23501` non funzionale in Wazuh 4.8+, approccio `decoded_as:json`)
- `/opt/greenbone-to-wazuh.py` su ct-102: campo `port` rinominato `vuln_port` — fix conflitto mapping OpenSearch
- `docs/phase3c-hardening.md` sostituito da `docs/phase3c-consolidation.md` — documento di pianificazione rimpiazzato dal runbook completo

### Fixed
- **OpenSearch mapper_parsing_exception:** il campo `data.port` inviato come stringa `"4430/tcp"` da Greenbone confliggeva con il mapping OpenSearch (atteso oggetto). Rinominato in `data.vuln_port`. Alert rule 100070 ora indicizzati correttamente in `wazuh-alerts-4.x-*`. VIZ-05 dashboard operativa.
- **vm-103 inaccessibile da remoto:** serial console non configurata, QEMU guest agent assente, chiave SSH non deployata. Tutti e tre i meccanismi ora abilitati.

### Verified
- **T-01:** Alert rule 100070 indicizzati in OpenSearch — query `wazuh-alerts-4.x-2026.05.14` restituisce hits con `data.vuln_port`, `data.cve`, `data.cvss`. VIZ-05 `Vulnerability Findings` operativa.
- **T-02:** Target settimanale Greenbone configurato — `HomeSOC Weekly - Critical Assets`, schedule `Weekly SOC Assets` attivo dal 2026-05-22 04:00.
- **T-03:** 366 CVE indicizzate in `wazuh-states-vulnerabilities-*`. Vulnerability scanner operativo. Comportamento Wazuh 4.8+ documentato: risultati non passano per `alerts.json`.
- **T-04:** FIM realtime verificato su vm-103 — alert `syscheck_entry_added` generato in < 30 secondi su `/var/ossec/etc/rules/`.
- **T-05:** SCA su SOC-01 — CIS Debian 13 Benchmark: 79 passed / 107 failed / Score 42% (baseline documentata). SCA MacBook CIS Apple macOS 26.0 Tahoe attivo.
- **T-06:** `grep -c '<mitre>' local_rules.xml` → 18. `wazuh-analysisd -t` → nessun errore.

### Notes
- **Rule 100062 limitazione Wazuh 4.8+:** il vulnerability scanner non genera alert in `alerts.json` — scrive direttamente in `wazuh-states-vulnerabilities-*`. Notifiche Slack per nuovi CVE richiedono OpenSearch alerting (deferred Fase 4+).
- **Filebeat log path:** `/var/log/filebeat/filebeat` (non `/var/ossec/logs/filebeat.log`). Fondamentale per diagnostica indicizzazione OpenSearch.
- **Campo `data.port` riservato:** nel mapping standard Wazuh/OpenSearch `data.port` è mappato come oggetto. Decoder custom devono usare nomi diversi per campi porta (es. `vuln_port`, `nas_port`).
- **SCA baseline SOC-01 42%:** punto di partenza per hardening CIS — non un problema operativo, ma baseline misurabile per Fase 4+.

## [0.7.0] — 2026-04-24

### Added
- `docs/phase3b-hardening.md` v1.2 — Fase 3b completata: tutti e 7 i task eseguiti e verificati in produzione
- `runbooks/greenbone-to-wazuh.py` — Script stdlib-only Python per pipeline Greenbone → Wazuh; eseguito via `docker exec -i` nel container gvmd (socket GVM su tmpfs interno non accessibile dall'host); zero dipendenze esterne
- `/var/ossec/etc/decoders/greenbone-decoder.xml` (vm-103) — Decoder JSON per finding Greenbone
- Rule 100062 in `local_rules.xml` (vm-103) — CVE High/Critical da Vulnerability Detector → Slack
- Rule 100070/100071 in `local_rules.xml` (vm-103) — Finding Greenbone High/Critical → Slack (rinominate da 100050/100051 per conflitto con crowdsec-rules.xml)
- Dashboard `HomeSOC Security Operations` su Wazuh Dashboard (7 visualizzazioni: UC Events, Alert Level, Top IPs, FIM, Vulnerability, Active Response, Log Health)
- Wazuh Agent `ct-102-greenbone` (ID 003) enrollato e Active

### Changed
- `docs/phase3b-hardening.md` v1.1 → v1.2: T-05/T-06/T-07 marcati completati, checklist aggiornata, sezione 12 "Elementi deferred Fase 3c" aggiunta

### Fixed
- **Conflitto Rule ID 100050/100051:** le rule Greenbone originalmente pianificate con questi ID confliggevano con `crowdsec-rules.xml` (che usa 100050/100051 per ban CrowdSec). Rinominate in 100070/100071. Il warning `Rule ID '100050' is duplicated` in wazuh-logtest era il segnale diagnostico.
- **Rule 100071 syntax error:** il regex `^(9|10)\.` per identificare CVSS ≥ 9.0 causa `ERROR: (5107): Syntax error on tag 'cvss'` — l'engine OS_Regex di Wazuh non supporta la stessa sintassi di PCRE. Workaround: rule 100071 usa `<field name="severity">Critical</field>` invece del regex CVSS.
- **`<vulnerability-detector>` deprecato:** blocco aggiunto manualmente in ossec.conf per T-05, ma Wazuh 4.8+ lo ignora con WARNING e usa valori default. Blocco rimosso, modulo già attivo di default.

### Verified
- **T-05:** Wazuh Vulnerability Detector attivo — 25 High + 32 Medium CVE su soc-01 (Debian 13) e MacBook (macOS). Top finding: amd64-microcode, urllib3, pip, setuptools, vim.
- **T-06:** Pipeline end-to-end Greenbone → docker exec → `/var/log/greenbone-findings.log` → Wazuh logcollector (ct-102 agent) → decoder JSON → rule 100070 level 12 → alert Wazuh → notifica Slack `#homesoc-alerts`. Finding reale: **CVE-2016-2183** (SWEET32) su NAS WD My Cloud Home `192.168.68.90:4430/tcp` — cipher suite 3DES, CVSS 7.5 High.
- **T-07:** Dashboard `HomeSOC Security Operations` operativa con dati reali su 6/7 visualizzazioni.

### Notes
- **Cron pipeline Greenbone:** `0 8 * * 1` su ct-102 — esecuzione lunedì 08:00, il giorno dopo la scan Greenbone domenicale 02:00
- **Issue OpenSearch deferred (Fase 3c):** Alert rule 100070 presenti in `alerts.json` e notificati su Slack, ma non indicizzati in `wazuh-alerts-*`. VIZ-05 dashboard vuota. Causa probabile: latenza indexer-connector per agent appena enrollato.
- **Scope copertura Greenbone:** baseline mensile /24 copre tutti gli asset inclusi vm-103/SOC-01/ct-102. Target settimanale per asset critici SOC pianificato per Fase 3c.
- **Finding reale actionable:** CVE-2016-2183 (SWEET32) su NAS porta 4430 — da valutare disabilitazione cipher 3DES nel firmware WD My Cloud Home o accettazione rischio residuo.

## [0.6.0] — 2026-04-23

### Fixed
- `runbooks/crowdsec-deploy.md` v1.2: tre fix Debian 12 verificati in produzione:
  1. **rsyslog ISO 8601 → RFC 3164** — rsyslog su Debian 12 scrive auth.log con timestamp ISO 8601 (`2026-04-23T...`); il parser `crowdsecurity/syslog-logs` lo scarta silenziosamente. Fix: aggiunto `RSYSLOG_TraditionalFileFormat` sulla riga auth.log in `/etc/rsyslog.conf` (riga 60)
  2. **acquis.yaml → acquis.d/ migration** — il separatore `---` multi-documento in acquis.yaml causava comportamento non deterministico; migrato a due file separati in `/etc/crowdsec/acquis.d/` (`auth-log.yaml` + `pveproxy.yaml`), acquis.yaml svuotato
  3. **Parser sshd-session (OpenSSH ≥ 9.x)** — OpenSSH moderno su Debian 12 / Proxmox 8.x usa il processo `sshd-session` per le sessioni; `crowdsecurity/sshd-logs` filtra solo `program == 'sshd'` → tutti gli eventi non raggiungevano lo scenario `ssh-bf`. Fix: parser custom `/etc/crowdsec/parsers/s01-parse/00-sshd-session-fix.yaml` con `onsuccess: continue` che rinomina il campo prima del passaggio a sshd-logs

### Verified
- Pipeline end-to-end confermata: brute force SSH da vm-103 → CrowdSec ban 4h → syslog → Wazuh rule 100051 level 10 → alert Slack #homesoc-alerts
- ~22.500 IP bloccati da blocklist CAPI attiva (ssh:bruteforce, http:scan, http:bruteforce, vm-management:exploit)

### Notes
- Test eseguito con whitelist LAN temporaneamente disabilitata (192.168.0.0/16 commentato in whitelists.yaml); whitelist ripristinata in produzione
- CrowdSec v1.4.6-10+b4-debian · collection crowdsecurity/sshd v0.2 (up-to-date al 23/04/2026)

## [0.5.1] — 2026-04-22

### Fixed
- `runbooks/nas-monitor.sh` v1.1: aggiunto guard su NAS irraggiungibile — se nmap non trova porte aperte lo script logga `event=nas_offline` e termina senza aggiornare la baseline, prevenendo il false positive "tutte le porte appaiono nuove" al ritorno online dopo spegnimento notturno (FP rilevato e triaggiato 2026-04-22)
- `runbooks/wazuh-deploy.md` v1.3: regole UC-04 100030/100031 riscritte per decoder `nas-monitor-fields` (sostituiscono placeholder syslog inattivo della v1.1); aggiunta rule 100032 `nas_offline` level 3 (solo audit trail, nessuna notifica Slack); fix `frequency`/`timeframe` come attributi su rule 100001, 100002, 100011 (stesso pattern del fix v1.1 già applicato a 100041)

### Notes
- FP classificato: NAS WD My Cloud Home spento di notte → baseline azzerata → al riaccensione mattutina tutte le porte baseline appaiono come "nuove" → rule 100030 (L12) triggered erroneamente. Causa root: script aggiornava baseline anche con risultato nmap vuoto. Risolto con guard `[ -z "$CURRENT" ]` prima dell'aggiornamento baseline.
- Rule 100032 (L3) permette audit trail degli spegnimenti NAS in Dashboard senza generare alert Slack
- Nessun impatto su altri UC o componenti

## [0.5.0] — 2026-04-20

### Added
- `wazuh-slack.md` — Runbook v1.0: integrazione Wazuh → Slack, script custom per messaggi contestuali per UC-01/03/04/06 (level ≥ 10), roadmap notifiche future (agent disconnect, Uptime Kuma, Greenbone, CrowdSec)
- `integrations/slack.py` — Script Python custom che sostituisce lo script built-in Wazuh: routing per rule ID, messaggi strutturati con emoji/campi/MITRE tag per ogni use case, fallback generico per rule non mappate

### Changed
- `docs/01-threat-model.md` — Updated to v1.3: risk register aggiornato con stato deploy Fase 3 — R-01 Parziale Mitigato (UC-02 operativo), R-02 Parziale Mitigato (UC-03 FIM + Slack), R-08 Parziale Mitigato (FIM operativo), R-10 Parziale Mitigato (UC-01 SSH brute force + Slack), R-14 nota aggiornata (Wazuh manager operativo, POS enrollment pianificato)

### Notes
- Fase 3 SIEM & Detection: Wazuh operativo (v1.2), integrazione Slack operativa (v1.0), CrowdSec in corso
- Alert Slack attivi: UC-01 (SSH brute force), UC-03 (FIM macOS), UC-04 (NAS port monitor), UC-06 (Rogue device)
- UC-02 (NextDNS beaconing, level 8) sotto il threshold Slack — monitorato solo su Dashboard
- Script `integrations/slack.py` da copiare in `/var/ossec/integrations/slack.py` su vm-103 dopo ogni reinstall

## [0.4.0] — 2026-04-17

### Added
- `proxmox-setup.md` — Runbook v1.0: Proxmox VE setup su SOC-01 (GMKtec M5 Ultra), configurazione base, network bridge, storage pool, snapshot policy
- `homeassistant-deploy.md` — Runbook v1.0: Home Assistant OS su vm-100, integrazione dispositivi LAN (Shelly, Google Nest, robot), DHCP reservation
- `uptimekuma-deploy.md` — Runbook v1.0: Uptime Kuma + Portainer su ct-101, monitoring ICMP/HTTP per tutti gli asset critici (SOC-01, NAS, MacBook, POS, Greenbone, Wazuh)
- `greenbone-deploy.md` — Runbook v1.1: Greenbone Community Edition su ct-102 (LXC privileged, nesting=1 keyctl=1 per Docker), scan periodici LAN, NVT feed sync (30-90 min atteso al primo boot)
- `wazuh-deploy.md` — Runbook v1.2: Wazuh 4.x single-node su vm-103, agent MacBook Pro M1 (END-05), 5 UC custom (UC-01/02/03/04/06), decoder custom, FIM workaround macOS (MD5/diff script), NAS port monitor script

### Notes
- Fase 2 completata: Proxmox, Home Assistant, Uptime Kuma, Greenbone operativi
- Fase 3 avviata: Wazuh operativo con tutti gli UC attivi e testati
- RAM SOC-01 aggiornata a 32 GB (necessario per vm-103 Wazuh Indexer)
- Greenbone LXC: requisito critico — modalità privileged + features nesting=1,keyctl=1 per Docker

## [0.3.0] — 2026-04-11

### Changed
- `docs/01-threat-model.md` — Updated to v1.2: corrected subnet to 192.168.68.0/24 (was .71), added IP/MAC from ARP scan CSV, identified ESP_EF1867 as smart light (Espressif/Tuya), identified PAX Computer as POS hardware (NEG-01/02), split Roborock into two distinct assets (IOT-03a home, IOT-03b shop), updated Shelly model (Plus 2PM Gen3), confirmed Ezviz/Dahua cameras, confirmed Narwal FN-LINK module, identified NEG-03 (android-5edd) as POS mobile, updated risk register: R-06 Mitigato (2FA WD enabled), R-11 Chiuso (ESP identified), R-15 Accettato (Shelly auth), R-16 Mitigato (Google 2FA confirmed), R-17 Parziale (Deco BE65 no DoH yet), added DHCP range note (.51+)
- `docs/02-architecture.md` — Updated to v1.1: corrected subnet to 192.168.68.0/24, updated DHCP reservation IPs (MacBook → .108, NAS → .90, SOC-01 → .200)

### Notes
- All pre-deployment immediate actions from Phase 0/1 now resolved or formally accepted
- DHCP reservations to configure on Deco before Phase 2: NAS (.90), MacBook (.108); SOC-01 (.200) after hardware connection
- DoH on Deco BE65 pending firmware update (beta); R-17 to be re-evaluated on release
- Wisol (AUTO-03) host device still unidentified — lower priority, not blocking Phase 2

## [0.2.0] — 2026-04-11

### Added
- `docs/02-architecture.md` — Architecture design v1.0: network topology (current + target + future OPNsense), logical security architecture (6 defense-in-depth layers), data flow diagram with ports/protocols, Proxmox VM/CT layout (16 GB and 32 GB configurations), 6 detection use cases mapped to MITRE ATT&CK
- `configs/attack-navigator/homesoc-layer-v1.json` — MITRE ATT&CK Navigator layer v1.0: 22 techniques with scoring, comments, and per-technique metadata linked to use cases and risk register

### Changed
- `docs/01-threat-model.md` — Updated to v1.1: corrected Deco models (XE75/XE75 Pro), thermostats → Google Nest Learning 3rd gen, NAS → WD My Cloud Home, added CIA objectives per segment
- `README.md` — Added "Why This Project" section, project status indicator, key documents table, language note, ATT&CK layer instructions

### Notes
- Phase 1 (Architecture Design) completed
- Checklist Fase 1 in `02-architecture.md`: 8/10 items complete — pending draw.io export as PNG
- ATT&CK layer covers 22 techniques across 10 tactics with 3-tier scoring (high/partial/low)

## [0.1.0] — 2026-04-11

### Added
- `docs/00-charter.md` — Project charter v1.0 (scope, objectives, roadmap, stack rationale, architectural decision records)
- `docs/01-threat-model.md` — STRIDE threat model v1.0: asset inventory (47 devices), 10 STRIDE scenarios, risk register (17 risks), CIA objectives per segment
- `README.md` — Project overview, repository structure, roadmap, hardware specs

### Notes
- Phase 0 (Scoping) completed
- Asset inventory sourced from Deco App export (10/04/2026)
- Risks R-05 and R-07 classified as Postponed (insufficient hardware for VLAN)
- R-06 (WD My Cloud Home) open — cloud relay not disableable, mitigation via 2FA on WD account
