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
