# Changelog

All notable changes to this project are documented here.
Format: [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)  — `type(scope): description`

---

## [Unreleased]

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
