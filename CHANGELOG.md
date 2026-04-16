# Changelog

All notable changes to this project are documented here.
Format: [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)  — `type(scope): description`

---

## [Unreleased]

## [0.4.0] — 2026-04-16

### Added
- `runbooks/wazuh-deploy.md` — Fase 3: deploy Wazuh 4.x single-node su vm-103 (Ubuntu 22.04, 4 vCPU / 6 GB / 64 GB, IP `192.168.68.204`). Comprende: Wazuh Manager + Indexer + Dashboard, enrollment agent macOS (END-05), FIM su home directory MacBook, ingestion log NextDNS via API, script rogue device detection, detection rules custom UC-01/02/03/04/06 mappate su MITRE ATT&CK.
- `runbooks/crowdsec-deploy.md` — Fase 3: deploy CrowdSec direttamente su SOC-01 host Proxmox (`192.168.68.200`). Comprende: agent + cs-firewall-bouncer (nftables), collections ssh-bf/linux/syslog, blocklist Hub globale, pipeline CrowdSec → rsyslog → Wazuh syslog (alert rule 100050-100053), sezione didattica modello agent/LAPI/bouncer vs fail2ban.

### Changed
- `docs/01-threat-model.md` — Aggiornato a v1.3: R-09 e R-10 → stato Mitigato (runbook). Controlli fail2ban → CrowdSec cs-firewall-bouncer in sez. 2.9 e risk register. UC-01 risposta prevista aggiornata.

### Notes
- Fase 3 runbook completati. Deployment effettivo su hardware da eseguire (prerequisito: upgrade RAM SOC-01 a 32 GB per vm-103 Wazuh).
- Criterio di chiusura Fase 3: test brute force SSH → alert rule 100051 visibile in Wazuh Dashboard.
- Decisione architetturale: CrowdSec deployato su SOC-01 anche senza servizi internet-facing — protezione SSH LAN (UC-01) + blocklist globale Hub + preparazione per esposizione futura (reverse proxy, VPN). Rationale documentato in `crowdsec-deploy.md` sez. 1.3.

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
