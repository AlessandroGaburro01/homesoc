# HomeSOC — Domestic Security Operations Centre

> A progressively deployed, documentation-first home SOC built on low-power hardware.
> Dual objective: real network protection + professional portfolio for a Master's in Cybersecurity.

> **Status:** ✅ Phase 0 · ✅ Phase 1 · ✅ Phase 2 · ✅ Phase 3a · ✅ Phase 3b · ✅ Phase 3c · ✅ Phase 3d · ✅ Phase 4 (Incident Response) · ⬜ Phase 5 (Intel) planned

---

## Why This Project

I've always been fascinated by the idea of applying enterprise-grade security practices to real-world environments — even small ones. HomeSOC started from a simple question: *what would it take to run a proper Security Operations Centre for a home network and a family shop?*

The answer turned into this project: a fully documented, incrementally deployed SOC that protects real assets (IoT devices, a MacBook, a POS system) while giving me hands-on experience with the exact tools and methodologies used in professional blue teams. Every phase follows a design-first approach — threat modelling before deployment, architecture before configuration, runbooks before commands.

---

## Overview

**HomeSOC** is a home Security Operations Centre deployed on a GMKtec M5 Ultra mini PC (AMD Ryzen 7 7730U, 8C/16T, 32 GB DDR4), running Proxmox VE as the hypervisor.

### Scope

| Segment | Assets |
|---|---|
| Home network | Deco BE65/XE75 mesh, IoT devices (Dreame, Narwal, Tapo, Arlo, Shelly), MacBook Pro M1 Pro |
| Shop network | POS, cash register, NVR — Sesto San Giovanni (Milan, Italy) |
| Future | New home network with OPNsense firewall and proper VLAN segmentation |

### Security Stack

| Layer | Function | Components |
|---|---|---|
| L1 Prevention | Block known threats | NextDNS (IoC blocking), CrowdSec, VLAN segmentation (future OPNsense) |
| L2 Visibility | Centralised logging | Wazuh SIEM, Uptime Kuma |
| L3 Detection | Alert on anomalies | Wazuh custom rules (MITRE ATT&CK mapped), Greenbone CVE scanner |
| L4 Deception | Adversary trapping | OpenCanary honeypot, Endlessh SSH tarpit, canary tokens |
| L5 Response | Case management | TheHive 5 + Cortex 3, IR playbooks (Phase 4) |
| L6 Intelligence | Threat intel correlation | OpenCTI (STIX/TAXII feeds) (Phase 5) |
| L7 Offensive Lab | Adversary emulation | Caldera, Infection Monkey, Nuclei (Phase 6) |

---

## Repository Structure

```
homesoc/
├── docs/
│   ├── 00-charter.md                  # Project charter — scope, objectives, roadmap, ADRs
│   ├── 01-threat-model.md             # STRIDE threat model, asset inventory (47 devices), risk register
│   ├── 02-architecture.md             # Logical security architecture, VM layout, DFD, detection use cases
│   ├── 03-network-diagram.drawio      # Physical and logical network topology (draw.io)
│   ├── phase3b-hardening.md           # Phase 3b scope, task log, lessons learned
│   ├── phase3c-consolidation.md       # Phase 3c runbook — OpenSearch fix, FIM Linux, SCA, MITRE tags
│   ├── phase3d-deception.md           # Phase 3d runbook — honeypot, tarpit, canary tokens
│   ├── phase4-incident-response.md    # Phase 4 runbook — TheHive 5, Cortex 3, IR playbooks
│   └── advanced-detection-analysis.md # Structural detection limits and extension roadmap
├── configs/
│   └── attack-navigator/
│       └── homesoc-layer-v1.json      # MITRE ATT&CK Navigator layer — 22 techniques mapped
├── integrations/
│   ├── slack_custom.py                # Custom Wazuh → Slack script (contextual messages per UC)
│   └── custom-thehive                 # Custom Wazuh → TheHive 5 script (case + observable creation)
├── runbooks/                          # Step-by-step deployment guides
│   ├── proxmox-setup.md               # Proxmox VE — SOC-01 base setup
│   ├── homeassistant-deploy.md        # Home Assistant OS — vm-100
│   ├── uptimekuma-deploy.md           # Uptime Kuma + Portainer — ct-101
│   ├── greenbone-deploy.md            # Greenbone Community Edition — ct-102
│   ├── wazuh-deploy.md                # Wazuh SIEM + agents + UC custom rules — vm-103
│   ├── wazuh-slack.md                 # Wazuh → Slack integration + custom script
│   ├── crowdsec-deploy.md             # CrowdSec — SOC-01 host
│   ├── backup-offsite.md              # Offsite backup strategy and setup
│   └── shelly-allarme-negozio.md      # Shelly-based shop alarm integration
├── detection-rules/                   # Custom Wazuh rules mapped to MITRE ATT&CK (Phase 3+)
├── playbooks/                         # Incident response playbooks (Phase 4+)
├── lab-reports/                       # Caldera / Infection Monkey exercise reports (Phase 6+)
├── CHANGELOG.md
└── README.md
```

> Runbooks and technical documentation are in Italian (university context — Università degli Studi di Milano). README and CHANGELOG are in English for international portfolio visibility.

---

## Deployment Roadmap

| Phase | Type | Description | Status |
|---|---|---|---|
| Phase 0 | Design | Scoping, threat model, asset inventory, risk register | ✅ Complete |
| Phase 1 | Architecture | Network diagram, VM layout, detection use cases, ATT&CK layer | ✅ Complete |
| Phase 2 | Deploy | Proxmox, Home Assistant, Greenbone, Uptime Kuma | ✅ Complete |
| Phase 3a | SIEM & Detection | Wazuh SIEM, agents, 6 custom UC rules, Slack alerts | ✅ Complete |
| Phase 3b | Hardening | CrowdSec, Active Response, Vulnerability Detector, Greenbone pipeline, dashboard | ✅ Complete |
| Phase 3c | Refinement | OpenSearch indexing fix, FIM Linux, SCA Linux, MITRE tags, Greenbone scan targets | ✅ Complete |
| Phase 3d | Deception Layer | OpenCanary honeypot, Endlessh tarpit, canary tokens | ✅ Complete |
| Phase 4 | Response | TheHive 5 + Cortex 3, Wazuh integration, IR playbooks | ✅ Complete |
| Phase 5 | Intel | OpenCTI + STIX/TAXII feeds | ⬜ Planned |
| Phase 6 | Offensive | Caldera, Infection Monkey, Nuclei | ⬜ Planned |

### Phase 4 — Incident Response checklist

| Task | Component | Status |
|---|---|---|
| T-01 | vm-105 provisioning (Ubuntu 22.04, Wazuh agent ID 005) | ✅ Complete |
| T-02 | TheHive 5.7.2 + Cortex 3.1.8 installed, connected | ✅ Complete |
| T-03 | Wazuh → TheHive integration script, ossec.conf, verified | ✅ Complete |
| T-04 | Cortex analyzers — VirusTotal, AbuseIPDB, Shodan | ✅ Complete |
| T-05 | IR playbooks — PB-01/02/03/04 | ✅ Complete |

### Phase 3 — Detection checklist

#### Phase 3a — SIEM & Detection ✅

| Component | Status |
|---|---|
| Wazuh single-node (Manager + Indexer + Dashboard) | ✅ Operational — vm-103 · 192.168.68.204 |
| Wazuh Agent — MacBook Pro M1 (END-05, ID 001) | ✅ Enrolled and active |
| UC-01 SSH brute force (rule 100001, level 10) | ✅ Operational · Slack alert active |
| UC-02 NextDNS IoT beaconing (rule 100010, level 8) | ✅ Operational · Dashboard only |
| UC-03 FIM macOS (rule 100020/100023, level 12/10) | ✅ Operational · Slack alert active |
| UC-04 NAS port monitor (rule 100030, level 12) | ✅ Operational · Slack alert active |
| UC-06 Rogue device (rule 100040, level 10) | ✅ Operational · Slack alert active |
| Slack integration (wazuh-slack.md) | ✅ Operational · `#homesoc-alerts` |

#### Phase 3b — Hardening ✅

| Component | Status |
|---|---|
| T-01 Log source health monitoring | ✅ Complete |
| T-02 Slack notification tuning | ✅ Complete |
| T-03 Uptime Kuma alerting | ✅ Complete |
| T-04 Wazuh Active Response — SSH brute force (iptables ban) | ✅ Complete |
| T-05 Wazuh Vulnerability Detector | ✅ Complete · 25 High + 32 Medium CVEs detected |
| T-06 Greenbone → Wazuh pipeline | ✅ Complete · CVE-2016-2183 (SWEET32) found on NAS |
| T-07 HomeSOC Security Dashboard (7 visualisations) | ✅ Complete |
| CrowdSec on SOC-01 (3 production bugs fixed) | ✅ Complete · ~22,500 IPs blocked |
| Wazuh Agent — SOC-01 (ID 002) | ✅ Enrolled and active |
| Wazuh Agent — ct-102 Greenbone (ID 003) | ✅ Enrolled and active |

#### Phase 3c — Refinement ✅

| Component | Status |
|---|---|
| Fix Greenbone alerts indexing in OpenSearch `wazuh-alerts-*` | ✅ Complete |
| Verify Vulnerability Detector alerts end-to-end | ✅ Complete · 366 CVE indexed |
| Extend Wazuh FIM to Linux hosts (vm-103, SOC-01) | ✅ Complete |
| Verify SCA on Linux hosts | ✅ Complete · CIS baseline documented |
| Add MITRE ATT&CK tags to all custom rules | ✅ Complete · 18/18 rules tagged |
| Add dedicated weekly Greenbone scan for critical SOC assets | ✅ Complete |

#### Phase 3d — Deception Layer ✅

| Component | Status |
|---|---|
| Canary tokens (Word doc x2, fake AWS creds, DNS token, README) | ✅ Operational · 5 tokens deployed |
| OpenCanary honeypot — ct-104 (`backup-srv`, 192.168.68.206) | ✅ Operational · SSH/FTP/HTTP/Telnet/MySQL |
| Endlessh SSH tarpit — SOC-01:22 (real SSH on :2222) | ✅ Operational |
| Wazuh rules 100080–100085 with MITRE ATT&CK mapping | ✅ Operational · Slack alerts active |

---

## Key Documents

| Document | Description |
|---|---|
| [Project Charter](docs/00-charter.md) | Scope, objectives, roadmap, stack rationale, architectural decision records |
| [Threat Model](docs/01-threat-model.md) | STRIDE analysis, 47-device asset inventory, 17-risk register, CIA objectives per segment |
| [Architecture](docs/02-architecture.md) | Defense-in-depth layers, Proxmox VM layout, data flow diagram, 6 detection use cases |
| [ATT&CK Layer](configs/attack-navigator/homesoc-layer-v1.json) | MITRE ATT&CK Navigator layer — load at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) |
| [Wazuh Deploy](runbooks/wazuh-deploy.md) | Wazuh single-node, agents, 6 UC custom rules, decoders, FIM |
| [Wazuh → Slack](runbooks/wazuh-slack.md) | Slack integration, contextual messages per UC, future notification roadmap |
| [Phase 3b Hardening](docs/phase3b-hardening.md) | CrowdSec, Active Response, Vulnerability Detector, Greenbone pipeline, dashboard |
| [Phase 3d Deception](docs/phase3d-deception.md) | Honeypot, SSH tarpit, canary tokens — design and adversarial rationale |
| [Phase 4 IR](docs/phase4-incident-response.md) | TheHive 5 + Cortex 3, Wazuh integration, 4 IR playbooks |
| [Detection Limits](docs/advanced-detection-analysis.md) | Structural visibility limits, attacker TTPs beyond current detection, extension roadmap |

---

## Hardware

| Component | Spec |
|---|---|
| Device | GMKtec M5 Ultra |
| CPU | AMD Ryzen 7 7730U (8C/16T) |
| RAM | 32 GB DDR4 |
| Network | 2× NIC 2.5 GbE |
| OS | Proxmox VE |

---

## Contributing & Conventions

This is a personal portfolio project — external contributions are not expected.
Conventions are documented here for consistency and transparency.

### Commit messages
- Language: **English**
- Format: [Conventional Commits](https://www.conventionalcommits.org/) — `type(scope): description`
- Examples:
  - `feat(wazuh): add SSH brute force detection rule 100001`
  - `docs(threat-model): update risk register v1.3`
  - `fix(crowdsec): resolve timestamp format incompatibility`

### Documentation language
- Runbooks and technical docs: **English**
- Personal guides (excluded from repo): Italian
- README and CHANGELOG: **English**

> Commit history prior to May 2026 may contain mixed-language messages
> — the standard above applies from that point forward.

---

## Author

**Alessandro** · Laurea Magistrale in Sicurezza Informatica · Università degli Studi di Milano · 2026
