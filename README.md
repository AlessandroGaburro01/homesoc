# HomeSOC — Domestic Security Operations Centre

> A progressively deployed, documentation-first home SOC built on low-power hardware.
> Dual objective: real network protection + professional portfolio for a Master's in Cybersecurity.

> **Status:** ✅ Phase 0 (Scoping) complete · ✅ Phase 1 (Architecture) complete · ✅ Phase 2 (Deploy) complete · 🔄 Phase 3 (SIEM & Detection) in progress

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
| L1 Prevention | Block known threats | NextDNS (IoC blocking), VLAN segmentation (future OPNsense) |
| L2 Visibility | Centralised logging | Wazuh SIEM, Uptime Kuma |
| L3 Detection | Alert on anomalies | Wazuh custom rules (MITRE ATT&CK mapped), CrowdSec |
| L4 Response | Case management | TheHive + Cortex, IR playbooks |
| L5 Intelligence | Threat intel correlation | OpenCTI (STIX/TAXII feeds) |
| L6 Offensive Lab | Adversary emulation | Caldera, Infection Monkey, Nuclei |

---

## Repository Structure

```
homesoc/
├── docs/
│   ├── 00-charter.md              # Project charter — scope, objectives, roadmap, ADRs
│   ├── 01-threat-model.md         # STRIDE threat model, asset inventory (47 devices), risk register
│   ├── 02-architecture.md         # Logical security architecture, VM layout, DFD, detection use cases
│   └── 03-network-diagram.drawio  # Physical and logical network topology (draw.io)
├── configs/
│   └── attack-navigator/
│       └── homesoc-layer-v1.json  # MITRE ATT&CK Navigator layer — 22 techniques mapped
├── integrations/
│   └── slack.py                   # Custom Wazuh → Slack script (messaggi contestuali per UC)
├── runbooks/                      # Step-by-step deployment guides
│   ├── proxmox-setup.md           # Proxmox VE — SOC-01 base setup
│   ├── homeassistant-deploy.md    # Home Assistant OS — vm-100
│   ├── uptimekuma-deploy.md       # Uptime Kuma + Portainer — ct-101
│   ├── greenbone-deploy.md        # Greenbone Community Edition — ct-102
│   ├── wazuh-deploy.md            # Wazuh SIEM + agent + UC custom rules — vm-103
│   ├── wazuh-slack.md             # Wazuh → Slack integration + script custom
│   └── crowdsec-deploy.md         # CrowdSec — SOC-01 host (in progress)
├── detection-rules/               # Custom Wazuh rules mapped to MITRE ATT&CK (Phase 3+)
├── playbooks/                     # Incident response playbooks (Phase 4+)
├── lab-reports/                   # Caldera / Infection Monkey exercise reports (Phase 6+)
├── CHANGELOG.md
└── README.md
```

> Documentation is in Italian (university context — Università degli Studi di Milano). README and CHANGELOG are in English for international portfolio visibility.

---

## Deployment Roadmap

| Phase | Type | Timeline | Description | Status |
|---|---|---|---|---|
| Phase 0 | Design | Week 1-2 | Scoping, threat model, asset inventory, risk register | ✅ Complete |
| Phase 1 | Architecture | Week 3 | Network diagram, VM layout, detection use cases, ATT&CK layer | ✅ Complete |
| Phase 2 | Deploy | Month 1 | Proxmox, Home Assistant, Greenbone, Uptime Kuma | ✅ Complete |
| Phase 3 | Deploy | Month 2-3 | Wazuh SIEM + agent, MITRE ATT&CK rules, FIM, Slack alerts, CrowdSec | 🔄 In progress |
| Phase 4 | Deploy | Month 4-5 | TheHive + Cortex, IR playbooks | ⬜ |
| Phase 5 | Intel | Month 6+ | OpenCTI + STIX/TAXII feeds | ⬜ |
| Phase 6 | Offensive | Month 7+ | Caldera, Infection Monkey, Nuclei | ⬜ |

### Phase 3 — Detection checklist

| Component | Status |
|---|---|
| Wazuh single-node (Manager + Indexer + Dashboard) | ✅ Operativo — vm-103 · 192.168.68.204 |
| Wazuh Agent — MacBook Pro M1 (END-05) | ✅ Enrollato e attivo |
| UC-01 SSH brute force (rule 100001, level 10) | ✅ Operativo · alert Slack attivo |
| UC-02 NextDNS IoT beaconing (rule 100010, level 8) | ✅ Operativo · solo Dashboard |
| UC-03 FIM macOS (rule 100020/100023, level 12/10) | ✅ Operativo · alert Slack attivo |
| UC-04 NAS port monitor (rule 100030, level 12) | ✅ Operativo · alert Slack attivo |
| UC-06 Rogue device (rule 100040, level 10) | ✅ Operativo · alert Slack attivo |
| Slack integration (wazuh-slack.md) | ✅ Operativo · canale #homesoc-alerts |
| CrowdSec su SOC-01 | 🔄 In corso |

---

## Key Documents

| Document | Description |
|---|---|
| [Project Charter](docs/00-charter.md) | Scope, objectives, roadmap, stack rationale, architectural decision records |
| [Threat Model](docs/01-threat-model.md) | STRIDE analysis, 47-device asset inventory, 17-risk register, CIA objectives per segment |
| [Architecture](docs/02-architecture.md) | Defense-in-depth layers, Proxmox VM layout, data flow diagram, 6 detection use cases |
| [ATT&CK Layer](configs/attack-navigator/homesoc-layer-v1.json) | MITRE ATT&CK Navigator layer — load in [navigator.io](https://mitre-attack.github.io/attack-navigator/) |
| [Proxmox Setup](runbooks/proxmox-setup.md) | SOC-01 base setup, VM/CT layout, storage, network bridge |
| [Wazuh Deploy](runbooks/wazuh-deploy.md) | Wazuh single-node, agent macOS, 5 UC custom rules, decoders, FIM |
| [Wazuh → Slack](runbooks/wazuh-slack.md) | Slack integration, messaggi contestuali per UC, roadmap notifiche future |

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

## Author

**Alessandro** · Laurea Magistrale in Sicurezza Informatica · Università degli Studi di Milano · 2026
