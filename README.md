# HomeSOC — Domestic Security Operations Centre

> A progressively deployed, documentation-first home SOC built on low-power hardware.
> Dual objective: real network protection + professional portfolio for a Master's in Cybersecurity.

---

## Overview

**HomeSOC** is a home Security Operations Centre deployed on a GMKtec M5 Ultra mini PC (Ryzen 7 7730U, 32 GB DDR4), running Proxmox VE as the hypervisor.

The project follows a **design-first approach**: every technical decision is preceded by scoping, threat modelling, and architecture on paper — exactly as it would be in a professional SOC context. Every deployment phase is tracked on Git and documented with operational runbooks.

### Scope

| Segment | Assets |
|---|---|
| Home network | Deco BE65 mesh, IoT devices (Dreame, Narwal, Ezviz, Shelly), MacBook Pro M1 Pro |
| Shop network | POS, cash register, NVR — Sesto San Giovanni |
| Future | New home network with OPNsense firewall |

### Security Stack

| Layer | Function | Components |
|---|---|---|
| L1 Prevention | Block known threats | NextDNS (IoC blocking), VLAN segmentation (future) |
| L2 Visibility | Centralised logging | Wazuh SIEM, Uptime Kuma |
| L3 Detection | Alert on anomalies | Wazuh custom rules (MITRE ATT&CK mapped) |
| L4 Response | Case management | TheHive + Cortex, IR playbooks |
| L5 Intelligence | Threat intel correlation | OpenCTI (STIX/TAXII feeds) |
| L6 Offensive Lab | Adversary emulation | Caldera, Infection Monkey |

---

## Repository Structure

```
homesoc/
├── docs/
│   ├── 00-charter.md           # Project charter
│   ├── 01-threat-model.md      # STRIDE threat model + asset inventory + risk register
│   ├── 02-architecture.md      # Logical security architecture + VM layout
│   └── 03-network-diagram.drawio
├── runbooks/                   # Step-by-step deployment guides
├── configs/                    # Versioned configuration files
├── detection-rules/            # Custom Wazuh rules (MITRE ATT&CK)
├── playbooks/                  # Incident response playbooks
├── lab-reports/                # Caldera / Infection Monkey exercise reports
├── CHANGELOG.md
└── README.md
```

---

## Deployment Roadmap

| Phase | Type | Timeline | Description |
|---|---|---|---|
| Phase 0 | Design | Week 1-2 | Scoping, threat model, asset inventory ✅ |
| Phase 1 | Architecture | Week 3 | Network diagram, VM layout, detection use cases |
| Phase 2 | Deploy | Month 1 | Proxmox, Home Assistant, Greenbone, Uptime Kuma |
| Phase 3 | Deploy | Month 2-3 | Wazuh SIEM + agent, MITRE ATT&CK rules, FIM |
| Phase 4 | Deploy | Month 4-5 | TheHive + Cortex, IR playbooks |
| Phase 5 | Intel | Month 6+ | OpenCTI + STIX/TAXII feeds |
| Phase 6 | Offensive | Month 7+ | Caldera, Infection Monkey, Nuclei |

---

## Hardware

| Component | Spec |
|---|---|
| Device | GMKtec M5 Ultra |
| CPU | AMD Ryzen 7 7730U (8C/16T) |
| RAM | 32 GB DDR4 |
| Network | 2× NIC 2.5 GbE |
| TDP | 15W |
| OS | Proxmox VE |

---

## Author

Alessandro · LM Sicurezza Informatica · Università degli Studi di Milano · 2026
