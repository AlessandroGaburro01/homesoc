# 00 — Project Charter
**Progetto:** HomeSOC · Domestic Security Operations Centre
**Versione:** 1.1 — Aprile 2026
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI
**Hardware:** GMKtec M5 Ultra · Ryzen 7 7730U · 16→32 GB DDR4
**OS base:** Proxmox VE (fallback: Debian 12 + Docker)

> Committare con: `git commit -m "docs(charter): update vX.Y — <motivo>"`

**Changelog:**
- v1.0 — Aprile 2026 — Prima stesura
- v1.1 — Aprile 2026 — Allineamento RAM con architettura, threat model rimandato a 01-threat-model.md, correzione modelli Deco

---

## Indice

1. [Executive Summary](#1-executive-summary)
2. [Obiettivi e Scope](#2-obiettivi-e-scope)
3. [Threat Model — Riepilogo](#3-threat-model--riepilogo)
4. [Architettura del Sistema](#4-architettura-del-sistema)
5. [Roadmap di Deployment](#5-roadmap-di-deployment)
6. [Stack Tecnologico — Motivazioni](#6-stack-tecnologico--motivazioni)
7. [Struttura Repository Git](#7-struttura-repository-git)
8. [Checklist Design-First](#8-checklist-design-first)
9. [Decision Log — Scelte Architetturali](#9-decision-log--scelte-architetturali)

---

## 1. Executive Summary

Il progetto **HomeSOC** consiste nella progettazione e nel deployment progressivo di un **Security Operations Centre domestico** su hardware low-power (mini PC GMKtec M5 Ultra). L'obiettivo è duplice: da un lato fornire protezione reale e misurabile per la rete di casa e del negozio; dall'altro costruire un **portfolio tecnico documentato** rilevante per la laurea magistrale in Sicurezza Informatica e per future opportunità professionali nel settore SOC/Blue Team.

Il progetto segue un approccio **design-first**: ogni decisione tecnica è preceduta da scoping, threat modelling e architettura su carta, esattamente come avverrebbe in un contesto professionale. Ogni fase di deployment è tracciata su Git e documentata con runbook operativi.

---

## 2. Obiettivi e Scope

### 2.1 Obiettivi di sicurezza

- **Confidentiality:** prevenire accessi non autorizzati a dati e dispositivi della rete domestica e del negozio.
- **Integrity:** rilevare modifiche non autorizzate a file critici, configurazioni e traffico di rete.
- **Availability:** monitorare uptime di tutti i servizi esposti internamente ed esternamente.
- **Detectability:** implementare use case di detection basati su MITRE ATT&CK e correlare gli alert con threat intelligence esterna.

### 2.2 Obiettivi di portfolio

- **Documentazione professionale:** ogni fase produce artefatti versionati su Git (runbook, config, detection rules).
- **Competenze hands-on:** deployment e operatività di Wazuh, TheHive, OpenCTI, Caldera e Nuclei in ambiente reale.

### 2.3 Scope — In perimetro

- Rete domestica (Deco BE65 master + XE75/XE75 Pro mesh nodes, VLAN segmentate — futuro)
- Rete negozio Sesto San Giovanni
- Dispositivi IoT: Dreame/Narwal vacuum, Tapo/Arlo/Ezviz cameras, Shelly relays, Google Nest
- MacBook Pro M1 Pro (client principale)
- Futura rete casa nuova (fase successiva)

### 2.4 Scope — Fuori perimetro (ora)

- Servizi esposti su Internet — CrowdSec attivabile solo dopo esposizione consapevole
- OPNsense firewall — richiede riprogettazione architettura di rete con casa nuova
- Vaultwarden — non prioritario

---

## 3. Threat Model — Riepilogo

Il threat model completo è documentato in [`docs/01-threat-model.md`](01-threat-model.md) e include: asset inventory (47 device), analisi STRIDE per 10 classi di asset, risk register (17 rischi), e obiettivi CIA per segmento.

### Riepilogo rischi per priorità

| Priorità | N. rischi | Asset principali |
|---|---|---|
| 🔴 ALTO (6+) | 8 | Robot IoT, MacBook, POS/Cassa, NAS, Telecamere |
| 🟡 MEDIO (3-4) | 6 | Server SOC, ESP custom, firmware IoT, log negozio |
| 🟢 BASSO (1-2) | 3 | Shelly, Nest, DNS |

> ℹ️ Il risk register va aggiornato ad ogni nuova fase di deployment e quando vengono aggiunti asset.

---

## 4. Architettura del Sistema

### 4.1 Logical Security Architecture

Lo stack è organizzato in livelli difensivi corrispondenti alle fasi della kill chain e al modello **defense-in-depth**. Il dettaglio completo è in [`docs/02-architecture.md`](02-architecture.md).

| Livello | Layer difensivo | Componenti |
|---|---|---|
| **L1** | Prevenzione | NextDNS (blocco IoC), VLAN segmentate (futuro), Greenbone/OpenVAS (scan), Nuclei (web vuln) |
| **L2** | Visibilità | Wazuh SIEM (log centralizzati, FIM, correlazione), Uptime Kuma (availability) |
| **L3** | Detection | Wazuh custom rules (MITRE ATT&CK mapped), CrowdSec (se servizi esposti) |
| **L4** | Response | TheHive + Cortex (case management + analisi automatizzata), playbook IR documentati |
| **L5** | Intelligence | OpenCTI (feed STIX/TAXII: OTX, Abuse.ch, MITRE), correlazione IoC con Wazuh alerts |
| **L6** | Offensive Lab | Caldera (adversary emulation MITRE ATT&CK), Infection Monkey (breach simulation) |

### 4.2 Proxmox VM/CT Layout

| VM / CT | Tipo | vCPU | RAM | Servizi ospitati |
|---|---|---|---|---|
| vm-100-homeassistant | VM | 2 | 2 GB | Home Assistant OS |
| ct-101-monitoring | LXC CT | 2 | 1 GB | Uptime Kuma, Portainer |
| ct-102-scanner | LXC CT | 4 | 4 GB | Greenbone/OpenVAS, Nuclei |
| vm-103-siem | VM | 4 | 6 GB | Wazuh Manager + Dashboard |
| vm-104-ir | VM | 2 | 4 GB | TheHive + Cortex |
| vm-105-cti | VM | 2 | 4 GB | OpenCTI + feed TAXII |
| vm-106-offlab | VM | 4 | 4 GB | Caldera, Infection Monkey |
| Proxmox host | — | — | 4 GB | OS host, management |
| **TOTALE (32 GB)** | — | **20** | **29 GB** | **3 GB buffer** |

> ⚠️ Con 16 GB (fase iniziale): avviare solo vm-100, ct-101, ct-102. RAM totale ~9 GB — Proxmox host ne richiede ~2, 7 GB liberi. Con 32 GB (upgrade): sbloccare vm-103 (Wazuh) e procedere con le fasi successive.

---

## 5. Roadmap di Deployment

La roadmap segue il principio **incrementale e verificabile**: ogni fase ha prerequisiti espliciti, output documentati e criteri di completamento prima di procedere alla successiva.

| # | Tipo | Durata | Attività | Output | Prerequisito |
|---|---|---|---|---|---|
| **FASE 0** | DESIGN | 1-2 sett. | Scoping, threat model, asset inventory, risk register, repo Git inizializzato | docs/00-charter.md, docs/01-threat-model.md | Nessuno |
| **FASE 1** | ARCH | 1 sett. | Network diagram, Proxmox VM layout, data flow diagram, detection use cases | docs/02-architecture.md, configs/attack-navigator/ | Fase 0 completa |
| **FASE 2** | DEPLOY | Mese 1 | Proxmox VE setup, Home Assistant, Greenbone/OpenVAS, Uptime Kuma, hardening SSH | runbooks/proxmox-setup.md, runbooks/homeassistant-deploy.md | Fase 1 completa, hardware disponibile |
| **FASE 3** | DEPLOY | Mese 2-3 | Wazuh SIEM (manager + agent MacBook), prime detection rules MITRE ATT&CK, FIM | runbooks/wazuh-deploy.md, detection-rules/wazuh-custom/ | Fase 2 OK, 32 GB RAM |
| **FASE 4** | DEPLOY | Mese 4-5 | TheHive + Cortex, integrazione API (VirusTotal, AbuseIPDB, Shodan), playbook IR | runbooks/thehive-deploy.md, playbooks/*.md | Fase 3 OK, Wazuh alert attivi |
| **FASE 5** | INTEL | Mese 6+ | OpenCTI + feed STIX/TAXII (OTX, Abuse.ch, MITRE ATT&CK), correlazione IoC | runbooks/opencti-deploy.md, configs/opencti/feeds.json | Fase 4 OK |
| **FASE 6** | OFFLAB | Mese 7+ | Caldera, Infection Monkey, Nuclei per web app scan | runbooks/caldera-deploy.md, lab-reports/ | Fase 5 OK, VLAN lab isolata |
| **FUTURO** | ARCH+ | Casa nuova | OPNsense firewall, nuova topologia con Fritzbox bridge, VLAN reali | docs/04-future-arch.md | Casa nuova pronta |

---

## 6. Stack Tecnologico — Motivazioni

| Componente | Categoria | Fase deploy | Ruolo | Motivazione scelta |
|---|---|---|---|---|
| **Proxmox VE** | INFRA | Base | Hypervisor VM/CT — isolamento servizi | Snapshot, live migration, ZFS storage, gestione risorse fine-grained |
| **Home Assistant** | DOMOTICA | Mese 1 | Domotica locale, no cloud vendor lock-in | Open, Matter/Thread, integra con Shelly, Eve Thermo, Aqara |
| **Greenbone/OpenVAS** | SCAN | Mese 1 | Vulnerability scanner rete e host | Standard de facto open source, CVE database aggiornato |
| **Uptime Kuma** | MONITOR | Mese 1 | Monitoring availability servizi | Leggero, UI eccellente, alert multicanale, self-hosted |
| **Wazuh** | SIEM | Mese 2-3 | SIEM, FIM, log centralizzati, correlazione | Open source, MITRE ATT&CK integration, agent macOS |
| **CrowdSec** | IPS | Mese 2-3 | Blocco IP malevoli se servizi esposti | Community threat intel, Firewall Bouncer |
| **TheHive + Cortex** | IR | Mese 4-5 | Case management IR + analisi automatizzata | Standard blue team, integrazione Wazuh, API gratuite |
| **OpenCTI** | CTI | Mese 6+ | Threat intelligence, correlazione IoC | Feed STIX/TAXII gratuiti, integrazione MITRE ATT&CK |
| **Caldera** | OFFENSE | Mese 7+ | Adversary emulation MITRE ATT&CK | MITRE project ufficiale, test realistico detection rules |
| **Infection Monkey** | OFFENSE | Mese 7+ | Breach & attack simulation automatizzata | Zero-config per ambienti LAN, complementare a Caldera |
| **Nuclei** | SCAN | Mese 7+ | Web vulnerability scanner (template-based) | Veloce, community templates, audit web app |

---

## 7. Struttura Repository Git

Il repository è il **cuore del portfolio**. Dimostra non solo il risultato finale ma il **processo professionale**: threat model → architettura → deployment → detection → response.

| Percorso | Contenuto |
|---|---|
| docs/00-charter.md | Questo documento (versione markdown versionata) |
| docs/01-threat-model.md | STRIDE threat model, asset inventory, risk register |
| docs/02-architecture.md | Logical security architecture, VM layout, data flow |
| docs/03-network-diagram.drawio | Network diagram topologia fisica e logica (draw.io) |
| configs/attack-navigator/ | MITRE ATT&CK Navigator layer JSON |
| runbooks/ | Un file .md per ogni deployment: passo-passo, comandi, verifica |
| configs/ | File di configurazione versionati (Wazuh, CrowdSec, etc.) |
| detection-rules/ | Custom Wazuh rules mappate su MITRE ATT&CK technique ID |
| playbooks/ | Incident response playbook per scenario |
| lab-reports/ | Report esercizi Caldera/Infection Monkey |
| CHANGELOG.md | Log cronologico di tutte le modifiche |
| README.md | Overview del progetto — faccia pubblica del portfolio |

---

## 8. Checklist Design-First

Questa checklist va completata **prima di qualsiasi attività di deployment**. Ogni voce deve essere verificata e il documento corrispondente deve essere committato su Git.

### 8.1 Fase 0 — Scoping

- [ ] Asset inventory completato (lista tutti i device con IP, OS, ruolo)
- [ ] Threat model STRIDE redatto e versionato in docs/01-threat-model.md
- [ ] Risk register compilato (asset × minaccia × P × I × controllo)
- [ ] Obiettivi CIA definiti per segmento (casa, negozio, IoT, server)
- [ ] Repository Git inizializzato con struttura directory

### 8.2 Fase 1 — Architecture Design

- [ ] Network diagram topologia attuale disegnato (draw.io/Excalidraw)
- [ ] Network diagram topologia target con server integrato
- [ ] Logical security architecture (kill chain layers → componenti)
- [ ] Data flow diagram (chi parla con chi, porte, protocolli)
- [ ] Proxmox VM/CT layout definitivo (vCPU, RAM, servizi per VM)
- [ ] Detection use cases prioritizzati (almeno 5 scenari MITRE ATT&CK)

### 8.3 Prima di ogni deployment (Fasi 2-6)

- [ ] Runbook scritto PRIMA di eseguire (non dopo)
- [ ] Snapshot Proxmox creato prima di ogni modifica significativa
- [ ] Criterio di completamento definito (come verifico che funziona?)
- [ ] Configurazioni committate su Git dopo deployment confermato
- [ ] CHANGELOG.md aggiornato con data e descrizione intervento

> ✔ Il documento va versionato come docs/00-charter.md nel repository Git. Aggiornare il numero di versione (v1.x) ad ogni modifica significativa di scope o architettura. Il README.md del repo deve linkare a questo documento come punto d'ingresso del portfolio.

---

## 9. Decision Log — Scelte Architetturali

Registro delle decisioni significative con motivazione — utile per portfolio.

| ID | Decisione | Motivazione | Alternative scartate |
|---|---|---|---|
| ADR-01 | Proxmox VE vs Debian+Docker | Isolamento VM, snapshot, gestione risorse fine-grained | Debian+Docker: meno overhead ma nessun isolamento VM |
| ADR-02 | Wazuh vs ELK stack puro | Wazuh include FIM, agent macOS, MITRE mapping out-of-the-box | ELK: più flessibile ma richiede config manuale di tutto |
| ADR-03 | GMKtec M5 Ultra vs ASUS F556U | 8C/16T vs 2C/4T, 2x NIC 2.5GbE, TDP 15W | ASUS: già disponibile ma CPU troppo limitata per Wazuh+TheHive |
| ADR-04 | NextDNS vs AdGuard Home locale | NextDNS già configurato, DoH, non dipende dall'uptime del server | AdGuard: più controllo ma aggiunge dipendenza dal server HomeSOC |
| ADR-05 | OPNsense rimandato | Richiede Fritzbox in bridge e nuova topologia — ok con casa nuova | Attivazione ora: troppo impatto su rete attiva del negozio |
| ADR-06 | TheHive 5 vs DFIR-IRIS | TheHive: community più ampia, integrazione Cortex matura, documentazione estesa | DFIR-IRIS: più leggero, UI moderna, ma community più piccola e meno integrazioni pronte |

---

*File: `docs/00-charter.md` · v1.1 · Aprile 2026*
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
