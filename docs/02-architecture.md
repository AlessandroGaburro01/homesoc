# 02 — Architecture Design
**Progetto:** HomeSOC · Domestic Security Operations Centre
**Versione:** 1.2 — Maggio 2026
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI
**Prerequisito:** Fase 0 completata — docs/00-charter.md, docs/01-threat-model.md

> Committare con: `git commit -m "docs(architecture): update v1.2 — phase4 vm-105 provisioned, layout updated"`

**Changelog:**
- v1.0 — Aprile 2026 — Prima stesura Fase 1
- v1.1 — Aprile 2026 — Correzione subnet 192.168.68.0/24 (era .71), IP DHCP reservation reali (MacBook .108, NAS .90, SOC-01 .200)
- v1.2 — Maggio 2026 — Fase 4: vm-105 (vm-ir) deployata IP .205; ID Proxmox 104 occupato da ct-104 (OpenCanary) → vm-ir usa ID 105; tabella porte aggiornata con IP reali; ADR-04-02 deviazione nota (LocalDB via .deb manuale, non script StrangeBee)

---

## Indice

1. [Topologia di Rete Attuale](#1-topologia-di-rete-attuale)
2. [Topologia Target con HomeSOC](#2-topologia-target-con-homesoc)
3. [Logical Security Architecture](#3-logical-security-architecture)
4. [Data Flow Diagram](#4-data-flow-diagram)
5. [Proxmox VM/CT Layout Definitivo](#5-proxmox-vmct-layout-definitivo)
6. [Detection Use Cases — MITRE ATT&CK](#6-detection-use-cases--mitre-attck)

---

## 1. Topologia di Rete Attuale

### 1.1 Descrizione

La rete attuale è organizzata su un'unica subnet flat (`192.168.68.0/24`) con due SSID distinti (LAN-MAIN e IoT-SSID) ma **nessun isolamento reale** tra segmenti. Non sono presenti VLAN, switch managed o firewall layer 3.

```
Internet
    │
    ▼
[Zyxel Windinfostrada] — Modem bridge, fibra
    │ (PPPoE → Deco)
    ▼
[Deco BE65 — Salotto] — Gateway NAT, 192.168.68.1
    ├── Wireless backhaul / Ethernet backhaul
    │   ├── [Deco XE75 Pro — Camera Nicole]   192.168.68.250
    │   ├── [Deco XE75 — Cucina]              192.168.68.247
    │   ├── [Deco XE75 Pro — Camera Ale]      TBD
    │   └── [Deco XE75 Pro — Negozio]         TBD (Sesto San Giovanni)
    │
    └── [Nighthawk S8000] — Switch unmanaged (Ethernet)
        └── Device cablati su LAN-MAIN

LAN-MAIN (192.168.68.0/24):
  MacBook Pro M1 Pro, iPad/iPhone, NAS WD My Cloud Home,
  Google Home/Nest, Samsung TV, Xbox, Samsung AC,
  Google Nest Hub, sistema audio

IoT-SSID (192.168.68.0/24 — stessa subnet):
  Robot Dreame/Narwal, Telecamere Tapo/Arlo/Ezviz,
  Shelly relay, Samsung SmartThings, ESP_EF1867

Negozio (nodo Deco separato geograficamente):
  Cassa (NEG-01), POS (NEG-02), NVR, Robot Roborock
```

### 1.2 Criticità topologia attuale

| Criticità | Impatto | Correlazione threat model |
|---|---|---|
| Flat network — nessuna VLAN | IoT può raggiungere POS e MacBook liberamente | R-05 — Lateral Movement |
| Switch unmanaged | Nessun port isolation, nessun traffico filtering | R-03, R-04 |
| IoT-SSID su stessa subnet | Isolamento solo L2, non L3 | R-01, R-07 |
| IP DHCP per tutti i device | Asset inventory incompleto, IP instabili | tutti |
| Nessun firewall interno | Nessun controllo east-west traffic | R-05 |

---

## 2. Topologia Target con HomeSOC

### 2.1 Modifiche immediate (Fase 2 — senza OPNsense)

Con l'hardware attuale non è possibile implementare VLAN reali. Le modifiche immediate si concentrano su:

- **Aggiunta SOC-01** (GMKtec M5 Ultra) con IP statico nella subnet esistente
- **IP statici** per asset critici: MacBook (END-05), NAS (NAS-01), SOC-01
- **Wazuh agents** su MacBook — comunicazione verso SOC-01 (porta 1514/tcp, 1515/tcp)
- **Uptime Kuma** — probe ICMP/HTTP verso tutti gli asset monitorati
- **Greenbone** — scan periodici dalla ct-102 verso tutti i segmenti

```
Internet
    │
    ▼
[Zyxel Windinfostrada] — Modem bridge
    │
    ▼
[Deco BE65] — Gateway NAT, 192.168.68.1
    │
    ├── [Nighthawk S8000] — Switch unmanaged
    │   ├── MacBook Pro M1 Pro     → DHCP reservation 192.168.68.108 (MAC C6:A3:2A:A3:A8:0F)
    │   ├── NAS WD My Cloud Home   → DHCP reservation 192.168.68.90  (MAC 00:00:C0:44:A4:97)
    │   └── SOC-01 (HomeSOC)       → DHCP reservation 192.168.68.200 (MAC da leggere dopo collegamento)
    │         ├── vm-100 Home Assistant
    │         ├── ct-101 Uptime Kuma + Portainer
    │         ├── ct-102 Greenbone/OpenVAS + Nuclei
    │         ├── vm-103 Wazuh Manager + Dashboard
    │         ├── vm-104 TheHive + Cortex
    │         ├── vm-105 OpenCTI
    │         └── vm-106 Caldera + Infection Monkey
    │
    └── [Deco mesh nodes] — Wireless
        ├── Device IoT (DHCP — monitorati via Wazuh/NextDNS)
        └── Device utente (DHCP)
```

### 2.2 Topologia futura (Fase FUTURO — casa nuova + OPNsense)

```
Internet
    │
    ▼
[Zyxel/Fritzbox bridge] — Modem
    │
    ▼
[OPNsense Firewall] — Firewall/Router con VLAN tagging
    ├── VLAN 10 — LAN-MAIN   (192.168.10.0/24) — Endpoint utente
    ├── VLAN 20 — IOT        (192.168.20.0/24) — Robot, telecamere, automazione
    ├── VLAN 30 — SOC        (192.168.30.0/24) — Server HomeSOC isolato
    ├── VLAN 40 — NEGOZIO    (192.168.40.0/24) — POS, cassa (VPN site-to-site)
    └── VLAN 99 — MGMT       (192.168.99.0/24) — Accesso management only
```

---

## 3. Logical Security Architecture

Lo stack difensivo segue il modello **defense-in-depth** organizzato in 6 livelli, mappati sulla kill chain MITRE ATT&CK.

| Layer | Livello | Componente | Funzione | Fase deploy |
|---|---|---|---|---|
| **L1** | Prevenzione | NextDNS (DoH + blocklist) | Blocco IoC DNS, prevenzione C2 via DNS | Immediato |
| **L1** | Prevenzione | VLAN + OPNsense | Segmentazione east-west (futuro) | Futuro |
| **L1** | Prevenzione | Greenbone/OpenVAS | Vulnerability scan proattivo rete e host | Fase 2 |
| **L2** | Visibilità | Wazuh SIEM | Log centralizzati, FIM, correlazione eventi | Fase 3 |
| **L2** | Visibilità | Uptime Kuma | Monitoring availability servizi e asset | Fase 2 |
| **L3** | Detection | Wazuh custom rules | Detection MITRE ATT&CK mapped | Fase 3 |
| **L3** | Detection | CrowdSec | Blocco IP malevoli (se servizi esposti) | Fase 3 |
| **L4** | Response | TheHive + Cortex | Case management IR, analisi automatizzata | Fase 4 |
| **L4** | Response | Playbook IR | Procedure documentate per scenario | Fase 4 |
| **L5** | Intelligence | OpenCTI | Feed STIX/TAXII, correlazione IoC | Fase 5 |
| **L5** | Intelligence | VirusTotal / AbuseIPDB | Arricchimento alert (API) | Fase 4 |
| **L6** | Offensive Lab | Caldera | Adversary emulation MITRE ATT&CK | Fase 6 |
| **L6** | Offensive Lab | Infection Monkey | Breach & attack simulation | Fase 6 |
| **L6** | Offensive Lab | Nuclei | Web vulnerability scanner | Fase 6 |

### 3.1 Copertura MITRE ATT&CK per fase

| Tattica ATT&CK | Fase 2 | Fase 3 | Fase 4 | Fase 5 | Fase 6 |
|---|---|---|---|---|---|
| Initial Access | Greenbone | Wazuh | TheHive | OpenCTI | Caldera |
| Execution | — | Wazuh FIM | — | — | Caldera |
| Persistence | — | Wazuh rules | — | — | Caldera |
| Privilege Escalation | — | Wazuh rules | — | — | Caldera |
| Defense Evasion | — | Wazuh | — | — | Caldera |
| Discovery | Greenbone | — | — | — | Monkey |
| Lateral Movement | — | Wazuh | TheHive | — | Monkey |
| Collection | — | Wazuh FIM | — | OpenCTI | — |
| Exfiltration | NextDNS | Wazuh | — | OpenCTI | — |
| Command & Control | NextDNS | Wazuh | Cortex | OpenCTI | Caldera |

---

## 4. Data Flow Diagram

### 4.1 Flussi principali — Fase 2-3 (con Wazuh attivo)

```
┌─────────────────────────────────────────────────────────────────────┐
│                     LAN 192.168.68.0/24                             │
│                                                                     │
│  [MacBook Pro M1]                                                   │
│      │                                                              │
│      │ Wazuh agent → Manager (TCP 1514 encrypted)                  │
│      │ ossec-authd → Manager (TCP 1515, enrollment)                 │
│      ▼                                                              │
│  [SOC-01 — vm-103 Wazuh Manager]  192.168.68.200                   │
│      │                                                              │
│      ├── Dashboard HTTP/S (TCP 443/5601 — solo LAN)                │
│      ├── Wazuh API (TCP 55000 — solo LAN)                          │
│      ├── Syslog in (UDP 514 / TCP 601)                             │
│      │                                                              │
│      ├── → TheHive (TCP 9000) — alert → case auto                  │
│      ├── → Cortex (TCP 9001) — analisi automatizzata               │
│      └── → OpenCTI (TCP 4000) — correlazione IoC                   │
│                                                                     │
│  [ct-102 Greenbone]                                                 │
│      └── Scan ICMP/TCP/UDP → tutti gli host LAN (scheduled)        │
│                                                                     │
│  [ct-101 Uptime Kuma]                                              │
│      └── Probe ICMP/HTTP → asset monitorati (ogni 60s)             │
│                                                                     │
│  [Device IoT / DHCP]                                               │
│      └── DNS queries → NextDNS (DoH → 1.1.1.1 con filtri)         │
│                                                                     │
│  [NAS WD My Cloud Home]                                            │
│      └── → Cloud WD (relay sempre attivo — non disabilitabile)     │
│      └── → Wazuh syslog (futuro — se supportato)                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 Tabella porte e protocolli

| Flusso | Origine | Destinazione | Porta | Protocollo | Note |
|---|---|---|---|---|---|
| Agent → Manager | MacBook (END-05) | SOC-01:vm-103 | 1514/tcp | TLS | Dati eventi Wazuh |
| Enrollment | MacBook (END-05) | SOC-01:vm-103 | 1515/tcp | TLS | Registrazione agent |
| Syslog | Device rete | SOC-01:vm-103 | 514/udp | Syslog | Log router/switch |
| Dashboard | Admin | SOC-01:vm-103 | 443/tcp | HTTPS | Solo LAN |
| Wazuh API | TheHive/Cortex | SOC-01:vm-103 | 55000/tcp | HTTPS | Integrazione IR |
| Case creation | vm-103 Wazuh | vm-105 TheHive | 9000/tcp | HTTP | Alert → case |
| Enrichment | vm-105 Cortex | Internet | 443/tcp | HTTPS | VirusTotal, AbuseIPDB |
| CTI | vm-106 OpenCTI | Internet | 443/tcp | HTTPS | Feed STIX/TAXII |
| Scan | ct-102 Greenbone | LAN hosts | vari | TCP/UDP/ICMP | Scheduled weekly |
| Probe | ct-101 Uptime Kuma | Asset LAN | 80/443/ICMP | HTTP/PING | Every 60s |
| DNS | Tutti i client | NextDNS | 443/tcp | DoH | Via Deco DNS config |
| Remote admin | Admin | SOC-01 | 22/tcp | SSH (key-only) | Solo LAN o Tailscale |
| Remote access | Admin | SOC-01 | — | Tailscale WireGuard | Accesso remoto sicuro |

### 4.3 Flussi di dati sensibili — da proteggere

| Flusso | Rischio | Mitigazione |
|---|---|---|
| IoT → Cloud cinese (Dreame/Narwal) | Esfiltrazione dati mappatura | NextDNS blocco, VLAN futuro |
| NAS → Cloud WD | Account compromise → accesso remoto | 2FA obbligatorio |
| POS → Acquirer (internet) | Intercettazione dati carte | TLS enforced, Greenbone scan |
| MacBook → Wazuh | Dati FIM e log sensibili | TLS 1.3 tra agent e manager |
| Cortex → VirusTotal | Hash file potenzialmente riservati | Configurare privacy mode API |

---

## 5. Proxmox VM/CT Layout Definitivo

### 5.1 Layout completo (32 GB RAM — target)

| ID | Nome | Tipo | vCPU | RAM | Storage | Rete | Servizi | Fase | Stato |
|---|---|---|---|---|---|---|---|---|---|
| 100 | vm-homeassistant | VM | 2 | 2 GB | 32 GB | vmbr0 (LAN) | Home Assistant OS | 2 | ✅ |
| 101 | ct-monitoring | LXC | 2 | 1 GB | 16 GB | vmbr0 (LAN) | Uptime Kuma, Portainer | 2 | ✅ |
| 102 | ct-scanner | LXC | 4 | 4 GB | 32 GB | vmbr0 (LAN) | Greenbone/OpenVAS, Nuclei | 2 | ✅ |
| 103 | vm-siem | VM | 4 | 6 GB | 64 GB | vmbr0 (LAN) | Wazuh Manager + Dashboard | 3 | ✅ |
| 104 | ct-opencanary | LXC | 1 | 1 GB | 8 GB | vmbr0 (LAN) | OpenCanary honeypot | 3d | ✅ |
| 105 | vm-ir | VM | 2 | 4 GB | 32 GB | vmbr0 (LAN) | TheHive 5 + Cortex 3 | 4 | 🔄 T-02 in corso |
| 106 | vm-cti | VM | 2 | 4 GB | 48 GB | vmbr0 (LAN) | OpenCTI + connettori | 5 | ⬜ |
| 107 | vm-offlab | VM | 4 | 4 GB | 32 GB | vmbr1 (isolata) | Caldera, Infection Monkey | 6 | ⬜ |
| — | Proxmox host | — | — | 4 GB | — | — | OS host, mgmt | sempre | ✅ |
| — | **TOTALE** | — | **21** | **30 GB** | **264 GB** | — | **2 GB buffer** | — | — |

> **Nota Fase 4 — ADR-04-02 deviazione:** vm-105 usa Proxmox ID 105 (non 104) perché ct-104 è occupato da OpenCanary. TheHive 5.7.2 installato via .deb manuale (`thehive.download.strangebee.com`) con LocalDB/BerkeleyDB — lo script automatico StrangeBee installa Cassandra+Elasticsearch (stack troppo pesante per 4 GB RAM); la configurazione manuale con LocalDB è fedele all'ADR originale.

### 5.2 Layout fase iniziale (16 GB RAM — pre-upgrade)

> ⚠️ Avviare **solo** le VM/CT seguenti finché la RAM non è portata a 32 GB.

| ID | Nome | vCPU | RAM | Servizi |
|---|---|---|---|---|
| 100 | vm-homeassistant | 2 | 2 GB | Home Assistant OS |
| 101 | ct-monitoring | 2 | 1 GB | Uptime Kuma, Portainer |
| 102 | ct-scanner | 4 | 4 GB | Greenbone/OpenVAS |
| — | Proxmox host | — | 2 GB | OS host |
| — | **TOTALE** | **8** | **9 GB** | **7 GB liberi** |

### 5.3 Specifiche storage Proxmox

| Pool | Tipo | Dimensione stimata | Contenuto |
|---|---|---|---|
| local-lvm | LVM-thin | 128 GB | Dischi VM OS |
| local | dir | 32 GB | ISO, backup CT |
| ZFS pool (opzionale) | ZFS mirror | — | Snapshot automatici, deduplica |

> **Raccomandazione:** configurare snapshot automatici Proxmox per ogni VM — minimo giornaliero con retention 7 giorni.

### 5.4 Network bridge Proxmox

| Bridge | VLAN aware | Collegamento | Uso |
|---|---|---|---|
| vmbr0 | No (ora) / Sì (futuro) | NIC1 (2.5GbE) → LAN | LAN principale, tutte le VM produzione |
| vmbr1 | No | NIC2 (2.5GbE) — isolata | Lab offensivo vm-106 — nessun accesso LAN |

> **Nota:** vmbr1 è fisicamente disconnessa dalla LAN per garantire isolamento del lab offensivo (Caldera/Infection Monkey). Connettività internet per update tramite NAT controllato su vmbr0 solo in fase di setup.

---

## 6. Detection Use Cases — MITRE ATT&CK

I seguenti use case sono i **5 scenari prioritari** da implementare in Fase 3 (Wazuh). Ogni use case include: scenario, tecnica ATT&CK, sorgente dati, logica di detection, e azione di risposta prevista.

---

### UC-01 — Brute Force SSH sul Server HomeSOC

| Campo | Dettaglio |
|---|---|
| **Scenario** | Attore esterno o device compromesso tenta accesso SSH al server SOC-01 tramite password guessing |
| **ATT&CK Technique** | T1110.001 — Brute Force: Password Guessing |
| **Tattica** | Credential Access |
| **Sorgente dati** | Log SSH `/var/log/auth.log` su SOC-01 → Wazuh agent |
| **Trigger** | ≥5 tentativi di login falliti in 60 secondi dallo stesso IP |
| **Regola Wazuh** | Rule ID 5720 (built-in) + custom rule alert livello 10 |
| **Risposta prevista** | Alert TheHive → playbook "SSH Brute Force" → blocco IP via fail2ban automatico |
| **Asset** | SOC-01 (R-10) |
| **Priorità** | Alta |

**Pseudocodice regola Wazuh:**
```xml
<rule id="100001" level="10">
  <if_matched_sid>5720</if_matched_sid>
  <same_source_ip />
  <timeframe>60</timeframe>
  <frequency>5</frequency>
  <description>Brute force SSH su HomeSOC — blocco fail2ban</description>
  <mitre><id>T1110.001</id></mitre>
  <group>authentication_failures,brute_force,</group>
</rule>
```

---

### UC-02 — Beaconing IoT verso IP Sospetti (C2)

| Campo | Dettaglio |
|---|---|
| **Scenario** | Robot Dreame/Narwal o altro device IoT instaura connessioni periodiche verso IP cinesi (Baidu/Alibaba) o C2 non in whitelist |
| **ATT&CK Technique** | T1071.001 — Application Layer Protocol: Web Protocols |
| **Tattica** | Command and Control |
| **Sorgente dati** | NextDNS query log (esportabili via API) → Wazuh, DHCP lease Deco |
| **Trigger** | Query DNS verso domini non in whitelist vendor IoT, frequenza >20/min da singolo host |
| **Regola Wazuh** | Custom rule su log NextDNS + alert se IP destinazione in feed OpenCTI |
| **Risposta prevista** | Alert + blocco DNS domain in NextDNS dashboard |
| **Asset** | IOT-01, IOT-02 (R-01) |
| **Priorità** | Alta |

**Indicatori di beaconing:**
- Connessioni periodiche con jitter costante (es. ogni 30s ± 2s)
- Volume dati basso costante (15 kbps down / 6 kbps up)
- IP destinazione in ASN cinesi (Baidu: AS23724, Alibaba: AS45102)

**Fonte indicatori:** analisi NextDNS query log (dashboard analytics) + whois/ASN lookup su IP destinazione osservati durante utilizzo normale dei robot vacuum.

---

### UC-03 — File Integrity Monitoring MacBook Pro

| Campo | Dettaglio |
|---|---|
| **Scenario** | Malware su MacBook modifica file critici di sistema, configurazioni SSH, o script in home directory |
| **ATT&CK Technique** | T1565.001 — Data Manipulation: Stored Data Manipulation |
| **Tattica** | Impact / Persistence |
| **Sorgente dati** | Wazuh FIM agent su macOS (END-05) |
| **Percorsi monitorati** | `/Users/alessandro/`, `/etc/`, `/Library/LaunchAgents/`, `/Library/LaunchDaemons/`, `~/.ssh/` |
| **Trigger** | Creazione/modifica/cancellazione file in percorsi sensibili da processo non whitelistato |
| **Regola Wazuh** | Rule ID 550/553/554 (built-in FIM) + custom per LaunchAgents |
| **Risposta prevista** | Alert TheHive → playbook "Endpoint Compromise" → isolamento manuale se confermato |
| **Asset** | END-05 (R-02, R-08) |
| **Priorità** | Alta |

**Configurazione FIM Wazuh (ossec.conf su macOS agent):**
```xml
<syscheck>
  <directories check_all="yes" report_changes="yes" realtime="yes">
    /Users/alessandro
  </directories>
  <directories check_all="yes">/Library/LaunchAgents</directories>
  <directories check_all="yes">/Library/LaunchDaemons</directories>
  <directories check_all="yes">/etc</directories>
</syscheck>
```

---

### UC-04 — Accesso Non Autorizzato NAS WD My Cloud Home

| Campo | Dettaglio |
|---|---|
| **Scenario** | Account WD compromesso → accesso remoto al NAS da IP sconosciuto, oppure tentativo di accesso SMB sulla LAN da host inatteso |
| **ATT&CK Technique** | T1078 — Valid Accounts |
| **Tattica** | Initial Access / Persistence |
| **Sorgente dati** | Log SMB rete (Wazuh sniffer) + alert NextDNS su domini WD cloud + Uptime Kuma anomalie |
| **Trigger** | Connessione SMB al NAS da IP non in whitelist (non MacBook, non iPad) |
| **Regola Wazuh** | Custom rule su network traffic alert + monitoring accesso porta 445/tcp verso NAS-01 |
| **Risposta prevista** | Alert TheHive → verifica accessi account WD online → revoca sessioni remote se anomalo |
| **Asset** | NAS-01 (R-06) |
| **Priorità** | Alta |

**Prerequisiti:**
- IP statico NAS-01 (DHCP reservation 192.168.68.90)
- Whitelist IP autorizzati per SMB: solo END-05 (192.168.68.108), END-01
- 2FA account WD abilitato (azione immediata pre-deploy)

---

### UC-05 — Vulnerabilità Critica su POS/Cassa Negozio

| Campo | Dettaglio |
|---|---|
| **Scenario** | Greenbone rileva CVE critica (CVSS ≥ 7.0) su cassa o POS del negozio, potenzialmente sfruttabile per malware POS o accesso non autorizzato |
| **ATT&CK Technique** | T1190 — Exploit Public-Facing Application |
| **Tattica** | Initial Access |
| **Sorgente dati** | Greenbone/OpenVAS scan report (ct-102) — scan settimanale schedulato |
| **Trigger** | Finding CVSS ≥ 7.0 su NEG-01 o NEG-02 |
| **Regola Wazuh** | Import report Greenbone via API → Wazuh custom integration → alert livello critico |
| **Risposta prevista** | Alert TheHive → playbook "Critical Vuln Negozio" → patch entro 72h o workaround documentato |
| **Asset** | NEG-01, NEG-02 (R-03, R-04) |
| **Priorità** | Alta |

**Scan schedule Greenbone:**
```
Cron: ogni domenica 02:00 → scan completo subnet negozio
Alert: se CVSS >= 7.0 → ticket TheHive automatico
Report: PDF settimanale in /lab-reports/greenbone/
```

---

### UC-06 — Device IoT Non Identificato in Rete (bonus)

| Campo | Dettaglio |
|---|---|
| **Scenario** | Device sconosciuto (come ESP_EF1867) appare in rete con comportamento anomalo — potenzialmente rogue device o compromissione |
| **ATT&CK Technique** | T1200 — Hardware Additions |
| **Tattica** | Initial Access |
| **Sorgente dati** | DHCP lease table Deco (polling periodico) → confronto con asset inventory approvato |
| **Trigger** | Nuovo MAC address in rete non presente in whitelist asset inventory |
| **Regola Wazuh** | Custom script polling DHCP + Wazuh active response alert |
| **Risposta prevista** | Alert → identificazione fisica device → quarantena (blocco MAC sul Deco) se non riconosciuto |
| **Asset** | AUTO-04 ESP_EF1867 (R-11) |
| **Priorità** | Media |

---

### 6.1 Riepilogo use case per fase

| Use Case | ATT&CK | Fase | Priorità | Stato |
|---|---|---|---|---|
| UC-01 SSH Brute Force | T1110.001 | Fase 3 | Alta | Da implementare |
| UC-02 IoT Beaconing C2 | T1071.001 | Fase 3 | Alta | Da implementare |
| UC-03 FIM MacBook | T1565.001 | Fase 3 | Alta | Da implementare |
| UC-04 NAS Unauthorized Access | T1078 | Fase 3 | Alta | Da implementare |
| UC-05 Vuln Critica Negozio | T1190 | Fase 2 | Alta | Da implementare |
| UC-06 Rogue Device | T1200 | Fase 3 | Media | Da implementare |

### 6.2 Mapping completo MITRE ATT&CK Navigator

> Esportare questo mapping come layer JSON per MITRE ATT&CK Navigator:
> `configs/attack-navigator/homesoc-layer-v1.json`

Tecniche coperte in Fase 3:
- T1110.001 — Brute Force SSH
- T1071.001 — C2 via web protocols
- T1565.001 — FIM stored data
- T1078 — Valid Accounts
- T1190 — Exploit Public-Facing
- T1200 — Hardware Additions
- T1046 — Network Service Discovery (Greenbone)
- T1083 — File and Directory Discovery (FIM)

---

## Checklist Fase 1 — Completamento

- [x] Network diagram topologia attuale documentata
- [x] Network diagram topologia target con HomeSOC
- [x] Topologia futura OPNsense descritta
- [x] Logical security architecture (6 layer defense-in-depth)
- [x] Data flow diagram con porte e protocolli
- [x] Proxmox VM/CT layout definitivo (16 GB e 32 GB)
- [x] Network bridge Proxmox documentati
- [x] Detection use cases ≥5 MITRE ATT&CK (6 implementati)
- [ ] Network diagram draw.io esportato → docs/03-network-diagram.drawio
- [x] MITRE ATT&CK Navigator layer → configs/attack-navigator/homesoc-layer-v1.json

---

*File: `docs/02-architecture.md` · v1.1 · Aprile 2026*
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
