# 01 — Threat Model
**Progetto:** HomeSOC · Domestic Security Operations Centre
**Versione:** 1.1 — Aprile 2026
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI
**Framework:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

> Aggiornare questo documento ad ogni nuova fase di deployment e quando vengono aggiunti asset.
> Committare con: `git commit -m "docs(threat-model): update vX.Y — <motivo>"`

**Changelog:**
- v1.0 — Aprile 2026 — Prima stesura
- v1.1 — Aprile 2026 — Correzione modelli Deco (XE75/XE75 Pro), termostati → Google Nest Learning 3a gen, NAS → WD My Cloud Home, aggiornamento R-06, aggiunta sezione CIA

---

## Indice

1. [Asset Inventory](#1-asset-inventory)
2. [Threat Model STRIDE](#2-threat-model-stride)
3. [Risk Register](#3-risk-register)
4. [Obiettivi CIA per Segmento](#4-obiettivi-cia-per-segmento)
5. [Note e TODO](#5-note-e-todo)

---

## 1. Asset Inventory

**Fonte:** Deco App (10/04/2026 22:22) + dashboard WD My Cloud Home + Project Charter v1
**Subnet:** 192.168.71.0/24

### Note architetturali

- Il Deco BE65 (Salotto) è il nodo master e gateway NAT. I nodi satellite sono Deco XE75 Pro e XE75.
- La rete IoT è un SSID separato ma condivide la stessa subnet della LAN principale — **nessun isolamento reale tra segmenti.**
- Alcuni device Google Home non funzionano su IoT SSID (WPA2-only) — rimasti su LAN-MAIN.
- Il Nighthawk S8000 opera come switch unmanaged — nessuna subnet shadow, nessuna VLAN.
- Il Zyxel Windinfostrada opera come modem puro. Il Deco BE65 è il gateway NAT effettivo. Dall'esterno tutte le porte risultano chiuse (verificato 10/04/2026).
- Isolamento reale con VLAN possibile solo con OPNsense (pianificato per casa nuova — Fase FUTURO).

### 1.1 Infrastruttura di Rete

| ID | Hostname | Tipo | IP | Connessione | Firmware | Note |
|---|---|---|---|---|---|---|
| INF-01 | Deco BE65 — Salotto | Mesh Gateway (master) | 192.168.71.1 | — | 1.2.0 B20250718 | Nodo principale, NAT gateway |
| INF-02 | Deco XE75 Pro — Camera Nicole | Mesh Node | 192.168.71.250 | Ethernet backhaul | 1.3.1 B20251023 | — |
| INF-03 | Deco XE75 — Cucina | Mesh Node | 192.168.71.247 | Wireless backhaul | 1.3.1 B20251023 | — |
| INF-04 | Deco XE75 Pro — Camera Ale | Mesh Node | TBD | TBD | 1.3.1 B20251023 | — |
| INF-05 | Deco XE75 Pro — Negozio | Mesh Node | TBD | TBD | 1.3.1 B20251023 | Sede Sesto San Giovanni |
| INF-06 | Nighthawk S8000 | Switch unmanaged | N/A | Ethernet | TBD | Nessuna funzione di routing, nessuna VLAN |
| INF-07 | Zyxel Windinfostrada | Modem (bridge) | 192.168.1.1 (stima) | Fibra | TBD | Fa solo da modem, NAT sul Deco |

### 1.2 Endpoint Utente

| ID | Hostname | Tipo | IP | OS | Note |
|---|---|---|---|---|---|
| END-01 | Ipaddialessandro | iPad Alessandro | DHCP | iPadOS | Dispositivo principale utente |
| END-02 | iPhone ale | iPhone Alessandro | DHCP | iOS | — |
| END-03 | iPhone | iPhone (utente TBD) | DHCP | iOS | Verificare proprietario |
| END-04 | iPad-di-Nicole-2 | iPad Nicole | DHCP | iPadOS | — |
| END-05 | MacBook Pro M1 Pro | Laptop principale | TBD → statico | macOS | **Asset critico. Target prioritario Wazuh agent + FIM.** |
| END-06 | Air-di-Nicole | Laptop/PC Nicole | DHCP | TBD | Modello da confermare |

### 1.3 NAS / Storage

| ID | Hostname | Tipo | IP | Note |
|---|---|---|---|---|
| NAS-01 | MyCloud-2J1F4P | WD My Cloud Home | DHCP → statico | Cloud-first by design: connessione ai server WD non disabilitabile. Accesso remoto dipende interamente dalla sicurezza dell'account WD. 2FA da abilitare. |

### 1.4 IoT — Robot Vacuum

| ID | Hostname | Tipo | IP | Note |
|---|---|---|---|---|
| IOT-01 | robot dreame | Dreame Robot Vacuum | DHCP | ⚠️ Beaconing attivo (15↓ / 6↑ kbps). Traffico cloud cinese. |
| IOT-02 | robot narwal | Narwal Robot | DHCP | Stesso profilo rischio Dreame. Traffico cloud cinese. |
| IOT-03 | roborock-vacuum-a15 | Roborock A15 | DHCP | Presente nel negozio. |

### 1.5 IoT — Telecamere

| ID | Hostname | Tipo | IP | Note |
|---|---|---|---|---|
| CAM-01 | Tapo camera ale | TP-Link Tapo | DHCP | Cloud TP-Link |
| CAM-02 | videocamera primo piano | IP Cam (TBD) | DHCP | Da identificare. Nodo Camera Ale. |
| CAM-03 | telecamera cortile | IP Cam (TBD) | DHCP | Nodo Cucina. |
| CAM-04 | VMC2030-A054C | Netgear Arlo | DHCP | Cloud Arlo. Nodo Camera Nicole. |
| CAM-05 | telecamera negozio | IP Cam (TBD) | DHCP | Negozio. |
| CAM-06 | sistema sorveglianza negozio | NVR locale | TBD | Ethernet. Storage locale. Negozio. |
| CAM-07 | google nest hub camera matrimoniale | Google Nest Hub | DHCP | Cloud Google, camera integrata. |

### 1.6 IoT — Climatizzazione

| ID | Hostname | Tipo | IP | Firmware | Note |
|---|---|---|---|---|---|
| CLIM-01 | termostato primo piano | Google Nest Learning 3a gen | DHCP | Ultimo disponibile | Aggiornamenti automatici Google. Profilo rischio contenuto. |
| CLIM-02 | termostato piano terra | Google Nest Learning 3a gen | DHCP | Ultimo disponibile | Come CLIM-01. |
| CLIM-03 | Samsung-Room-AC (×2) | Samsung AC | DHCP | TBD | SmartThings cloud. Due unità. |

### 1.7 IoT — Automazione

| ID | Hostname | Tipo | IP | Note |
|---|---|---|---|---|
| AUTO-01 | tapparella ale | Shutter controller (Shelly?) | DHCP | Controllo fisico tapparelle Camera Ale |
| AUTO-02 | SAMJIN | Samsung SmartThings Hub | DHCP | Bridge Zigbee/Z-Wave → cloud Samsung |
| AUTO-03 | Wisol | IoT module embedded (TBD) | DHCP | Modulo embedded — identificare device host |
| AUTO-04 | ESP_EF1867 | ESP8266/ESP32 custom | DHCP | ⚠️ Firmware e funzione sconosciuti. Priorità identificazione. |

### 1.8 Speaker / Display

| ID | Hostname | Tipo | IP | Note |
|---|---|---|---|---|
| SPK-01 | Google-Home (×2+) | Google Home | DHCP | Su LAN-MAIN (incompatibili WPA2-only IoT SSID) |
| SPK-02 | Google Mini ale | Google Nest Mini | DHCP | Camera Ale |
| SPK-03 | Google (generico) | Google device (TBD) | DHCP | Identificare modello |
| SPK-04 | google nicole | Google device Nicole | DHCP | Nodo Camera Nicole |
| SPK-05 | Google nest hub cucina | Google Nest Hub | DHCP | Cucina |

### 1.9 Intrattenimento

| ID | Hostname | Tipo | IP | Note |
|---|---|---|---|---|
| ENT-01 | Samsung (×2) | Smart TV Samsung | DHCP | SmartThings/Tizen cloud. Due unità. |
| ENT-02 | XBOX | Xbox Console | TBD | Ethernet. Xbox Live. |
| ENT-03 | skyq | Sky Q Decoder | DHCP | Cloud Sky |
| ENT-04 | Sala-audio- | Sistema Audio (TBD) | DHCP | Modello da identificare (Sonos?) |

### 1.10 Negozio — Sesto San Giovanni

| ID | Hostname | Tipo | IP | Connessione | Note |
|---|---|---|---|---|---|
| NEG-01 | cassa negozio | Cassa / Software POS | DHCP | Ethernet | 🔴 Asset critico. Gestisce pagamenti. Flat network. |
| NEG-02 | pos negozio | Terminale POS fisico | DHCP | Ethernet | 🔴 Asset critico. Dati carte. Flat network. |
| NEG-03 | android-5edd... | Android (TBD) | DHCP | WiFi | ⚠️ Non identificato. Verificare fisicamente. |

### 1.11 Server HomeSOC (pianificato — non ancora deployato)

| ID | Hostname | Tipo | IP Target | OS | Ruolo |
|---|---|---|---|---|---|
| SOC-01 | homesoc | GMKtec M5 Ultra · Ryzen 7 7730U · 32GB | Statico TBD | Proxmox VE | Hypervisor per tutte le VM del progetto |

---

## 2. Threat Model STRIDE

**Legenda:** P = Probabilità (1-3) · I = Impatto (1-3) · Rischio = P × I

### 2.1 Definizione segmenti

| Segmento | Asset inclusi | Isolamento attuale |
|---|---|---|
| **LAN-MAIN** | Endpoint utente, NAS, speaker, TV, console | Nessuno — flat network |
| **IOT-SSID** | Robot, telecamere, termostati, automazione | SSID separato, stessa subnet — nessun isolamento reale |
| **NEGOZIO** | POS, cassa, NVR, robot negozio | Nodo Deco separato geograficamente, stessa infrastruttura logica |
| **SOC** | Server HomeSOC (futuro) | Da definire in Fase 2 |

### 2.2 MacBook Pro M1 Pro (END-05)

| Minaccia STRIDE | Scenario | P | I | Rischio |
|---|---|---|---|---|
| Elevation of Privilege | Malware ottiene privilegi root tramite exploit macOS o app malevola | 2 | 3 | **ALTO** |
| Information Disclosure | Keylogger o screen capture esfiltrano credenziali e dati sensibili | 2 | 3 | **ALTO** |
| Tampering | Modifica file di sistema o configurazioni critiche | 1 | 3 | **MEDIO** |
| Lateral Movement | MacBook usato come pivot per attaccare altri device LAN | 2 | 3 | **ALTO** |

**Controlli previsti:** Wazuh agent macOS, FIM su home directory, ClamAV, nessun servizio esposto in LAN.

### 2.3 NAS WD My Cloud Home (NAS-01)

| Minaccia STRIDE | Scenario | P | I | Rischio |
|---|---|---|---|---|
| Information Disclosure | Account WD compromesso → accesso remoto ai file da attore esterno | 2 | 3 | **ALTO** |
| Tampering | Ransomware da LAN cifra share accessibili via SMB | 2 | 3 | **ALTO** |
| Spoofing | Credenziali account WD rubate (phishing) → accesso cloud non autorizzato | 2 | 3 | **ALTO** |
| Denial of Service | NAS irraggiungibile per saturazione o attacco diretto | 1 | 2 | **BASSO** |

**Nota:** WD My Cloud Home è cloud-first by design — connessione ai server WD non disabilitabile. Il controllo della superficie di attacco passa interamente dalla sicurezza dell'account WD.
**Controlli previsti:** 2FA su account WD, password robusta e unica, monitoraggio traffico Wazuh post-deploy, IP statico.

### 2.4 Robot Vacuum cinesi — Dreame / Narwal (IOT-01, IOT-02)

| Minaccia STRIDE | Scenario | P | I | Rischio |
|---|---|---|---|---|
| Information Disclosure | Beaconing costante verso cloud cinesi — dati mappatura casa, abitudini | 3 | 2 | **ALTO** |
| Spoofing | Server C2 camuffato da endpoint cloud legittimo del vendor | 2 | 2 | **MEDIO** |
| Tampering | Aggiornamento firmware OTA compromesso — backdoor installata | 1 | 3 | **MEDIO** |
| Elevation of Privilege | Vulnerabilità firmware → shell remota → pivot su LAN flat | 1 | 3 | **MEDIO** |

**Controlli previsti:** Monitoraggio NextDNS per IoC DNS, blocco DNS verso IP Baidu anomali, VLAN IoT reale con OPNsense (Fase FUTURO), Wazuh alert su beaconing post-deploy.

### 2.5 Telecamere IP (CAM-01 → CAM-07)

| Minaccia STRIDE | Scenario | P | I | Rischio |
|---|---|---|---|---|
| Information Disclosure | Stream video esfiltrato verso cloud vendor o attore esterno | 2 | 3 | **ALTO** |
| Tampering | Firmware OTA compromesso — camera usata come punto di osservazione | 1 | 3 | **MEDIO** |
| Spoofing | Camera impersonata da device malevolo su rete flat | 1 | 2 | **BASSO** |
| Denial of Service | Camera irraggiungibile per saturazione rete | 1 | 2 | **BASSO** |

**Controlli previsti:** Firmware aggiornato, blocco accesso internet telecamere (OPNsense futuro), monitoraggio Uptime Kuma.

### 2.6 Termostati Google Nest Learning 3a gen (CLIM-01, CLIM-02)

| Minaccia STRIDE | Scenario | P | I | Rischio |
|---|---|---|---|---|
| Information Disclosure | Dati abitudini domestiche (orari, presenze) verso cloud Google | 2 | 1 | **BASSO** |
| Tampering | Compromissione account Google → controllo remoto temperatura | 1 | 2 | **BASSO** |

**Nota:** Profilo di rischio contenuto. Hardware di qualità enterprise, aggiornamenti automatici garantiti da Google, nessuna CVE critica nota recente.
**Controlli previsti:** Account Google con 2FA. Nessuna azione aggiuntiva prioritaria.

### 2.7 Automazione — Shelly / ESP custom (AUTO-01, AUTO-04)

| Minaccia STRIDE | Scenario | P | I | Rischio |
|---|---|---|---|---|
| Elevation of Privilege (Shelly) | Accesso non autorizzato al relay — controllo fisico tapparelle/luci | 1 | 2 | **BASSO** |
| Tampering (Shelly) | Modifica configurazione via interfaccia web non autenticata | 1 | 2 | **BASSO** |
| Spoofing (ESP_EF1867) | Device non identificato — natura e legittimità sconosciuta | 2 | 2 | **MEDIO** |
| Information Disclosure (ESP_EF1867) | Firmware ignoto trasmette dati in chiaro o verso C2 | 2 | 2 | **MEDIO** |

**Controlli previsti:** Shelly — nessun cloud, auth UI web abilitata, firmware aggiornato. ESP — identificazione fisica urgente.

**Metodologia identificazione ESP_EF1867:**
1. MAC OUI lookup su macvendors.com → identificare produttore chipset
2. Ispezione fisica — localizzare il device seguendo il MAC address sulla rete
3. Traffic capture con tcpdump/Wireshark — analizzare destinazioni, protocolli, frequenza
4. Se non identificato → quarantena (blocco MAC sul Deco) fino a verifica

### 2.8 POS e Cassa Negozio (NEG-01, NEG-02)

| Minaccia STRIDE | Scenario | P | I | Rischio |
|---|---|---|---|---|
| Tampering | Malware POS (RAM scraper) — esfiltrazione dati carte di credito | 2 | 3 | **ALTO** |
| Denial of Service | Cassa irraggiungibile — interruzione attività negozio | 2 | 3 | **ALTO** |
| Lateral Movement | Device IoT compromesso nella stessa subnet usato per attaccare POS | 2 | 3 | **ALTO** |
| Repudiation | Transazioni non tracciabili in assenza di log centralizzati | 2 | 2 | **MEDIO** |

**Nota:** Isolamento VLAN non possibile con hardware attuale. R-05 classificato Posticipato — richiede OPNsense + switch managed.
**Controlli previsti:** Greenbone scan periodico, Wazuh monitoring post-deploy, isolamento futuro con OPNsense.

### 2.9 Server HomeSOC (SOC-01)

| Minaccia STRIDE | Scenario | P | I | Rischio |
|---|---|---|---|---|
| Tampering | Compromissione del server di monitoring — blind spot totale sulla rete | 1 | 3 | **MEDIO** |
| Elevation of Privilege | Accesso SSH non autorizzato → root dell'hypervisor | 1 | 3 | **MEDIO** |
| Denial of Service | Server SOC irraggiungibile — perdita visibilità su tutta la rete | 1 | 3 | **MEDIO** |
| Repudiation | Log Wazuh manomessi — eventi non più attendibili | 1 | 3 | **MEDIO** |

**Controlli previsti:** SSH hardening (no root login, solo chiavi pubbliche), fail2ban, snapshot Proxmox automatici, accesso solo LAN, Tailscale per accesso remoto.

### 2.10 DNS Resolver — NextDNS

| Minaccia STRIDE | Scenario | P | I | Rischio |
|---|---|---|---|---|
| Spoofing | DNS poisoning — redirect verso siti malevoli | 1 | 2 | **BASSO** |
| Denial of Service | NextDNS irraggiungibile — rete senza risoluzione nomi | 1 | 2 | **BASSO** |

**Controlli previsti:** NextDNS DoH (DNS over HTTPS), DNSSEC abilitato, DNS di fallback configurato.

---

## 3. Risk Register

**Legenda:**
- **P** = Probabilità: 1 (raro) · 2 (possibile) · 3 (probabile)
- **I** = Impatto: 1 (trascurabile) · 2 (significativo) · 3 (grave)
- **Rischio** = P × I — 1-2: BASSO · 3-4: MEDIO · 6-9: ALTO
- **Stato:** Aperto · Mitigato · Accettato · Posticipato

| ID | Asset | Minaccia STRIDE | P | I | Rischio | Controllo previsto | Fase | Stato |
|---|---|---|---|---|---|---|---|---|
| R-01 | IOT-01, IOT-02 (Robot cinesi) | Information Disclosure — beaconing cloud cinese | 3 | 2 | **ALTO (6)** | NextDNS blocco IoC, VLAN IoT (OPNsense futuro), Wazuh alert | Fase 3 | Aperto |
| R-02 | END-05 (MacBook) | Elevation of Privilege — malware, lateral movement | 2 | 3 | **ALTO (6)** | Wazuh agent macOS, FIM home dir, ClamAV | Fase 3 | Aperto |
| R-03 | NEG-01, NEG-02 (POS/Cassa) | Tampering — malware POS, RAM scraper | 2 | 3 | **ALTO (6)** | Greenbone scan, Wazuh monitoring | Fase 2 | Aperto |
| R-04 | NEG-01, NEG-02 (POS/Cassa) | Denial of Service — interruzione attività negozio | 2 | 3 | **ALTO (6)** | Greenbone scan, Uptime Kuma | Fase 2 | Aperto |
| R-05 | NEG-01, NEG-02 (POS/Cassa) | Lateral Movement da IoT su rete flat | 2 | 3 | **ALTO (6)** | Isolamento VLAN con OPNsense + switch managed | Futuro | Posticipato — hardware insufficiente |
| R-06 | NAS-01 (WD My Cloud Home) | Information Disclosure — account WD compromesso | 2 | 3 | **ALTO (6)** | 2FA account WD, password robusta, monitoraggio Wazuh | Immediato | Aperto — relay non disabilitabile per design |
| R-07 | CAM-01→07 (Telecamere) | Information Disclosure — stream video verso cloud | 2 | 3 | **ALTO (6)** | Blocco internet telecamere (OPNsense futuro), firmware aggiornato | Futuro | Posticipato |
| R-08 | END-05 (MacBook) | Information Disclosure — keylogger/screen capture | 2 | 3 | **ALTO (6)** | Wazuh agent, FIM, controllo processi | Fase 3 | Aperto |
| R-09 | SOC-01 (Server HomeSOC) | Tampering — compromissione server monitoring | 1 | 3 | **MEDIO (3)** | SSH hardening, no root, fail2ban, snapshot Proxmox | Fase 2 | Aperto |
| R-10 | SOC-01 (Server HomeSOC) | Elevation of Privilege — accesso SSH non autorizzato | 1 | 3 | **MEDIO (3)** | Chiavi pubbliche only, fail2ban | Fase 2 | Aperto |
| R-11 | AUTO-04 (ESP_EF1867) | Spoofing / Info Disclosure — device non identificato | 2 | 2 | **MEDIO (4)** | Identificazione fisica MAC OUI, analisi traffico Wazuh | Immediato | Aperto |
| R-12 | IOT-01, IOT-02 (Robot cinesi) | Tampering — firmware OTA compromesso | 1 | 3 | **MEDIO (3)** | Blocco OTA automatici via DNS, monitoraggio | Fase 3 | Aperto |
| R-13 | CAM-01→07 (Telecamere) | Tampering — firmware OTA compromesso | 1 | 3 | **MEDIO (3)** | Firmware aggiornato manualmente | Fase 3 | Aperto |
| R-14 | NEG-01, NEG-02 (POS/Cassa) | Repudiation — assenza log centralizzati | 2 | 2 | **MEDIO (4)** | Wazuh log centralizzati post-deploy | Fase 3 | Aperto |
| R-15 | AUTO-01 (Shelly) | Elevation of Privilege — controllo fisico dispositivi | 1 | 2 | **BASSO (2)** | Nessun cloud Shelly, auth UI web abilitata | Immediato | Aperto |
| R-16 | CLIM-01, CLIM-02 (Nest Learning) | Information Disclosure — dati abitudini verso Google | 2 | 1 | **BASSO (2)** | Account Google con 2FA | Immediato | Accettato |
| R-17 | INF-01→05 (Deco mesh) | Spoofing — DNS poisoning | 1 | 2 | **BASSO (2)** | NextDNS DoH, DNSSEC | Immediato | Aperto |

### 3.1 Riepilogo per priorità

| Priorità | Rischi | Asset principali |
|---|---|---|
| 🔴 ALTO (6+) | R-01, R-02, R-03, R-04, R-05, R-06, R-07, R-08 | Robot IoT, MacBook, POS/Cassa, NAS, Telecamere |
| 🟡 MEDIO (3-4) | R-09, R-10, R-11, R-12, R-13, R-14 | Server SOC, ESP custom, firmware IoT, log negozio |
| 🟢 BASSO (1-2) | R-15, R-16, R-17 | Shelly, Nest, DNS |

### 3.2 Azioni immediate (pre-deployment)

| Rischio | Azione |
|---|---|
| R-06 | Abilitare 2FA su account WD My Cloud Home |
| R-11 | Identificare ESP_EF1867 fisicamente — MAC OUI su macvendors.com |
| R-15 | Verificare auth UI web Shelly abilitata, cloud Shelly disabilitato |
| R-16 | Verificare 2FA su account Google (già accettato — solo conferma) |
| R-17 | Confermare NextDNS DoH attivo dalla dashboard NextDNS |

---

## 4. Obiettivi CIA per Segmento

La triade **CIA** (Confidentiality · Integrity · Availability) è declinata per ogni segmento in base alla natura degli asset e alle minacce identificate nella sezione 2.

**Livelli:** 🔴 Critico · 🟡 Alto · 🟢 Standard

### 4.1 LAN Principale — Endpoint utente, NAS

| Obiettivo | Livello | Descrizione | Controlli principali |
|---|---|---|---|
| **Confidentiality** | 🔴 Critico | Prevenire accesso non autorizzato a file personali, credenziali e dati finanziari su MacBook e NAS | Wazuh FIM, 2FA account WD, FileVault su macOS |
| **Integrity** | 🟡 Alto | Rilevare modifiche non autorizzate a file critici e configurazioni su endpoint | Wazuh FIM su home directory MacBook, alert su modifiche sospette |
| **Availability** | 🟢 Standard | Garantire operatività normale degli endpoint — downtime tollerato nell'ordine di ore | Uptime Kuma, snapshot NAS |

**Rischi collegati:** R-02, R-06, R-08.

### 4.2 IoT — Robot, Telecamere, Automazione

| Obiettivo | Livello | Descrizione | Controlli principali |
|---|---|---|---|
| **Confidentiality** | 🔴 Critico | Impedire esfiltrazione dati di mappatura casa, stream video e abitudini domestiche verso cloud non controllati | NextDNS blocco IoC, VLAN IoT (futuro OPNsense), monitoraggio beaconing Wazuh |
| **Integrity** | 🟡 Alto | Garantire che i device IoT eseguano solo firmware legittimo e non siano stati compromessi via OTA | Blocco OTA automatici per device critici, verifica firma firmware |
| **Availability** | 🟡 Alto | Telecamere e automazione devono essere operative — malfunzionamento impatta sicurezza fisica | Uptime Kuma, alert su device offline |

**Rischi collegati:** R-01, R-07, R-12, R-13.

### 4.3 Negozio — POS, Cassa, Sorveglianza

| Obiettivo | Livello | Descrizione | Controlli principali |
|---|---|---|---|
| **Confidentiality** | 🔴 Critico | Proteggere dati di pagamento (carte di credito/bancomat) da esfiltrazione | Greenbone scan, Wazuh monitoring, isolamento futuro OPNsense |
| **Integrity** | 🔴 Critico | Garantire che cassa e POS non siano stati manomessi — malware o RAM scraper | Greenbone vulnerability scan periodico, integrità software POS verificata |
| **Availability** | 🔴 Critico | Cassa e POS devono essere sempre operativi durante orario di apertura — ogni minuto di downtime è perdita diretta | Uptime Kuma con alert immediato, piano di ripristino documentato |

**Rischi collegati:** R-03, R-04, R-05, R-14.
**Nota:** Tutti e tre gli obiettivi CIA sono Critici — il negozio è il segmento con il maggiore impatto economico diretto.

### 4.4 Server HomeSOC

| Obiettivo | Livello | Descrizione | Controlli principali |
|---|---|---|---|
| **Confidentiality** | 🟡 Alto | Proteggere configurazioni, detection rules e log da accesso non autorizzato | SSH con chiavi pubbliche only, accesso solo LAN, Tailscale per remoto |
| **Integrity** | 🔴 Critico | Il SOC è il sistema di fiducia dell'intera rete — se compromesso, tutti gli alert perdono valore | Snapshot Proxmox automatici, no root login, verifica integrità Wazuh |
| **Availability** | 🟡 Alto | Il SOC deve essere operativo per garantire visibilità — downtime tollerato nell'ordine di minuti/ore | Uptime Kuma self-monitoring, watchdog Proxmox |

**Rischi collegati:** R-09, R-10.
**Nota:** L'Integrity è Critica perché un SOC compromesso è peggio di nessun SOC — genera falsa sicurezza sull'intera infrastruttura.

### 4.5 DNS — NextDNS

| Obiettivo | Livello | Descrizione | Controlli principali |
|---|---|---|---|
| **Confidentiality** | 🟢 Standard | Le query DNS non devono essere leggibili in chiaro da attori sulla rete locale o ISP | NextDNS DoH (DNS over HTTPS) |
| **Integrity** | 🟡 Alto | Le risposte DNS devono essere autentiche — DNS poisoning reindirizzerebbe tutti i device | DNSSEC abilitato, DoH impedisce MITM |
| **Availability** | 🟡 Alto | La rete dipende interamente da NextDNS — se irraggiungibile, nessun device risolve i nomi | DNS di fallback configurato (es. 1.1.1.1) |

**Rischi collegati:** R-17.

### 4.6 Riepilogo CIA per segmento

| Segmento | Confidentiality | Integrity | Availability |
|---|---|---|---|
| LAN Principale | 🔴 Critico | 🟡 Alto | 🟢 Standard |
| IoT | 🔴 Critico | 🟡 Alto | 🟡 Alto |
| Negozio | 🔴 Critico | 🔴 Critico | 🔴 Critico |
| Server HomeSOC | 🟡 Alto | 🔴 Critico | 🟡 Alto |
| DNS | 🟢 Standard | 🟡 Alto | 🟡 Alto |

---

## 5. Note e TODO

### Assunzioni e limitazioni attuali

- Nessuna VLAN reale — rischi R-05, R-07 classificati come Posticipati — tecnicamente non mitigabili con hardware attuale.
- WD My Cloud Home è cloud-first by design — relay WD non disabilitabile. Unico controllo possibile: sicurezza account.
- IP di quasi tutti i device è DHCP — inventory IP completo richiede export DHCP lease table dal Deco.
- Device non ancora identificati: AUTO-03 (Wisol host), AUTO-04 (ESP_EF1867), NEG-03 (Android negozio).

### TODO — prossimi aggiornamenti

| # | Azione | Rischio | Priorità | Stato |
|---|---|---|---|---|
| 1 | Abilitare 2FA su account WD My Cloud Home | R-06 | Alta | Da completare |
| 2 | Identificare ESP_EF1867 tramite MAC OUI lookup + ispezione fisica | R-11 | Alta | Da completare |
| 3 | Completare colonne IP/MAC con DHCP lease table Deco | Tutti | Media | Da completare |
| 4 | Identificare device host modulo Wisol (AUTO-03) | R-11 | Media | Da completare |
| 5 | Verificare Android negozio (NEG-03) fisicamente | — | Media | Da completare |
| 6 | Aggiornare stato rischi a ogni nuova fase di deployment | Tutti | Ongoing | — |

**Commit:** `git add docs/01-threat-model.md && git commit -m "docs(threat-model): update vX.Y — <motivo>"`

---

*File: `docs/01-threat-model.md` · v1.1 · Aprile 2026*
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
