# 01 — Threat Model
**Progetto:** HomeSOC · Domestic Security Operations Centre
**Versione:** 1.3 — Aprile 2026
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI
**Framework:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

> Aggiornare questo documento ad ogni nuova fase di deployment e quando vengono aggiunti asset.
> Committare con: `git commit -m "docs(threat-model): update vX.Y — <motivo>"`

**Changelog:**
- v1.0 — Aprile 2026 — Prima stesura
- v1.1 — Aprile 2026 — Correzione modelli Deco (XE75/XE75 Pro), termostati → Google Nest Learning 3a gen, NAS → WD My Cloud Home, aggiornamento R-06, aggiunta sezione CIA
- v1.2 — Aprile 2026 — Correzione subnet (192.168.68.0/24), IP/MAC da scan CSV, identificazione ESP_EF1867 (luce smart sala), PAX Computer come hardware POS, Narwal FN-LINK, due Roborock distinti, aggiornamento stati risk register (R-06, R-11, R-15, R-16, R-17), NEG-03 identificato come POS mobile, note DoH Deco BE65
- v1.3 — Aprile 2026 — Aggiornamento risk register post Fase 3: R-01/R-02/R-08/R-10 Parziale Mitigato (UC operativi + Slack), R-14 nota aggiornata (Wazuh manager operativo, POS enrollment pianificato)
- v1.4 — Aprile 2026 — R-10 → Mitigato ✅: CrowdSec cs-firewall-bouncer attivo su SOC-01, pipeline CrowdSec → Wazuh verificata in produzione; aggiornamento controlli sez. 2.9

---

## Indice

1. [Asset Inventory](#1-asset-inventory)
2. [Threat Model STRIDE](#2-threat-model-stride)
3. [Risk Register](#3-risk-register)
4. [Obiettivi CIA per Segmento](#4-obiettivi-cia-per-segmento)
5. [Note e TODO](#5-note-e-todo)

---

## 1. Asset Inventory

**Fonte:** Deco App (10/04/2026 22:22) + scan ARP/nmap CSV (11/04/2026) + dashboard WD My Cloud Home + Project Charter v1
**Subnet:** 192.168.68.0/24
**DHCP range:** 192.168.68.51+ (le prime 50 sono riservate dal Deco per uso interno/statico)

### Note architetturali

- Il Deco BE65 (Salotto) è il nodo master e gateway NAT. I nodi satellite sono Deco XE75 Pro e XE75.
- La rete IoT è un SSID separato ma condivide la stessa subnet della LAN principale — **nessun isolamento reale tra segmenti.**
- Alcuni device Google Home non funzionano su IoT SSID (WPA2-only) — rimasti su LAN-MAIN.
- Il Nighthawk S8000 opera come switch unmanaged — nessuna subnet shadow, nessuna VLAN.
- Il Zyxel Windinfostrada opera come modem puro. Il Deco BE65 è il gateway NAT effettivo. Dall'esterno tutte le porte risultano chiuse (verificato 10/04/2026).
- Isolamento reale con VLAN possibile solo con OPNsense (pianificato per casa nuova — Fase FUTURO).
- **DoH non supportato a livello router dal Deco BE65** — aggiornamento firmware con supporto DoH in beta testing al momento della stesura. DoH attivo solo su device con profilo NextDNS configurato direttamente (es. MacBook). Impatta R-17.

### 1.1 Infrastruttura di Rete

| ID | Hostname | Tipo | IP | Connessione | Firmware | Note |
|---|---|---|---|---|---|---|
| INF-01 | Deco BE65 — Salotto | Mesh Gateway (master) | 192.168.68.1 | — | 1.2.0 B20250718 | Nodo principale, NAT gateway |
| INF-02 | Deco XE75 Pro — Camera Nicole | Mesh Node | 192.168.68.250 | Ethernet backhaul | 1.3.1 B20251023 | — |
| INF-03 | Deco XE75 — Cucina | Mesh Node | 192.168.68.247 | Wireless backhaul | 1.3.1 B20251023 | — |
| INF-04 | Deco XE75 Pro — Camera Ale | Mesh Node | TBD | TBD | 1.3.1 B20251023 | — |
| INF-05 | Deco XE75 Pro — Negozio | Mesh Node | TBD | TBD | 1.3.1 B20251023 | Sede Sesto San Giovanni |
| INF-06 | Nighthawk S8000 | Switch unmanaged | N/A | Ethernet | TBD | Nessuna funzione di routing, nessuna VLAN |
| INF-07 | Zyxel Windinfostrada | Modem (bridge) | 192.168.1.1 (stima) | Fibra | TBD | Fa solo da modem, NAT sul Deco |

### 1.2 Endpoint Utente

| ID | Hostname | Tipo | IP | MAC | OS | Note |
|---|---|---|---|---|---|---|
| END-01 | Ipaddialessandro | iPad Alessandro | DHCP | — | iPadOS | Dispositivo principale utente |
| END-02 | Iphone-di-alessandro.local | iPhone Alessandro | 192.168.68.79 | F6:C9:51:DC:F9:58 | iOS | — |
| END-03 | iPhone (utente TBD) | iPhone | DHCP | — | iOS | Verificare proprietario |
| END-04 | iPad-di-Nicole-2 | iPad Nicole | DHCP | — | iPadOS | — |
| END-05 | MacBookPro-di-Alessandro-Gaburro.local | MacBook Pro M1 Pro | 192.168.68.108 → **reservation .108** | C6:A3:2A:A3:A8:0F | macOS | **Asset critico. Target prioritario Wazuh agent + FIM.** MAC randomizzato — verificare se fisso o rotante. |
| END-06 | MacBook-Air-di-Nicole.local | MacBook Air Nicole | 192.168.68.75 | 38:F9:D3:BF:FE:65 | macOS | Modello da confermare (Apple MAC confermato) |

### 1.3 NAS / Storage

| ID | Hostname | Tipo | IP | MAC | Note |
|---|---|---|---|---|---|
| NAS-01 | MyCloud-2J1F4P.local | WD My Cloud Home | 192.168.68.90 → **reservation .90** | 00:00:C0:44:A4:97 | Cloud-first by design: connessione ai server WD non disabilitabile. **2FA account WD abilitato ✅ (11/04/2026).** Porta 80 aperta (web UI LAN). |

### 1.4 IoT — Robot Vacuum

| ID | Hostname | Tipo | IP | MAC | Note |
|---|---|---|---|---|---|
| IOT-01 | robot dreame | Dreame Robot Vacuum | 192.168.68.53 | 70:C9:32:2F:90:05 | ⚠️ Beaconing attivo (15↓ / 6↑ kbps). Traffico cloud cinese. |
| IOT-02 | NARWAL_f90d1d.local | Narwal Robot | 192.168.68.70 | 80:9D:65:2C:D8:13 (FN-LINK) | Stesso profilo rischio Dreame. Traffico cloud cinese. FN-LINK = modulo Wi-Fi interno Narwal. |
| IOT-03a | — | Roborock A15 (casa) | 192.168.68.77 | B0:4A:39:1B:84:CD (Beijing Roborock) | Casa. |
| IOT-03b | — | Roborock (negozio) | 192.168.68.101 | B0:4A:39:0A:61:37 (Beijing Roborock) | Negozio Sesto San Giovanni. |

### 1.5 IoT — Telecamere

| ID | Hostname | Tipo | IP | MAC | Note |
|---|---|---|---|---|---|
| CAM-01 | — | TP-Link Tapo | 192.168.68.84 | CC:BA:BD:79:E7:65 (TP-Link) | Cloud TP-Link. Porta 80 aperta. |
| CAM-02 | — | Ezviz (Hangzhou Ezviz) | 192.168.68.52 | 0C:A6:4C:52:89:81 | Telecamera Ezviz confermata. Cloud Ezviz/Hikvision. |
| CAM-03 | — | Ezviz / Dahua | 192.168.68.94 | 54:D6:0D:F0:6F:EB (Hangzhou Ezviz) | Seconda Ezviz. Porte 80/443 aperte. |
| CAM-04 | — | Dahua OEM | 192.168.68.96 | 14:A7:8B:CE:F0:63 (Zhejiang Dahua) | Ezviz è sussidiaria Dahua — device Dahua/Ezviz branded. Porta 80 aperta. |
| CAM-05 | — | Netgear Arlo base station | 192.168.68.95 | 08:02:8E:A3:DD:DC (NETGEAR) | Base station Arlo. Cloud Arlo. Porta 80 aperta. |
| CAM-06 | — | NVR locale (negozio) | TBD | TBD | Ethernet. Storage locale. Negozio. |
| CAM-07 | — | Google Nest Hub (camera integrata) | DHCP | — | Cloud Google, camera integrata. |

### 1.6 IoT — Climatizzazione

| ID | Hostname | Tipo | IP | Firmware | Note |
|---|---|---|---|---|---|
| CLIM-01 | termostato primo piano | Google Nest Learning 3a gen | DHCP | Ultimo disponibile | Aggiornamenti automatici Google. Profilo rischio contenuto. |
| CLIM-02 | termostato piano terra | Google Nest Learning 3a gen | DHCP | Ultimo disponibile | Come CLIM-01. |
| CLIM-03 | Samsung-Room-AC (×2) | Samsung AC | DHCP | TBD | SmartThings cloud. Due unità. |

### 1.7 IoT — Automazione

| ID | Hostname | Tipo | IP | MAC | Note |
|---|---|---|---|---|---|
| AUTO-01 | Shelly2PMG3-E4B3232B99FC.local | Shelly Plus 2PM Gen3 | 192.168.68.89 | E4:B3:23:2B:99:FC (Espressif) | Conferma modello da hostname. Doppio relay con power monitoring. Cloud Shelly disabilitato — **auth UI web non abilitata per mantenere compatibilità controllo locale** (rischio R-15 accettato). Porta 80 aperta. |
| AUTO-02 | SAMJIN (×3) | Samsung SmartThings hub + device | 192.168.68.80, .81, .82 | 28:6D:97:D5:0E:C9, 28:6D:97:D5:42:09, 28:6D:97:D0:FB:FE | Bridge Zigbee/Z-Wave → cloud Samsung. Tre device SmartThings sulla rete. |
| AUTO-03 | — | Wisol IoT module | 192.168.68.83 | 70:2C:1F:49:15:72 (Wisol) | Modulo embedded — identificare device host fisicamente. |
| AUTO-04 | ESP_EF1867 | Luce smart sala (Espressif/Tuya) | 192.168.68.51 | 40:F5:20:EF:18:67 (Espressif) | **Identificato (11/04/2026): luce smart sala.** Modulo Espressif ESP8266/ESP32, probabilmente Tuya-compatibile. Profilo rischio assimilabile agli altri device Tuya in rete (.61, .85). R-11 chiuso. |

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

| ID | Hostname | Tipo | IP | MAC | Connessione | Note |
|---|---|---|---|---|---|---|
| NEG-01 | — | PAX Computer — terminale POS #1 | 192.168.68.64 | A0:44:B7:17:84:62 (PAX Computer) | Ethernet | 🔴 Asset critico. Hardware POS PAX. Gestisce pagamenti. Flat network. |
| NEG-02 | — | PAX Computer — terminale POS #2 | 192.168.68.67 | A0:44:B7:4E:27:10 (PAX Computer) | Ethernet | 🔴 Asset critico. Secondo terminale PAX. Dati carte. Flat network. |
| NEG-03 | android-5edd2163d46e6f51 | POS mobile negozio (Android) | DHCP | TBD | WiFi | 🔴 **Identificato (11/04/2026): POS mobile negozio.** Presente durante orario di apertura. |

### 1.11 Server HomeSOC (pianificato — non ancora deployato)

| ID | Hostname | Tipo | IP Target | OS | Ruolo |
|---|---|---|---|---|---|
| SOC-01 | homesoc | GMKtec M5 Ultra · Ryzen 7 7730U · 32GB | 192.168.68.200 (DHCP reservation — da configurare dopo collegamento hardware) | Proxmox VE | Hypervisor per tutte le VM del progetto |

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

**Controlli previsti:** SSH hardening (no root login, solo chiavi pubbliche), **CrowdSec cs-firewall-bouncer** (blocco attivo IP brute force via nftables), snapshot Proxmox automatici, accesso solo LAN, Tailscale per accesso remoto.

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
| R-01 | IOT-01, IOT-02 (Robot cinesi) | Information Disclosure — beaconing cloud cinese | 3 | 2 | **ALTO (6)** | NextDNS blocco IoC, VLAN IoT (OPNsense futuro), Wazuh alert | Fase 3 | **Parziale Mitigato** — NextDNS blocco attivo, Wazuh UC-02 (rule 100010) operativo. VLAN posticipato a OPNsense. |
| R-02 | END-05 (MacBook) | Elevation of Privilege — malware, lateral movement | 2 | 3 | **ALTO (6)** | Wazuh agent macOS, FIM home dir, ClamAV | Fase 3 | **Parziale Mitigato** — Wazuh agent END-05 attivo, FIM UC-03 (rule 100020/100023) operativo, alert Slack attivi. ClamAV non ancora deployato. |
| R-03 | NEG-01, NEG-02 (POS/Cassa) | Tampering — malware POS, RAM scraper | 2 | 3 | **ALTO (6)** | Greenbone scan, Wazuh monitoring | Fase 2 | Aperto |
| R-04 | NEG-01, NEG-02 (POS/Cassa) | Denial of Service — interruzione attività negozio | 2 | 3 | **ALTO (6)** | Greenbone scan, Uptime Kuma | Fase 2 | Aperto |
| R-05 | NEG-01, NEG-02 (POS/Cassa) | Lateral Movement da IoT su rete flat | 2 | 3 | **ALTO (6)** | Isolamento VLAN con OPNsense + switch managed | Futuro | Posticipato — hardware insufficiente |
| R-06 | NAS-01 (WD My Cloud Home) | Information Disclosure — account WD compromesso | 2 | 3 | **ALTO (6)** | 2FA account WD, password robusta, monitoraggio Wazuh | Immediato | **Mitigato ✅ — 2FA abilitato 11/04/2026** |
| R-07 | CAM-01→07 (Telecamere) | Information Disclosure — stream video verso cloud | 2 | 3 | **ALTO (6)** | Blocco internet telecamere (OPNsense futuro), firmware aggiornato | Futuro | Posticipato |
| R-08 | END-05 (MacBook) | Information Disclosure — keylogger/screen capture | 2 | 3 | **ALTO (6)** | Wazuh agent, FIM, controllo processi | Fase 3 | **Parziale Mitigato** — FIM UC-03 operativo, alert Slack attivi su modifiche file critici. Controllo processi non ancora implementato. |
| R-09 | SOC-01 (Server HomeSOC) | Tampering — compromissione server monitoring | 1 | 3 | **MEDIO (3)** | SSH hardening, no root, fail2ban, snapshot Proxmox | Fase 2 | Aperto |
| R-10 | SOC-01 (Server HomeSOC) | Elevation of Privilege — accesso SSH non autorizzato | 1 | 3 | **MEDIO (3)** | Chiavi pubbliche only, CrowdSec cs-firewall-bouncer | Fase 3 | **Mitigato ✅ — CrowdSec attivo su SOC-01: blocco IP via nftables + detection Wazuh UC-01 (rule 100051, level 10, T1110.001). Pipeline CrowdSec → rsyslog → Wazuh verificata in produzione (21/04/2026).** |
| R-11 | AUTO-04 (ESP_EF1867) | Spoofing / Info Disclosure — device non identificato | 2 | 2 | **MEDIO (4)** | Identificazione fisica MAC OUI, analisi traffico Wazuh | Immediato | **Chiuso — identificato: luce smart sala (Espressif/Tuya). Rischio residuo assimilato a Tuya cloud (cfr. R-01).** |
| R-12 | IOT-01, IOT-02 (Robot cinesi) | Tampering — firmware OTA compromesso | 1 | 3 | **MEDIO (3)** | Blocco OTA automatici via DNS, monitoraggio | Fase 3 | Aperto |
| R-13 | CAM-01→07 (Telecamere) | Tampering — firmware OTA compromesso | 1 | 3 | **MEDIO (3)** | Firmware aggiornato manualmente | Fase 3 | Aperto |
| R-14 | NEG-01, NEG-02 (POS/Cassa) | Repudiation — assenza log centralizzati | 2 | 2 | **MEDIO (4)** | Wazuh log centralizzati post-deploy | Fase 3 | Aperto — Wazuh manager operativo, agent MacBook (END-05) enrollato. Enrollment agenti POS/Cassa pianificato Fase 3. |
| R-15 | AUTO-01 (Shelly) | Elevation of Privilege — controllo fisico dispositivi | 1 | 2 | **BASSO (2)** | Nessun cloud Shelly, auth UI web non abilitata (compatibilità) | Immediato | **Accettato — auth web disabilitata per mantenere controllo locale. Mitigazione futura: VLAN IoT con OPNsense.** |
| R-16 | CLIM-01, CLIM-02 (Nest Learning) | Information Disclosure — dati abitudini verso Google | 2 | 1 | **BASSO (2)** | Account Google con 2FA | Immediato | **Mitigato ✅ — 2FA Google confermato 11/04/2026** |
| R-17 | INF-01→05 (Deco mesh) | Spoofing — DNS poisoning | 1 | 2 | **BASSO (2)** | NextDNS DoH, DNSSEC | Immediato | **Parziale — Deco BE65 non supporta DoH a livello router (firmware con DoH in beta). DoH attivo solo su device con profilo NextDNS diretto. DNSSEC attivo. Rivalutare a firmware rilasciato.** |

### 3.1 Riepilogo per priorità

| Priorità | Rischi | Asset principali |
|---|---|---|
| 🔴 ALTO (6+) | R-01, R-02, R-03, R-04, R-05, R-06, R-07, R-08 | Robot IoT, MacBook, POS/Cassa, NAS, Telecamere |
| 🟡 MEDIO (3-4) | R-09, R-10, R-11, R-12, R-13, R-14 | Server SOC, ESP custom, firmware IoT, log negozio |
| 🟢 BASSO (1-2) | R-15, R-16, R-17 | Shelly, Nest, DNS |

### 3.2 Azioni immediate (pre-deployment) — stato aggiornato

| Rischio | Azione | Stato |
|---|---|---|
| R-06 | Abilitare 2FA su account WD My Cloud Home | ✅ Completato 11/04/2026 |
| R-11 | Identificare ESP_EF1867 tramite MAC OUI lookup + ispezione fisica | ✅ Completato — luce smart sala (Espressif/Tuya) |
| R-15 | Auth UI web Shelly abilitata, cloud disabilitato | **Accettato** — auth web non abilitata per compatibilità controllo locale |
| R-16 | Verificare 2FA su account Google (per i Nest) | ✅ Confermato 11/04/2026 |
| R-17 | Confermare NextDNS DoH attivo | **Parziale** — Deco BE65 non supporta DoH a livello router (firmware beta in arrivo) |
| TODO-3 | DHCP lease table per IP inventory completo | ✅ Completato — CSV integrato in v1.2 |

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
- WD My Cloud Home è cloud-first by design — relay WD non disabilitabile. Unico controllo possibile: sicurezza account (2FA abilitato ✅).
- Deco BE65 non supporta DoH a livello router — aggiornamento firmware con DoH in beta. R-17 parzialmente mitigato.
- IP DHCP completati da scan ARP CSV (11/04/2026). Alcuni device con MAC randomizzato (es. END-05 C6:... — MAC potenzialmente rotante su iOS/macOS, verificare se privacy MAC è attivo).

### TODO — prossimi aggiornamenti

| # | Azione | Rischio | Priorità | Stato |
|---|---|---|---|---|
| 1 | Abilitare 2FA su account WD My Cloud Home | R-06 | Alta | ✅ Completato |
| 2 | Identificare ESP_EF1867 | R-11 | Alta | ✅ Completato |
| 3 | Completare colonne IP/MAC con DHCP lease table Deco | Tutti | Media | ✅ Completato (CSV v1.2) |
| 4 | Identificare device host modulo Wisol (AUTO-03) | — | Media | Da completare |
| 5 | Verificare se privacy MAC è attivo su MacBook Pro (END-05) — il MAC C6:A3:2A:A3:A8:0F potrebbe essere randomizzato | END-05 | Media | Da verificare |
| 6 | Configurare DHCP reservation sul Deco: NAS → .90, MacBook → .108, SOC-01 → .200 (dopo collegamento hardware) | — | Alta | .90 e .108 da fare; .200 dopo hardware |
| 7 | Rivalutare R-17 dopo rilascio firmware Deco con DoH | R-17 | Bassa | Pending firmware |
| 8 | Aggiornare stato rischi a ogni nuova fase di deployment | Tutti | Ongoing | — |

**Commit:** `git add docs/01-threat-model.md && git commit -m "docs(threat-model): update vX.Y — <motivo>"`

---

*File: `docs/01-threat-model.md` · v1.4 · Aprile 2026*
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
