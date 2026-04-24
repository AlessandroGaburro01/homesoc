# Advanced Detection — Analisi dei Limiti e Roadmap Estensioni
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `docs/advanced-detection-analysis.md`  
**Versione:** 1.0 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Tipo documento:** Analisi tecnica — Scoping

> Questo documento analizza i limiti strutturali del HomeSOC rispetto ad attori avanzati, classifica le estensioni possibili per livello di complessità e definisce quali rientrano nello scope del progetto e quali no. Serve sia come riferimento tecnico che come dimostrazione della consapevolezza metodologica richiesta in un contesto Blue Team professionale.

**Changelog:**
- v1.0 — Aprile 2026 — Prima stesura post-analisi threat landscape avanzato

---

## Indice

1. [Premessa — Modello di Minaccia Avanzato](#1-premessa--modello-di-minaccia-avanzato)
2. [Perché un Attore State-Level è Invisibile](#2-perché-un-attore-state-level-è-invisibile)
3. [Segnali Residui — Cosa Potrebbe Emergere](#3-segnali-residui--cosa-potrebbe-emergere)
4. [Estensioni — Livello 1 (già in scope)](#4-estensioni--livello-1-già-in-scope)
5. [Estensioni — Livello 2 (avanzamento realistico)](#5-estensioni--livello-2-avanzamento-realistico)
6. [Estensioni — Livello 3 (limite superiore home lab)](#6-estensioni--livello-3-limite-superiore-home-lab)
7. [Fuori Scope — Motivazione Tecnica](#7-fuori-scope--motivazione-tecnica)
8. [Matrice di Priorità](#8-matrice-di-priorità)
9. [Conclusioni](#9-conclusioni)

---

## 1. Premessa — Modello di Minaccia Avanzato

Il threat model del HomeSOC (vedi `01-threat-model.md`) è calibrato su attori realistici per il contesto domestico/negozio: script kiddie, ransomware opportunistico, credential stuffing, vulnerabilità firmware IoT non patchate.

Questo documento estende l'analisi a un livello superiore: **attori state-level o APT (Advanced Persistent Threat)**, con l'obiettivo di:

1. Documentare i limiti strutturali dello stack attuale con rigore tecnico
2. Identificare le estensioni che aumentano genuinamente la visibilità senza stravolgere lo scope
3. Definire con chiarezza cosa è fuori portata e perché — una competenza essa stessa rilevante per il portfolio

> **Nota metodologica:** la capacità di definire i limiti del proprio sistema di detection è una skill Blue Team di livello senior. Un SOC analyst che non sa dove finisce la visibilità del proprio SIEM è più pericoloso di uno che non ne ha uno — genera falsa sicurezza.

---

## 2. Perché un Attore State-Level è Invisibile

### 2.1 Operano sotto il detection threshold

Wazuh e CrowdSec lavorano su pattern noti e su anomalie di volume: brute force, port scan, spike di traffico. Un APT statale non genera nessuno di questi segnali. Si muove lentamente — una connessione ogni ore o giorni — dentro protocolli legittimi (HTTPS, DNS, SMB). Nessuna soglia scatta. Nessuna regola fa match.

**Contromisura teorica:** baseline comportamentale su lunghissimo periodo + ML per anomalie statistiche (out of scope per home lab, richiede settimane di dati e infrastruttura dedicata).

### 2.2 0-day e implant firmware

Se l'accesso avviene tramite vulnerabilità sconosciuta nel router, nel firmware della NAS WD, o nel chipset di rete, l'impianto esiste **sotto il livello OS** dove gira l'agente Wazuh. Il malware non appare nei processi, non tocca i log, non è visibile agli strumenti che operano a livello applicativo.

Esempi documentati: NSA ANT Catalog (BIOS/firmware implant), Equation Group, impianti su hardware di rete Cisco e Juniper.

**Contromisura teorica:** Secure Boot con TPM attestation, verifica firma firmware a livello hardware. Praticamente non implementabile su hardware consumer.

### 2.3 Living Off the Land (LotL)

Un APT sofisticato non porta i propri strumenti — usa quelli già presenti nel sistema: PowerShell, cron, systemd, OpenSSH, Python, curl. Dal punto di vista dei log, ogni singola operazione appare come attività legittima dell'amministratore.

**Contromisura teorica:** EDR con kernel-level telemetry che analizza l'intera catena di esecuzione (parent process, syscall, memory injection) — non solo il processo singolo. Wazuh FIM copre solo le modifiche a file su disco.

### 2.4 Esfiltrazione su canali rumorosi

Dati esfiltrati dentro traffico HTTPS verso Google, AWS, Cloudflare o qualsiasi CDN sono indistinguibili dal traffico legittimo. Anche il volume può essere distribuito nel tempo per non superare nessuna soglia.

**Contromisura teorica:** DPI (Deep Packet Inspection) + analisi statistica del traffico aggregato. Richiede visibilità full-netflow, non solo log applicativi.

### 2.5 Compromissione dei tool di monitoring

Un attore sufficientemente sofisticato può compromettere l'agente Wazuh stesso, modificando cosa viene riportato al manager. A quel punto il SIEM è strutturalmente cieco su se stesso — gli alert che non arrivano non generano nessun indicatore di anomalia.

**Contromisura teorica:** out-of-band monitoring tramite TAP fisico sul link WAN, analizzato da un sistema completamente separato e non raggiungibile dall'interno della rete monitorata.

### 2.6 Riepilogo — Tabella dei gap strutturali

| Vettore | Perché invisibile allo stack attuale | Categoria gap |
|---|---|---|
| Movimento lento / basso volume | Sotto soglia detection rules Wazuh/CrowdSec | **Threshold** |
| Impianto firmware / BIOS | Opera sotto il livello OS dell'agente | **Visibility layer** |
| Living Off the Land | Strumenti legittimi, log indistinguibili | **Context** |
| Esfiltrazione HTTPS | Traffico cifrato su canali rumorosi legittimi | **Protocol** |
| Compromissione agente SIEM | Il monitoring non può monitorare se stesso | **Trust boundary** |

---

## 3. Segnali Residui — Cosa Potrebbe Emergere

Anche gli attori più sofisticati commettono errori operativi. Lo stack attuale potrebbe captare segnali molto flebili in questi scenari:

| Segnale | Come potrebbe emergere | Probabilità rilevamento |
|---|---|---|
| **Domain Generation Algorithm (DGA)** | NextDNS threat intel flaggerebbe query verso domini generati algoritmicamente | Bassa — solo DGA già noti |
| **Beacon C2 periodico preciso** | Pattern a intervalli regolari rilevabile con analisi statistica del traffico — ma richiede NetFlow, non solo log | Molto bassa |
| **Anomalie volume notturno** | Esfiltrazione massiva lascia traccia nel traffico aggregato se si ha una baseline oraria robusta | Bassa — soglia alta, molti falsi negativi |
| **Canary token attivato** | Se l'attore accede a un file esca con token univoco, il callback è rilevamento garantito indipendentemente dalla sofisticazione | **Alta** — unica eccezione affidabile |
| **FIM su file di sistema critici** | Wazuh FIM rileva modifiche a `/etc/passwd`, crontab, binari di sistema — se l'attore non disabilita l'agente prima | Media |

---

## 4. Estensioni — Livello 1 (già in scope)

Lo stack attuale copre il threat landscape opportunistico con buona efficacia.

| Componente | Stato | Cosa copre |
|---|---|---|
| CrowdSec | ✅ Operativo | Brute force, scan noti, IP reputation |
| Wazuh SIEM | ✅ Operativo | Log correlation, FIM, SCA, alerting |
| Greenbone CE | ✅ Operativo | Vulnerability assessment periodico |
| NextDNS | ✅ Operativo | DNS filtering, IoC noti, DoH |
| Wazuh Active Response | ✅ Operativo | Blocco automatico IP su regola |
| Uptime Kuma | ✅ Operativo | Availability monitoring |

**Limite superiore del Livello 1:** attore opportunistico con strumenti standard, malware da commodity market, credential stuffing. Copertura stimata: buona contro ~95% del threat landscape reale su una rete domestica.

---

## 5. Estensioni — Livello 2 (avanzamento realistico)

Queste estensioni sono **implementabili sul hardware attuale** (Proxmox, 32 GB RAM), aumentano genuinamente la visibilità su attori più avanzati e hanno alto valore di portfolio.

### 5.1 Honeypot interno — OpenCanary

**Cosa fa:** deploya servizi fake (SSH, SMB, HTTP, FTP, MySQL, RDP) che non dovrebbero mai ricevere traffico legittimo. Qualsiasi connessione è per definizione un alert ad alta fedeltà — zero falsi positivi strutturali.

**Valore detection:** copre il **lateral movement interno**, che è uno dei segnali più affidabili di compromissione avanzata. Un attore che si muove nella rete prima o poi tenta di raggiungere un servizio che non conosce.

**Come:** LXC container leggero su Proxmox. OpenCanary è un daemon Python con overhead minimo.

**Integrazione:** log OpenCanary → Wazuh via syslog → alert Slack esistente.

**Effort:** basso.  
**Valore portfolio:** molto alto — threat deception è una competenza rara a livello home lab.

**Runbook:** da creare (`opencanary-deploy.md`).

---

### 5.2 Canary Token / Honeyfile

**Cosa fa:** file esca (PDF, documento Word, foglio Excel, credenziale fake) con token univoco incorporato. Se il file viene aperto su qualsiasi dispositivo connesso a internet, genera un callback HTTP verso canarytokens.org con IP sorgente, user-agent e timestamp.

**Valore detection:** rileva accesso al filesystem indipendentemente dalla sofisticazione dell'attore. Un APT che esplora il filesystem di un endpoint toccherà un honeyfile prima o poi — è l'unico meccanismo di detection affidabile ad alta fedeltà contro attori avanzati implementabile in home lab.

**Come:** canarytokens.org (gratuito, zero infrastruttura). Piazzare file su: NAS (MyCloud), desktop MacBook, cartelle condivise.

**Naming consigliato:** nomi che invogliano l'apertura — `Credenziali_Servizi_2026.xlsx`, `VPN_Config_Backup.pdf`, `SSH_Keys_Export.docx`.

**Effort:** zero.  
**Valore portfolio:** dimostrativo immediato di threat deception thinking.

---

### 5.3 Network Traffic Analysis — Zeek

**Cosa fa:** analizza il traffico di rete a livello **comportamentale**, non solo a firma. Genera log strutturati su: connessioni TCP/UDP, query DNS, handshake TLS (metadati, non contenuto), file transfer, credenziali in chiaro, beacon periodici.

**Valore detection:** copre il gap di visibilità più grande dello stack attuale — il traffico di rete. Wazuh vede solo i log degli applicativi; Zeek vede ogni pacchetto che attraversa l'interfaccia monitorata.

**Cosa rileva in più rispetto allo stack attuale:**
- Beacon C2 a intervalli regolari (pattern statistico sul traffico)
- Connessioni TLS verso certificati auto-firmati o con JA3 fingerprint sospetto
- Esfiltrazione via DNS (query anomale per lunghezza o frequenza)
- Lateral movement interno tra host
- Utilizzo di protocolli inusuali

**Come:** VM leggera (2 vCPU, 4 GB RAM) su Proxmox + port mirroring. Il Deco BE65 non supporta port mirroring hardware — alternativa: bridge software su Proxmox con interfaccia promiscua, o TAP fisico passivo sul link verso il modem Zyxel.

**Integrazione:** log Zeek → Wazuh (decoder JSON) → regole custom.

**Effort:** medio-alto. Richiede gestione del port mirroring e tuning per ridurre il rumore.  
**Valore portfolio:** il salto qualitativo più significativo per la visibilità complessiva del progetto.

**Runbook:** da creare (`zeek-deploy.md`).

---

### 5.4 Suricata IDS

**Cosa fa:** IDS signature-based con ruleset Emerging Threats (open source). Complementare a Zeek: mentre Zeek analizza comportamenti, Suricata matcha pattern noti di exploit, C2, malware documentati.

**Come:** affiancato a Zeek sulla stessa VM, oppure nativamente integrato in OPNsense quando verrà deployato. Su OPNsense è incluso di default e richiede solo attivazione del ruleset.

**Effort:** basso se deployato su OPNsense (futuro), medio se su VM standalone oggi.  
**Valore portfolio:** standard de facto negli ambienti SOC — dimostra familiarità con IDS operativo.

---

### 5.5 Wazuh FIM e SCA — Completamento

**Cosa fa:** File Integrity Monitoring monitora modifiche a file e directory critiche (binari di sistema, crontab, configurazioni). System Configuration Assessment verifica continuamente il livello di hardening rispetto a benchmark CIS.

**Stato attuale:** FIM attivo su END-05 (MacBook) per UC-03. SCA non configurato sistematicamente su tutti gli agenti.

**Estensione:** attivare FIM su vm-103 e SOC-01 per percorsi critici (`/etc/`, `/usr/bin/`, `/lib/systemd/`). Configurare SCA con profilo CIS Level 1 su tutti gli host Linux.

**Effort:** basso — tutto dentro Wazuh, nessun tool aggiuntivo.  
**Valore detection:** rileva persistence via cron/systemd, modifica di binari di sistema, aggiunta di chiavi SSH autorizzate non previste.

---

## 6. Estensioni — Livello 3 (limite superiore home lab)

Queste estensioni richiedono hardware aggiuntivo, configurazioni più complesse o conoscenze specialistiche, ma rimangono nel dominio del "home lab avanzato" e rappresentano il confine superiore ragionevole del progetto.

### 6.1 OPNsense + NetFlow + Suricata integrato

**Perché è un salto di livello:** OPNsense trasforma la visibilità dell'intera rete. Abilita VLAN reali (prerequisito per R-05 e R-07), Suricata integrato su tutti i flussi, NetFlow verso Wazuh, blocco geografico, e gestione centralizzata delle policy di rete.

**NetFlow verso Wazuh:** consente l'analisi del traffico aggregato per volume, destinazione e protocollo — base per rilevare esfiltrazione lenta e beacon C2.

**Prerequisiti:** hardware con almeno due interfacce di rete (mini PC aggiuntivo o scheda PCIe), o deploy in VM con NIC passthrough.

**Stato nel progetto:** pianificato per casa nuova (Fase FUTURO). Prerequisito per rischi R-05 e R-07.

---

### 6.2 MITRE ATT&CK Mapping — Wazuh

**Cosa fa:** mappa ogni detection rule Wazuh a una tattica e tecnica della matrice MITRE ATT&CK. Wazuh ha integrazione nativa tramite il campo `mitre` nelle regole XML.

**Valore:** trasforma il SIEM da "vedo log" a "vedo comportamenti avversariali classificati". Consente di visualizzare la copertura del proprio detection stack sulla matrice ATT&CK e identificare i gap tattici.

**Come:** aggiungere tag `<mitre>` alle regole custom esistenti (già sviluppate nelle fasi precedenti). La dashboard Wazuh mostra automaticamente la copertura.

**Effort:** medio — richiede classificazione manuale di ogni regola, ma nessun tool aggiuntivo.  
**Valore portfolio:** enorme — dimostra pensiero strategico oltre la detection tattica. È il tipo di output che si presenta in un colloquio Blue Team senior.

---

### 6.3 Memory Forensics periodico — Volatility

**Cosa fa:** analisi della memoria RAM di una VM per rilevare injection di processo, hook su system call, processi nascosti, moduli kernel non autorizzati.

**Come:** non continuous monitoring, ma analisi periodica o post-incident. Snapshot RAM di una VM da Proxmox → trasferimento → Volatility 3 su macchina di analisi separata.

**Valore:** dimostra capability forense — analisi di memoria è una skill difensiva di livello avanzato, raramente praticata in home lab. Rileva la classe di malware (rootkit, process injection) che è completamente invisibile ai log applicativi.

**Effort:** medio — richiede setup iniziale di Volatility e familiarità con i profili OS.

---

### 6.4 Threat Intelligence Feed — OpenCTI

**Stato nel progetto:** già pianificato come Fase 4 (L5 della security stack). OpenCTI con feed STIX/TAXII consente la correlazione di IoC osservati nella rete con threat intelligence globale.

**Valore aggiunto rispetto al Livello 2:** da "ho visto questa connessione" a "questa connessione è associata al gruppo APT-X documentato in questo report MISP".

---

## 7. Fuori Scope — Motivazione Tecnica

Queste misure sono tecnicamente valide ma **non implementabili** nel contesto HomeSOC per ragioni strutturali, non di competenza.

| Misura | Perché fuori scope | Categoria limite |
|---|---|---|
| **Rilevamento impianti firmware/BIOS** | Richiede hardware specializzato (bus analyzer, firmware extractor), accesso fisico costante, competenze in reverse engineering firmware | Hardware + specializzazione |
| **EDR commerciale kernel-level** (CrowdStrike, SentinelOne) | Costo licenze (migliaia €/anno), telemetria proprietaria non integrabile liberamente, dipendenza da infrastruttura cloud vendor | Costo + dipendenza vendor |
| **Difesa contro 0-day attivi** | Per definizione non esiste signature per una vulnerabilità sconosciuta. Detection possibile solo su comportamento post-exploitation (coperto parzialmente da FIM + honeypot) | Limite strutturale |
| **Ispezione traffico TLS 1.3** | TLS 1.3 con Perfect Forward Secrecy rende impossibile l'ispezione inline senza MitM certificato. MitM su traffico domestico è eticamente e legalmente complesso, e degrada la sicurezza degli endpoint | Protocollo + etica |
| **Protezione supply chain hardware** | Richiederebbe canali di approvvigionamento verificati, audit fisico dei componenti, accesso a database di contraffazione. Non applicabile a hardware consumer | Contesto |
| **Out-of-band monitoring fisico** (TAP hardware dedicato) | Richiede hardware TAP passivo (€200-500), NIC aggiuntiva, sistema di analisi separato fisicamente isolato dalla rete monitorata | Hardware + architettura |

> **Nota:** la chiarezza su questi limiti non è una debolezza del progetto — è una dimostrazione di maturità metodologica. Un SOC analyst che sa dove finisce la visibilità del suo sistema vale più di uno che sopravvaluta le proprie capability.

---

## 8. Matrice di Priorità

Classificazione delle estensioni per impatto su detection e valore di portfolio, ordinata per priorità di implementazione.

| Priorità | Estensione | Effort | Detection gain | Portfolio value | Prerequisiti |
|---|---|---|---|---|---|
| 🥇 1 | Canary Token / Honeyfile | Zero | Alto (unico detection affidabile vs APT) | Alto | Nessuno |
| 🥇 2 | OpenCanary — Honeypot | Basso | Alto (lateral movement) | Molto alto | LXC su Proxmox |
| 🥈 3 | Wazuh FIM + SCA — completamento | Basso | Medio (persistence, hardening gap) | Medio | Wazuh già operativo |
| 🥈 4 | MITRE ATT&CK mapping Wazuh | Medio | Nessuno (classificazione) | Molto alto | Regole custom esistenti |
| 🥉 5 | Zeek NTA | Medio-alto | Molto alto (traffico di rete) | Alto | Port mirroring o TAP |
| 🥉 6 | Suricata IDS (standalone) | Medio | Medio (firme note) | Medio | VM + visibilità rete |
| 🔮 Futuro | OPNsense + NetFlow + Suricata | Alto | Molto alto (rete completa) | Molto alto | Hardware aggiuntivo |
| 🔮 Futuro | MITRE ATT&CK Navigator — coverage map | Medio | Nessuno (visualizzazione) | Alto | ATT&CK mapping completato |
| 🔮 Futuro | Volatility — memory forensics | Medio | Alto (rootkit, injection) | Alto | Snapshot RAM Proxmox |
| 🔮 Futuro | OpenCTI + feed STIX/TAXII | Alto | Alto (threat intel) | Molto alto | Fase 4 pianificata |

---

## 9. Conclusioni

### Cosa il HomeSOC può realisticamente rilevare

Lo stack attuale, completato con le estensioni di Livello 2, fornisce **protezione reale e misurabile** contro:
- Attori opportunistici (script kiddie, ransomware commodity, credential stuffing)
- Lateral movement interno nella LAN (honeypot)
- Modifica non autorizzata di file di sistema (FIM)
- Accesso a file esca su endpoint e NAS (canary token)
- Vulnerabilità note su asset critici (Greenbone)
- Brute force e IP malevoli noti (CrowdSec + Wazuh)

### Cosa rimane strutturalmente fuori portata

Un attore state-level con risorse significative, che opera lentamente su canali legittimi, con strumenti del sistema operativo, è **non rilevabile** con qualsiasi stack home lab — e probabilmente con la maggior parte degli stack enterprise non dedicati. La difesa in quel contesto si chiama OPSEC (Operational Security), non detection.

### Perché questa analisi è parte del portfolio

Definire i limiti del proprio sistema di detection con rigore tecnico è una competenza Blue Team di livello senior. Un candidato che sa dove finisce la visibilità del proprio SIEM, perché finisce, e quali sarebbero le contromisure teoriche corrette — dimostra una comprensione del threat landscape che va ben oltre la configurazione di strumenti.

---

**Commit:** `git add docs/advanced-detection-analysis.md && git commit -m "docs(analysis): add advanced-detection-analysis v1.0 — limiti strutturali e roadmap estensioni"`

---

*File: `docs/advanced-detection-analysis.md` · v1.0 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
