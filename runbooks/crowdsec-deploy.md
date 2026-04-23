# Runbook — CrowdSec Deploy su SOC-01 (Host Proxmox)
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `runbooks/crowdsec-deploy.md`  
**Versione:** 1.0 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 3 — SIEM & Detection  
**Prerequisito:** `runbooks/wazuh-deploy.md` completato — vm-103 operativa, Wazuh Manager attivo su `192.168.68.204`

> **Scopo:** Installare e configurare CrowdSec direttamente sull'host Proxmox (SOC-01, `192.168.68.200`) come sistema di Intrusion Prevention collaborativo. CrowdSec protegge SSH su SOC-01, le dashboard di Wazuh e Proxmox Web UI, e invia gli alert di blocco a Wazuh via syslog per centralizzare la visibilità. Al termine di questo runbook SOC-01 deve bloccare automaticamente gli IP che tentano brute force SSH, la blocklist globale CrowdSec Hub deve essere attiva, e ogni decisione di blocco deve generare un alert in Wazuh Dashboard.

> **Nota di deployment:** CrowdSec gira direttamente sull'**host Proxmox**, non in una VM o LXC dedicata. Questa scelta è intenzionale: il bouncer opera a livello iptables/nftables dell'host, dove può proteggere sia il servizio SSH del nodo stesso sia i servizi esposti attraverso le VM ospitate (Proxmox Web UI 8006, Wazuh Dashboard su vm-103).

**Changelog:**
- v1.0 — Aprile 2026 — Prima stesura
- v1.1 — Aprile 2026 — Fix post-deploy reale: percorso log CrowdSec, formato syslog RFC3164, decoder OS_Regex, regole Wazuh; aggiunte note Debian 13 e sezione troubleshooting estesa
- v1.2 — Aprile 2026 — Fix Debian 12 / OpenSSH moderno: rsyslog ISO 8601 → RFC 3164 (riga 60 rsyslog.conf), acquis.yaml multi-documento → acquis.d/ migration, parser sshd-session per OpenSSH ≥ 9.x (00-sshd-session-fix.yaml, onsuccess: continue); test end-to-end verificato con alert Slack rule 100051 level 10

---

## Indice

1. [Background — Modello CrowdSec vs Fail2ban](#1-background--modello-crowdsec-vs-fail2ban)
2. [Prerequisiti](#2-prerequisiti)
3. [Installazione CrowdSec Agent](#3-installazione-crowdsec-agent)
4. [Configurazione Collections](#4-configurazione-collections)
5. [Installazione cs-firewall-bouncer](#5-installazione-cs-firewall-bouncer)
6. [Threat Intelligence — Blocklist Hub](#6-threat-intelligence--blocklist-hub)
7. [Integrazione Wazuh — Pipeline CrowdSec → Syslog → Wazuh](#7-integrazione-wazuh--pipeline-crowdsec--syslog--wazuh)
8. [Verifica end-to-end](#8-verifica-end-to-end)
9. [Preparazione per esposizione futura](#9-preparazione-per-esposizione-futura)
10. [Backup e persistenza della configurazione](#10-backup-e-persistenza-della-configurazione)
11. [Verifica finale e checklist](#11-verifica-finale-e-checklist)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Background — Modello CrowdSec vs Fail2ban

> ℹ️ **Sezione didattica** — comprensione del modello prima della configurazione. Rilevante per il portfolio e per la presentazione del progetto.

### 1.1 Architettura CrowdSec

CrowdSec è composto da tre componenti distinti con responsabilità separate:

```
┌─────────────────────────────────────────────────────────┐
│                        SOC-01                           │
│                                                         │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────┐  │
│  │   PARSER    │    │     LAPI     │    │  BOUNCER  │  │
│  │  (scenario) │───▶│  (Local API) │───▶│ (iptables)│  │
│  └─────────────┘    └──────────────┘    └───────────┘  │
│        ▲                   │                            │
│        │             decisions                          │
│   log files          (ban/captcha)                      │
│  /var/log/auth.log         │                            │
│  /var/log/syslog           ▼                        │
│                    ┌──────────────┐                     │
│                    │  CrowdSec    │                     │
│                    │    Hub       │◀── Threat Intel     │
│                    │  (blocklist) │    globale          │
│                    └──────────────┘                     │
└─────────────────────────────────────────────────────────┘
```

| Componente | Ruolo | Analogia |
|---|---|---|
| **Agent** (crowdsec) | Legge i log, applica scenari, rileva comportamenti malevoli | Il "cervello" — capisce cosa sta succedendo |
| **LAPI** (Local API) | Mantiene il database delle decisioni (ban/unban), gestisce i bouncers | Il "registro" — chi è bannato e per quanto |
| **Bouncer** (cs-firewall-bouncer) | Applica le decisioni al firewall in tempo reale | Il "braccio" — esegue il blocco effettivo |
| **Hub** | Repository centrale di scenari, parser, collection e blocklist | Il "cloud intelligence" — feed collaborativo |

### 1.2 Differenze strutturali rispetto a Fail2ban

| Caratteristica | Fail2ban | CrowdSec |
|---|---|---|
| **Architettura** | Monolitica — analisi + blocco nello stesso processo | Modulare — agent separato da bouncer |
| **Linguaggio scenari** | Regex su log | YAML strutturato + Grok patterns |
| **Threat Intelligence** | Nessuna (locale only) | Blocklist collaborativa da milioni di istanze |
| **Multi-bouncer** | No — solo iptables integrato | Sì — stessa decisione applicata a più bouncer (fw, nginx, Cloudflare) |
| **API** | Nessuna | REST API locale + CrowdSec Central API (CAPI) |
| **Condivisione** | Nessuna — ogni installazione è isolata | Opt-in: i tuoi ban vengono condivisi, ricevi i ban degli altri |
| **Dashboard** | Nessuna nativa | CrowdSec Console (cloud) o visualizzazione locale |
| **Scenari comunità** | Da scrivere manualmente | Hub con centinaia di scenari mantenuti |

### 1.3 Rilevanza per UC-01

Nel threat model del progetto (sez. 6, `docs/02-architecture.md`), **UC-01** descrive il rischio di brute force SSH su SOC-01 (T1110.001 — Credential Access). L'architettura originale prevedeva fail2ban come risposta automatica. CrowdSec è la scelta architetturalmente superiore perché:

1. **Blocco proattivo** — gli IP già noti come malevoli a livello globale vengono bloccati *prima ancora* che tentino su SOC-01 (blocklist Hub)
2. **Detection più ricca** — lo scenario `crowdsecurity/ssh-bf` riconosce pattern di brute force più sofisticati del semplice conteggio regex di fail2ban
3. **Integrazione nativa Wazuh** — le decisioni CrowdSec vengono portate in Wazuh come alert strutturati, chiudendo il loop detection → response → visibilità
4. **Estensibilità** — quando si aggiungeranno servizi esposti (reverse proxy, VPN), basta aggiungere un bouncer senza riscrivere la logica

> **Nota tecnica — CAPI (Central API):** CrowdSec può condividere i tuoi ban e ricevere i ban della comunità tramite la CAPI cloud. In HomeSOC questa funzione è abilitata di default ma non critica — anche senza connettività CAPI le blocklist vengono aggiornate tramite `cscli hub update`. La disabilitazione è documentata in sez. 9 per chi preferisce un profilo zero-disclosure.

---

## 2. Prerequisiti

### 2.1 Verifica stato SOC-01

```bash
# Su SOC-01 (come root o con sudo)

# Verifica OS host Proxmox
cat /etc/debian_version
# Atteso: Debian 12.x (Proxmox 8.x)

uname -r
# Atteso: kernel 6.x

# Verifica connettività internet (per download pacchetti)
curl -s https://packagecloud.io/crowdsec/crowdsec/gpgkey | head -1
# Atteso: -----BEGIN PGP PUBLIC KEY BLOCK-----

# Verifica che il servizio SSH sia attivo (target di protezione primario)
systemctl is-active ssh
# Atteso: active

# Verifica log SSH disponibili
# NOTA Debian 13 (Trixie): /var/log/auth.log non esiste — i log SSH
# vanno nel journal di sistema. CrowdSec legge da journalctl (vedi sez. 4.3)
journalctl _SYSTEMD_UNIT=ssh.service --no-pager -n 5
# Atteso: righe con sshd — se vuoto, SSH non ha ancora ricevuto connessioni

# Verifica che Wazuh Manager su vm-103 sia raggiungibile (per integrazione syslog)
nc -zv 192.168.68.204 514 2>&1 || echo "Porta 514 non ancora aperta — da configurare in sez. 7"
```

### 2.2 Verifica firewall host

```bash
# Su SOC-01
# Proxmox usa nftables di default — verifica backend attivo
nft list ruleset | head -5
# Se output vuoto o errore, usare iptables:
iptables -L -n | head -5

# Annota quale backend è attivo: nftables o iptables
# Rilevante per la configurazione del bouncer in sez. 5
```

### 2.3 Requisiti di sistema

| Parametro | Minimo | Nota |
|---|---|---|
| OS | Debian 11+ / Ubuntu 20.04+ | Proxmox 8.x = Debian 12 ✅ |
| RAM overhead CrowdSec | ~50-100 MB | Trascurabile su SOC-01 |
| Disco | ~200 MB (binari + db) | Il database SQLite cresce con i ban |
| Porte in uso (locale) | 8080/tcp (LAPI) | Solo localhost — non esposto |
| Connettività | Internet per install + hub update | Solo in uscita |

---

## 3. Installazione CrowdSec Agent

### 3.1 Aggiunta repository e installazione

```bash
# Su SOC-01

# Aggiungi il repository CrowdSec
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash

# Installa CrowdSec
apt install crowdsec -y

# Verifica che il servizio sia partito
systemctl status crowdsec
# Atteso: active (running)

# Verifica versione
cscli version
# Atteso: CrowdSec v1.6.x o superiore
```

### 3.2 Verifica installazione base

```bash
# Su SOC-01

# Il wizard di installazione auto-rileva i servizi attivi
# Verifica che SSH sia stato rilevato
cscli collections list | grep ssh

# Verifica acquisitions — quali log sta leggendo CrowdSec
cat /etc/crowdsec/acquis.yaml
# Deve contenere almeno:
# - /var/log/auth.log (SSH brute force)
# - /var/log/syslog

# Visualizza metriche in tempo reale
cscli metrics
# Mostra: parser hits, scenario triggers, decisions
```

### 3.3 Verifica LAPI attiva

```bash
# Su SOC-01

# La LAPI gira su localhost:8080
curl -s http://localhost:8080/v1/heartbeat
# Atteso: {"status":"ok"} o simile

# Verifica che il bouncer possa comunicare con la LAPI
cscli bouncers list
# Lista vuota inizialmente — i bouncer vengono aggiunti in sez. 5
```

---

## 4. Configurazione Collections

### 4.1 Collections rilevanti per HomeSOC

Le **collections** sono bundle che raggruppano parser, scenari e postoverflows necessari per proteggere uno specifico servizio. Una collection installata porta con sé tutto il necessario.

```bash
# Su SOC-01

# Aggiorna l'hub CrowdSec (scarica lista aggiornata di collection/scenari)
cscli hub update

# Installa le collection per HomeSOC
# 1. Brute force SSH — protezione primaria per UC-01
cscli collections install crowdsecurity/ssh-bf

# 2. Baseline Linux — comportamenti malevoli generici su sistemi Linux
cscli collections install crowdsecurity/linux

# 3. Syslog — parsing log di sistema
cscli collections install crowdsecurity/syslog

# Aggiorna tutto (scarica le versioni più recenti degli scenari installati)
cscli hub upgrade

# Verifica installazione
cscli collections list
# Tutte e tre devono mostrare status: enabled
```

### 4.2 Verifica parser e scenari attivi

```bash
# Su SOC-01

# Lista parser installati
cscli parsers list
# Atteso: crowdsecurity/sshd-logs, crowdsecurity/syslog-logs, etc.

# Lista scenari attivi (cosa CrowdSec sta rilevando)
cscli scenarios list
# Atteso: crowdsecurity/ssh-bf, crowdsecurity/ssh-slow-bf, etc.
```

### 4.3 Configurazione acquisitions — acquis.d/ (Debian 12)

> ⚠️ **Tre problemi verificati in produzione su Debian 12 + CrowdSec v1.4.6:**
> 1. **Campo `tags:` non supportato:** causa errore fatale `field tags not found in type fileacquisition.FileConfiguration` → rimuovere da acquis.yaml
> 2. **Separatore `---` in acquis.yaml:** può causare comportamento non deterministico su alcune versioni → usare `acquis.d/` con file separati
> 3. **Formato timestamp ISO 8601 in auth.log:** rsyslog su Debian 12 scrive il timestamp come `2026-04-23T10:21:59.123+02:00` invece del formato RFC 3164 classico `Apr 23 10:21:59`. Il parser `crowdsecurity/syslog-logs` non riconosce il formato ISO 8601 → tutte le righe risultano unparsed. Fix: forzare il template tradizionale in `rsyslog.conf`

**Step 1 — Fix rsyslog: forza formato RFC 3164 per auth.log**

```bash
# Su SOC-01

# Trova il numero di riga della regola auth.log
grep -n "auth.log" /etc/rsyslog.conf
# Tipicamente: 60:auth,authpriv.* /var/log/auth.log

# Aggiungi il template tradizionale sulla riga (sostituire XX con il numero reale)
sed -i 'XXs|/var/log/auth.log$|/var/log/auth.log;RSYSLOG_TraditionalFileFormat|' /etc/rsyslog.conf

# Verifica
grep "auth.log" /etc/rsyslog.conf
# Atteso: auth,authpriv.* /var/log/auth.log;RSYSLOG_TraditionalFileFormat

# Test sintassi e riavvio
rsyslogd -N1 && systemctl restart rsyslog

# Verifica formato nuova riga — genera attività auth
logger -p auth.info "test-format-check"
tail -3 /var/log/auth.log
# Atteso: Apr 23 10:xx:xx soc-01 root: test-format-check (NON ISO 8601)
```

**Step 2 — Migra da acquis.yaml a acquis.d/**

```bash
# Su SOC-01

# Crea directory acquis.d/ se non esiste
mkdir -p /etc/crowdsec/acquis.d

# File 1: SSH — auth.log (formato RFC 3164 dopo il fix rsyslog)
tee /etc/crowdsec/acquis.d/auth-log.yaml << 'EOF'
filenames:
  - /var/log/auth.log
labels:
  type: syslog
EOF

# File 2: Proxmox Web UI — HTTP access log
tee /etc/crowdsec/acquis.d/pveproxy.yaml << 'EOF'
filenames:
  - /var/log/pveproxy/access.log
labels:
  type: nginx
EOF

# Svuota acquis.yaml principale (lasciarlo vuoto evita conflitti)
truncate -s 0 /etc/crowdsec/acquis.yaml

# Riavvia CrowdSec
systemctl restart crowdsec

# Verifica che i file siano aperti dal processo
ls -la /proc/$(systemctl show crowdsec --property=MainPID --value)/fd | grep -E "auth|pve"
# Atteso: due symlink a /var/log/auth.log e /var/log/pveproxy/access.log

# Genera attività e verifica parsing (attendi connessioni SSH reali)
sleep 30 && cscli metrics 2>&1 | grep -A 8 "Acquisition"
# Atteso: file:/var/log/auth.log con Lines parsed > 0
```

> ℹ️ **Nota:** I log di pveproxy hanno formato HTTP access log compatibile con il parser nginx. Questo permette a CrowdSec di rilevare scan/brute force sulla Web UI Proxmox (porta 8006) senza parser dedicato.

### 4.4 Fix parser sshd-session (OpenSSH ≥ 9.x su Debian 12)

OpenSSH nelle versioni recenti (Proxmox 8.x / Debian 12) ha introdotto il processo separato `sshd-session` per gestire le sessioni autenticate. I log SSH vengono scritti con `program_name = sshd-session` invece del classico `sshd`. Il parser `crowdsecurity/sshd-logs` filtra esclusivamente su `evt.Parsed.program == 'sshd'` — tutti gli eventi risultano unparsed e non raggiungono mai lo scenario `ssh-bf`.

> ℹ️ **Come verificare il problema:** Se `cscli metrics` mostra `Lines parsed > 0` nella tabella Acquisition ma `crowdsecurity/sshd-logs` **non appare** nella tabella Parser Metrics, il rename non avviene prima che sshd-logs valuti l'evento.

**Fix: parser custom con prefisso 00- per garantire l'ordine di caricamento**

```bash
# Su SOC-01

# Verifica il nome del programma nei log SSH
tail -5 /var/log/auth.log | grep sshd
# Se mostra "sshd-session[...]" invece di "sshd[...]" → fix necessario

# Crea il parser custom — prefisso 00- garantisce il caricamento PRIMA di sshd-logs.yaml
# onsuccess: continue → rimane nello stage s01-parse, permette a sshd-logs di processare l'evento
cat > /etc/crowdsec/parsers/s01-parse/00-sshd-session-fix.yaml << 'EOF'
# Fix per OpenSSH moderno (Debian 12 / Proxmox 8.x) — rinomina sshd-session → sshd
# Necessario perché crowdsecurity/sshd-logs filtra solo su program == 'sshd'
# onsuccess: continue mantiene l'evento nello stage corrente per il parser successivo
name: custom/sshd-session-fix
filter: "evt.Parsed.program == 'sshd-session'"
onsuccess: continue
nodes:
  - filter: "true"
    statics:
      - parsed: program
        value: "sshd"
EOF

# Riavvia
systemctl restart crowdsec && echo "OK"

# Verifica che crowdsecurity/sshd-logs appaia nei Parser Metrics
# (genera prima qualche connessione SSH, poi:)
cscli metrics 2>&1 | grep -A 15 "Parser Metrics"
# Atteso: "crowdsecurity/sshd-logs" presente con Parsed > 0
```

> ⚠️ **Whitelist LAN:** La whitelist built-in di CrowdSec esclude `192.168.0.0/16` dalla detection. In un ambiente domestico questo significa che i test brute force da LAN non genereranno mai ban. La whitelist è corretta per la produzione — per i test commentare temporaneamente il CIDR in `/etc/crowdsec/parsers/s02-enrich/whitelists.yaml` e ripristinare dopo. Non rimuovere la whitelist in produzione.

---

## 5. Installazione cs-firewall-bouncer

Il **cs-firewall-bouncer** è il componente che traduce le decisioni LAPI in regole iptables/nftables effettive. Senza bouncer, CrowdSec rileva ma non blocca.

### 5.1 Installazione

```bash
# Su SOC-01

# Installa il bouncer
apt install crowdsec-firewall-bouncer-nftables -y

# Se l'host usa iptables invece di nftables:
# apt install crowdsec-firewall-bouncer-iptables -y

# Verifica che il bouncer sia registrato con la LAPI
cscli bouncers list
# Deve mostrare: cs-firewall-bouncer con IP 127.0.0.1 e status: valid
```

### 5.2 Verifica configurazione bouncer

```bash
# Su SOC-01

# Il file di configurazione del bouncer
cat /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
```

Verifica i campi chiave (non modificare se i default sono corretti):

```yaml
# Valori attesi/raccomandati — verifica che corrispondano
mode: nftables           # o iptables in base al backend host
api_url: http://127.0.0.1:8080/
api_key: <GENERATA AUTOMATICAMENTE>
```

```bash
# Avvia e abilita il bouncer
systemctl enable --now crowdsec-firewall-bouncer

# Verifica status
systemctl status crowdsec-firewall-bouncer
# Atteso: active (running)
```

### 5.3 Verifica che il bouncer applichi le decisioni

```bash
# Su SOC-01

# Test: aggiungi una decisione di ban manuale su un IP di test (usa RFC5737 — range doc)
cscli decisions add --ip 198.51.100.1 --duration 5m --reason "test-ban-manuale"

# Verifica che la decisione sia in lista
cscli decisions list | grep 198.51.100.1

# Verifica che nftables abbia recepito il ban
nft list ruleset | grep 198.51.100.1
# Deve mostrare la regola di drop per quell'IP

# Rimuovi il ban di test
cscli decisions delete --ip 198.51.100.1

# Verifica rimozione da nftables
nft list ruleset | grep 198.51.100.1
# Non deve restituire nulla
```

> ✅ **Checkpoint:** Se il test sopra ha funzionato, il ciclo LAPI → Bouncer → nftables è operativo. CrowdSec ora blocca effettivamente gli IP malevoli.

---

## 6. Threat Intelligence — Blocklist Hub

CrowdSec fornisce blocklist di IP malevoli noti a livello globale, aggiornate continuamente dalla comunità. Questa funzione è attiva anche senza servizi esposti a internet — protegge da device interni compromessi che tentano di raggiungere SOC-01.

### 6.1 Verifica aggiornamento blocklist

```bash
# Su SOC-01

# Aggiorna hub (scenari + blocklist)
cscli hub update && cscli hub upgrade

# Verifica che il feed di blocklist sia attivo
cscli hub list | grep blocklist

# Visualizza decisioni attive (incluse quelle da blocklist)
cscli decisions list
# Le entry con "CAPI" come sorgente vengono dalla blocklist collaborativa
```

### 6.2 Statistiche protezione attiva

```bash
# Su SOC-01

# Mostra conteggio decisioni attive per tipo
cscli decisions list -o json | python3 -c "
import json, sys
from collections import Counter
data = json.load(sys.stdin)
if data:
    c = Counter(d['type'] for d in data)
    for k,v in c.items(): print(f'{k}: {v}')
else:
    print('Nessuna decisione attiva al momento')
"

# Panoramica metriche
cscli metrics
```

### 6.3 Iscrizione a blocklist premium Hub (opzionale)

CrowdSec offre blocklist specializzate (TOR exit nodes, ransomware C2, etc.) tramite Hub. Per accedere:

```bash
# Registrazione account CrowdSec Console (gratuita)
# https://app.crowdsec.net → Sign up

# Dopo registrazione, enrolla SOC-01 nella Console
cscli console enroll <ENROLLMENT-KEY-DA-CONSOLE>

# Verifica enrollment
cscli console status
```

> ℹ️ L'enrollment alla Console è **opzionale**. CrowdSec funziona completamente offline — l'hub update scarica gli aggiornamenti tramite `cscli hub update` senza richiedere account. L'enrollment aggiunge solo la dashboard web e le blocklist premium.

---

## 7. Integrazione Wazuh — Pipeline CrowdSec → Syslog → Wazuh

Questa sezione configura il forwarding degli alert CrowdSec a Wazuh su vm-103. Ogni decisione di blocco (ban/unban) diventa un evento visibile nella Wazuh Dashboard.

### 7.1 Architettura del flusso

```
SOC-01 (192.168.68.200)                vm-103 (192.168.68.204)
┌────────────────────────┐             ┌────────────────────────┐
│  CrowdSec Agent        │             │  Wazuh Manager         │
│  (rileva brute force)  │             │                        │
│         │              │             │  ┌──────────────────┐  │
│         ▼              │             │  │  logcollector    │  │
│  LAPI (decisione ban)  │             │  │  (syslog 514)    │  │
│         │              │             │  └────────┬─────────┘  │
│         ▼              │  UDP 514    │           │            │
│  notification plugin   │ ──────────▶│  ┌────────▼─────────┐  │
│  (crowdsec-syslog)     │             │  │  analysisd       │  │
│                        │             │  │  (rules custom)  │  │
└────────────────────────┘             │  └────────┬─────────┘  │
                                       │           │            │
                                       │  ┌────────▼─────────┐  │
                                       │  │  Wazuh Dashboard │  │
                                       │  │  (alert visibili)│  │
                                       │  └──────────────────┘  │
                                       └────────────────────────┘
```

### 7.2 Configurazione rsyslog forwarding su SOC-01

CrowdSec scrive i propri log su file in `/var/log/crowdsec.log` (non in una subdirectory). rsyslog monitora quel file e forwarda ogni riga relativa a decisioni di ban a Wazuh via UDP 514.

> ⚠️ **Tre errori comuni da evitare (verificati in produzione):**
> 1. **Path sbagliato:** il log è `/var/log/crowdsec.log`, **non** `/var/log/crowdsec/crowdsec.log`
> 2. **Template sbagliato:** usare `RSYSLOG_TraditionalForwardFormat` (RFC 3164). Il template `RSYSLOG_SyslogProtocol23Format` produce RFC 5424 (con version field `1` nel payload) che `wazuh-remoted` scarta silenziosamente senza errori
> 3. **Tag senza due punti:** il `Tag` deve terminare con `:` (es. `Tag="crowdsec:"`) — senza il separatore, Wazuh non estrae correttamente il `program_name` e il decoder non scatta

```bash
# Su SOC-01

# Verifica che il file di log esista e abbia contenuto
ls -la /var/log/crowdsec.log
tail -5 /var/log/crowdsec.log
# Deve mostrare righe con level=info e msg="... ban on Ip ..."

# Crea configurazione rsyslog forwarding
cat > /etc/rsyslog.d/50-crowdsec-wazuh.conf << 'ENDOFFILE'
module(load="imfile" Mode="inotify")

input(type="imfile"
      File="/var/log/crowdsec.log"
      Tag="crowdsec:"
      Severity="warning"
      Facility="local3")

if $programname == 'crowdsec' then {
    action(type="omfwd"
           Target="192.168.68.204"
           Port="514"
           Protocol="udp"
           Template="RSYSLOG_TraditionalForwardFormat")
    stop
}
ENDOFFILE

# Verifica sintassi — nessun output = OK
rsyslogd -N1 2>&1 | grep -i error

# Riavvia rsyslog
systemctl restart rsyslog
systemctl is-active rsyslog
```

### 7.3 Apertura porta syslog su vm-103

```bash
# Su vm-103 (192.168.68.204) via SSH

# Verifica se Wazuh Manager ascolta già su 514/udp
ss -ulnp | grep 514
# Se nessun output, configurare il logcollector Wazuh

# Apri porta 514/udp sul firewall vm-103 solo per SOC-01
sudo ufw allow from 192.168.68.200 to any port 514 proto udp comment "CrowdSec syslog da SOC-01"

# Verifica regola aggiunta
sudo ufw status numbered | grep 514
```

### 7.4 Configurazione Wazuh logcollector per syslog CrowdSec

```bash
# Su vm-103 (192.168.68.204) via SSH

# Aggiungi sorgente syslog nel ossec.conf di Wazuh
sudo nano /var/ossec/etc/ossec.conf
```

Aggiungi la seguente sezione all'interno di `<ossec_config>`:

```xml
<!-- Syslog da CrowdSec su SOC-01 -->
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.68.200</allowed-ips>
</remote>
```

```bash
# Riavvia Wazuh Manager per applicare
sudo systemctl restart wazuh-manager

# Verifica che il manager ascolti su 514/udp
sudo ss -ulnp | grep 514
# Atteso: *:514 in ascolto
```

### 7.5 Decoder e regole Wazuh per eventi CrowdSec

> ⚠️ **Note critiche sull'engine regex di Wazuh (OS_Regex):** Wazuh non usa PCRE ma il proprio engine OS_Regex con sintassi diversa:
> - **`\.`** significa "qualsiasi carattere" (non `.` come in PCRE)
> - **`.`** significa punto letterale
> - `\s`, `\S`, `\w` **non sono supportati** — usa `\.` per "qualsiasi char"
>
> Il decoder root deve usare `<program_name>` (non `<prematch>^crowdsec`) per matchare sul campo `program_name` estratto dall'header syslog RFC3164.

Il formato reale dei log CrowdSec è:
```
Apr 21 20:56:03 soc-01 crowdsec: time="..." level=info msg="(machine-id/cscli) scenario by ip X.X.X.X : 2m ban on Ip X.X.X.X"
```

```bash
# Su vm-103 (192.168.68.204) via SSH

# Crea decoder per i log CrowdSec
sudo tee /var/ossec/etc/decoders/crowdsec-decoder.xml << 'EOF'
<!-- Decoder per eventi CrowdSec via syslog — HomeSOC -->
<!-- Nota: usa <program_name> (non <prematch>) per matchare sull'header syslog -->
<!-- Nota: OS_Regex usa \. per "qualsiasi carattere", non il punto . -->
<decoder name="crowdsec">
  <program_name>crowdsec</program_name>
</decoder>

<decoder name="crowdsec-ban">
  <parent>crowdsec</parent>
  <regex>\) (\.+) by ip (\.+) : (\.+) ban on Ip</regex>
  <order>scenario, srcip, duration</order>
</decoder>
EOF
```

```bash
# Crea regole custom per alert CrowdSec
sudo tee /var/ossec/etc/rules/crowdsec-rules.xml << 'EOF'
<!-- Regole Wazuh per eventi CrowdSec — HomeSOC -->
<!-- Nota: decoded_as punta al decoder parent "crowdsec" + match sul testo -->
<group name="crowdsec,">

  <!-- Ban automatico — IP bloccato da CrowdSec -->
  <rule id="100050" level="8">
    <decoded_as>crowdsec</decoded_as>
    <match>ban on Ip</match>
    <description>CrowdSec: IP $(srcip) bannato — scenario: $(scenario)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>crowdsec_ban,intrusion_prevention,</group>
  </rule>

  <!-- Ban da brute force SSH — priorità alta, mappa su UC-01 -->
  <rule id="100051" level="10">
    <if_sid>100050</if_sid>
    <match>ssh-bf</match>
    <description>CrowdSec: ban per brute force SSH — UC-01 — IP: $(srcip)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>crowdsec_ban,brute_force,authentication_failures,</group>
  </rule>

  <!-- Ban da blocklist globale Hub -->
  <rule id="100052" level="7">
    <if_sid>100050</if_sid>
    <match>crowdsecurity/</match>
    <description>CrowdSec: IP $(srcip) bloccato da blocklist Hub globale</description>
    <group>crowdsec_ban,threat_intel,</group>
  </rule>

</group>
EOF
```

```bash
# Verifica sintassi con wazuh-logtest usando la riga reale del log
sudo /var/ossec/bin/wazuh-logtest
# Quando appare il prompt, incolla questa riga (è il formato reale prodotto da CrowdSec):
# Apr 21 20:56:03 soc-01 crowdsec: time="21-04-2026 20:56:03" level=info msg="(machine-id/cscli) crowdsecurity/ssh-bf by ip 198.51.100.1 : 2m ban on Ip 198.51.100.1"
#
# Atteso:
# Phase 2: name='crowdsec', srcip='198.51.100.1', scenario='crowdsecurity/ssh-bf', duration='2m'
# Phase 3: Rule 100051, level 10

# Riavvia Wazuh Manager per caricare decoder e regole
sudo systemctl restart wazuh-manager
```

### 7.6 Test integrazione syslog → Wazuh

```bash
# Su SOC-01 — aggiungi un ban di test (IP da range RFC5737 — documentazione)
cscli decisions add --ip 198.51.100.99 --duration 2m --reason "test-wazuh-integration"

# Verifica che rsyslog abbia trasmesso il pacchetto UDP (su SOC-01)
tcpdump -i any -n udp port 514 -c 4 -v
# Deve mostrare: 192.168.68.200 → 192.168.68.204:514 con "crowdsec:" nel payload

# Attendi 15 secondi poi verifica alert su Wazuh (su vm-103)
sudo grep "bannato\|brute force" /var/ossec/logs/alerts/alerts.log | tail -5
# Deve mostrare: Rule 100050, level 8, Src IP: 198.51.100.99

# Test UC-01 — scenario ssh-bf (rule 100051, level 10)
cscli decisions add --ip 198.51.100.11 --duration 2m --reason "crowdsecurity/ssh-bf"
# Su vm-103:
sudo grep "198.51.100.11" /var/ossec/logs/alerts/alerts.log
# Deve mostrare: Rule 100051, level 10 — UC-01

# Cleanup
cscli decisions delete --ip 198.51.100.99
cscli decisions delete --ip 198.51.100.11
```

> ✅ **Checkpoint:** Se `alerts.log` mostra Rule 100051 level 10, la pipeline CrowdSec → rsyslog → Wazuh è completamente operativa e UC-01 è implementato.

---

## 8. Verifica end-to-end

### 8.1 Simulazione brute force SSH

```bash
# Da MacBook Pro M1 (o qualsiasi host LAN diverso da SOC-01)
# ATTENZIONE: questo test genera tentativi SSH falliti — normale, è il test previsto

# Esegui 10 tentativi SSH con password errata verso SOC-01
for i in {1..10}; do
  ssh -o "StrictHostKeyChecking=no" -o "ConnectTimeout=3" \
    wronguser@192.168.68.200 2>/dev/null || true
  sleep 0.5
done

echo "Test completato — verifica decisione CrowdSec su SOC-01"
```

```bash
# Su SOC-01 — verifica che l'IP del MacBook sia stato bannato
cscli decisions list | grep <IP-MACBOOK>
# Esempio: cscli decisions list | grep 192.168.68.108

# Verifica che nftables abbia la regola di drop
nft list ruleset | grep <IP-MACBOOK>

# Verifica che l'alert sia arrivato in Wazuh (su vm-103)
# Dashboard Wazuh → Security Events → filtra: rule.id:100051
```

```bash
# Rimuovi il ban del MacBook dopo il test
cscli decisions delete --ip <IP-MACBOOK>
# Esempio: cscli decisions delete --ip 192.168.68.108
```

> ⚠️ **Importante:** Dopo il test, verifica che il MacBook sia stato de-bannato prima di continuare il lavoro su SOC-01.

### 8.2 Verifica metriche globali

```bash
# Su SOC-01

# Panoramica completa dello stato CrowdSec
cscli metrics
# Deve mostrare: parser hits > 0, scenario triggers attivi

# Riepilogo decisioni attive
echo "=== Decisioni attive ==="
cscli decisions list | head -20

echo "=== Bouncers connessi ==="
cscli bouncers list

echo "=== Collections installate ==="
cscli collections list

echo "=== Hub aggiornato ==="
cscli hub list | grep -E "STATE|enabled"
```

---

## 9. Preparazione per esposizione futura

Questa sezione documenta la struttura per aggiungere bouncers su nuovi servizi senza dover riconfigurare l'agent — il design "pronto per scalare" del progetto HomeSOC.

### 9.1 Struttura bouncers per servizi futuri

| Servizio futuro | Bouncer da aggiungere | Collection aggiuntiva |
|---|---|---|
| Nginx reverse proxy | `crowdsec-nginx-bouncer` | `crowdsecurity/nginx` |
| Traefik | `crowdsec-bouncer-traefik-plugin` | `crowdsecurity/traefik` |
| WireGuard / Tailscale | `cs-firewall-bouncer` (già installato) | — |
| HAProxy | `cs-haproxy-bouncer` | `crowdsecurity/haproxy` |

### 9.2 Pattern di aggiunta bouncer futuro

Quando si espone un nuovo servizio, il pattern da seguire è:

```bash
# 1. Installa la collection per il servizio
cscli collections install crowdsecurity/<SERVIZIO>

# 2. Aggiungi il log del servizio in acquis.d/ (un file per servizio)
# /etc/crowdsec/acquis.d/<servizio>.yaml:
# filenames:
#   - /var/log/<servizio>/access.log
# labels:
#   type: <servizio>

# 3. Se serve un bouncer applicativo (non solo firewall):
apt install crowdsec-<servizio>-bouncer -y

# 4. Riavvia
systemctl restart crowdsec

# Il bouncer firewall esistente blocca già a livello IP —
# il bouncer applicativo aggiunge captcha/rate limiting a livello HTTP
```

### 9.3 Disabilitazione CAPI per profilo zero-disclosure (opzionale)

Se si preferisce non partecipare alla condivisione collaborativa:

```bash
# Su SOC-01
# Disabilita sharing verso CrowdSec Central API
sudo nano /etc/crowdsec/config.yaml
```

Trovare e modificare la sezione `api.server`:

```yaml
api:
  server:
    online_client:
      credentials_path: ""  # stringa vuota = CAPI disabilitata
```

```bash
systemctl restart crowdsec
# Le blocklist locali (Hub update) rimangono funzionali
# Solo la condivisione cloud viene disabilitata
```

---

## 10. Backup e persistenza della configurazione

### 10.1 File di configurazione da includere nel backup

```bash
# Su SOC-01 — lista file critici CrowdSec
ls -la /etc/crowdsec/
# crowdsec.yaml       — configurazione principale
# acquis.yaml         — sorgenti log
# profiles.yaml       — profili di risposta
# bouncers/           — configurazione bouncers
# hub/                — scenari e parser scaricati

# Database decisioni (SQLite)
ls -la /var/lib/crowdsec/data/crowdsec.db
```

### 10.2 Export configurazione per git

```bash
# Su SOC-01 — crea backup della config per archiviazione

mkdir -p /root/homesoc-config-backup/crowdsec

# Copia file di configurazione (senza secrets)
cp /etc/crowdsec/crowdsec.yaml /root/homesoc-config-backup/crowdsec/
cp -r /etc/crowdsec/acquis.d/ /root/homesoc-config-backup/crowdsec/
cp /etc/crowdsec/profiles.yaml /root/homesoc-config-backup/crowdsec/
cp /etc/crowdsec/parsers/s01-parse/00-sshd-session-fix.yaml \
   /root/homesoc-config-backup/crowdsec/

# Esporta lista collections/scenari installati
cscli collections list -o json > /root/homesoc-config-backup/crowdsec/collections-installed.json
cscli scenarios list -o json > /root/homesoc-config-backup/crowdsec/scenarios-installed.json

echo "Backup configurazione CrowdSec in /root/homesoc-config-backup/crowdsec/"
```

> ⚠️ **Attenzione:** Non includere nel backup `/etc/crowdsec/local_api_credentials.yaml` e `/etc/crowdsec/bouncers/*.yaml` — contengono API key locali. In caso di ripristino, rigenera le chiavi con `cscli bouncers add <nome>`.

### 10.3 Aggiornamento programmato

```bash
# Su SOC-01 — cron giornaliero per aggiornamento hub
crontab -e
```

Aggiungi la riga:

```cron
# Aggiornamento CrowdSec Hub ogni giorno alle 03:00
0 3 * * * /usr/bin/cscli hub update && /usr/bin/cscli hub upgrade --force >> /var/log/crowdsec.log 2>&1
```

---

## 11. Verifica finale e checklist

### 11.1 Checklist di completamento

**Installazione Agent:**
- [ ] `systemctl is-active crowdsec` → `active`
- [ ] `cscli version` → CrowdSec v1.6.x o superiore
- [ ] LAPI risponde: `curl -s http://localhost:8080/v1/heartbeat` → `{"status":"ok"}`

**Collections e scenari:**
- [ ] `cscli collections list | grep crowdsecurity/ssh-bf` → `enabled`
- [ ] `cscli collections list | grep crowdsecurity/linux` → `enabled`
- [ ] `cscli collections list | grep crowdsecurity/syslog` → `enabled`
- [ ] `cscli scenarios list` → ssh-bf, ssh-slow-bf presenti

**Acquisitions (Debian 12):**
- [ ] `rsyslog.conf` riga auth.log ha template `RSYSLOG_TraditionalFileFormat` → `tail /var/log/auth.log` mostra formato `Apr 23 HH:MM:SS` (non ISO 8601)
- [ ] `/etc/crowdsec/acquis.d/auth-log.yaml` presente con `filenames: [/var/log/auth.log]` e `type: syslog`
- [ ] `/etc/crowdsec/acquis.d/pveproxy.yaml` presente con `type: nginx`
- [ ] `/etc/crowdsec/acquis.yaml` vuoto (nessun conflitto con acquis.d/)
- [ ] Parser fix OpenSSH: `/etc/crowdsec/parsers/s01-parse/00-sshd-session-fix.yaml` presente con `onsuccess: continue`
- [ ] `cscli metrics` → Parser Metrics mostra `crowdsecurity/sshd-logs` con Parsed > 0

**Firewall Bouncer:**
- [ ] `systemctl is-active crowdsec-firewall-bouncer` → `active`
- [ ] `cscli bouncers list` → cs-firewall-bouncer con status `valid`
- [ ] Test ban manuale: `cscli decisions add --ip 198.51.100.1 --duration 1m --reason test` → regola appare in `nft list ruleset`
- [ ] Test unban: regola rimossa dopo `cscli decisions delete --ip 198.51.100.1`

**Threat Intelligence Hub:**
- [ ] `cscli hub update` eseguito senza errori
- [ ] `cscli decisions list` mostra decisioni (anche 0 è OK se nessun attacco recente)

**Integrazione Wazuh:**
- [ ] `/etc/rsyslog.d/50-crowdsec-wazuh.conf` presente con `File="/var/log/crowdsec.log"` e `Tag="crowdsec:"`
- [ ] Template rsyslog: `RSYSLOG_TraditionalForwardFormat` (RFC 3164 — non SyslogProtocol23Format)
- [ ] `rsyslogd -N1` → nessun errore
- [ ] `systemctl is-active rsyslog` → `active`
- [ ] Porta 514/udp aperta su vm-103 per 192.168.68.200 — `sudo ufw status | grep 514`
- [ ] Wazuh logcollector configurato con `<remote>` syslog 514/udp — `sudo ss -ulnp | grep 514` mostra `0.0.0.0:514`
- [ ] Decoder usa `<program_name>crowdsec</program_name>` e regex OS_Regex con `\.+`
- [ ] `wazuh-logtest` con riga reale CrowdSec → Phase 2 mostra `srcip`, `scenario`, `duration`
- [ ] Test ban → alert rule 100050 level 8 in `alerts.log`
- [ ] Test ssh-bf → alert rule 100051 level 10 in `alerts.log`

**Protezione SSH (UC-01):**
- [ ] Test brute force simulato → IP bannato da CrowdSec in < 30 secondi
- [ ] Ban compare in `nft list ruleset`
- [ ] Alert UC-01 (rule 100051) generato in Wazuh
- [ ] MacBook de-bannato dopo test

**Cron aggiornamento:**
- [ ] Cron giornaliero `cscli hub update && upgrade` configurato alle 03:00

### 11.2 Comandi diagnostici di riepilogo

```bash
# Su SOC-01 — stato completo CrowdSec
echo "=== CrowdSec Agent ===" && systemctl is-active crowdsec
echo "=== Firewall Bouncer ===" && systemctl is-active crowdsec-firewall-bouncer
echo "=== LAPI ===" && curl -s http://localhost:8080/v1/heartbeat 2>/dev/null || echo "LAPI non risponde"
echo "=== Bouncers ===" && cscli bouncers list
echo "=== Decisioni attive ===" && cscli decisions list | wc -l && echo "decisioni totali"
echo "=== Collections ===" && cscli collections list | grep -c enabled && echo "collections enabled"
echo "=== Metriche parser ===" && cscli metrics | grep -A5 "Parser"
echo "=== rsyslog → Wazuh ===" && systemctl is-active rsyslog
```

```bash
# Su vm-103 — verifica ricezione eventi CrowdSec
echo "=== Wazuh Manager ===" && systemctl is-active wazuh-manager
echo "=== Porta 514 aperta ===" && ss -ulnp | grep 514
echo "=== Ultimi alert CrowdSec ===" && sudo grep -i crowdsec /var/ossec/logs/alerts/alerts.log 2>/dev/null | tail -5
```

---

## 12. Troubleshooting

### CrowdSec agent non parte — errore "field tags not found"

```bash
# Su SOC-01
journalctl -u crowdsec -n 20 --no-pager | grep fatal
# Se vedi: "field tags not found in type fileacquisition.FileConfiguration"
# Il problema è il campo tags: in acquis.yaml — non supportato in CrowdSec v1.6+

# Fix: rimuovi tutti i blocchi tags: da acquis.yaml
# Vedi sezione 4.3 per la configurazione corretta
nano /etc/crowdsec/acquis.yaml
systemctl restart crowdsec
```

### CrowdSec agent non parte — errore LAPI

```bash
# Su SOC-01
journalctl -u crowdsec -n 50 --no-pager
# Cercate: "unable to start local API" o "port already in use"

# Verifica che la porta 8080 non sia occupata da altro
ss -tlnp | grep 8080

# Se occupata, cambia porta LAPI in /etc/crowdsec/config.yaml:
# api.server.listen_uri: 127.0.0.1:8081
# e aggiorna il bouncer: api_url: http://127.0.0.1:8081/
```

### Bouncer non applica i ban — nftables vuoto

```bash
# Su SOC-01
journalctl -u crowdsec-firewall-bouncer -n 30 --no-pager
# Cercate: "unable to connect to LAPI" o errori di autenticazione

# Rigenera la chiave API del bouncer
cscli bouncers delete cs-firewall-bouncer
cscli bouncers add cs-firewall-bouncer
# Copia la nuova api_key in /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml

systemctl restart crowdsec-firewall-bouncer
```

### Log SSH non vengono parsati — 0 hits nel parser / crowdsecurity/sshd-logs assente

**Causa A — Formato timestamp ISO 8601 (Debian 12):**

rsyslog su Debian 12 scrive auth.log con timestamp ISO 8601 (`2026-04-23T10:21:59+02:00`) invece di RFC 3164 (`Apr 23 10:21:59`). Il parser `crowdsecurity/syslog-logs` non riconosce il formato ISO e scarta tutte le righe.

```bash
# Su SOC-01
# Verifica il formato timestamp
tail -3 /var/log/auth.log
# Se mostra "2026-04-23T..." → fix necessario

# Trova e correggi la riga auth.log in rsyslog.conf
grep -n "auth.log" /etc/rsyslog.conf
# Aggiungi template: sed -i 'XXs|/var/log/auth.log$|/var/log/auth.log;RSYSLOG_TraditionalFileFormat|' /etc/rsyslog.conf
rsyslogd -N1 && systemctl restart rsyslog
```

**Causa B — OpenSSH moderno usa sshd-session (Debian 12 / Proxmox 8.x):**

OpenSSH ≥ 9.x separa il processo di sessione in `sshd-session`. Il parser `crowdsecurity/sshd-logs` filtra `program == 'sshd'` — gli eventi `sshd-session` vengono parsati dal syslog-logs ma non raggiungono mai sshd-logs (non appare in Parser Metrics).

```bash
# Su SOC-01
# Verifica
tail -5 /var/log/auth.log | grep -E "sshd\[|sshd-session\["
# "sshd-session[" → fix necessario

# Fix: parser con prefisso 00- (carica prima di sshd-logs.yaml)
cat > /etc/crowdsec/parsers/s01-parse/00-sshd-session-fix.yaml << 'EOF'
name: custom/sshd-session-fix
filter: "evt.Parsed.program == 'sshd-session'"
onsuccess: continue
nodes:
  - filter: "true"
    statics:
      - parsed: program
        value: "sshd"
EOF
systemctl restart crowdsec
```

**Causa C — Debian 13: auth.log non esiste:**

```bash
# Su SOC-01
# Verifica se auth.log esiste
ls -lh /var/log/auth.log 2>/dev/null || echo "ASSENTE — usare journalctl"

# Se assente, usa acquis.d/auth-log.yaml con source journalctl:
# source: journalctl
# journalctl_filter:
#   - "_SYSTEMD_UNIT=ssh.service"
# labels:
#   type: syslog
```

### Alert non arrivano su Wazuh — debug layer by layer

Segui questa sequenza diagnostica per isolare il punto di rottura:

**Step 1 — rsyslog sta trasmettendo?**
```bash
# Su SOC-01 — sniffer + trigger contemporaneamente
tcpdump -i any -n udp port 514 -c 4 -v &
cscli decisions add --ip 198.51.100.50 --duration 1m --reason test

# Se NON vedi pacchetti UDP: rsyslog non sta leggendo il file
# Verifica path e sintassi:
rsyslogd -N1 2>&1 | grep -i error
cat /etc/rsyslog.d/50-crowdsec-wazuh.conf | grep File
# Deve essere: File="/var/log/crowdsec.log"  (non /var/log/crowdsec/crowdsec.log)

cscli decisions delete --ip 198.51.100.50
```

**Step 2 — il pacchetto arriva a vm-103?**
```bash
# Su vm-103 (con sniffer attivo su vm-103 e trigger su SOC-01)
sudo tcpdump -i any -n udp port 514 -c 4

# Se NON arriva: problema Proxmox firewall
cat /etc/pve/firewall/103.fw 2>/dev/null
# Se arriva ma Wazuh non lo processa: problema wazuh-remoted
sudo ss -ulnp | grep 514
# Deve mostrare: 0.0.0.0:514 con "wazuh-remoted"
```

**Step 3 — il formato syslog è RFC 3164?**
```bash
# Nel tcpdump il messaggio deve iniziare SENZA "1 " prima del timestamp:
# CORRETTO:   Msg: Apr 21 20:56:03 soc-01 crowdsec: time=...
# SBAGLIATO:  Msg: 1 2026-04-21T20:56:03 soc-01 crowdsec time=...
# (il "1" indica RFC 5424 — Wazuh lo scarta silenziosamente)

# Fix: verifica che il template in rsyslog sia TraditionalForwardFormat
grep Template /etc/rsyslog.d/50-crowdsec-wazuh.conf
# Deve mostrare: Template="RSYSLOG_TraditionalForwardFormat"
```

**Step 4 — il decoder matcha?**
```bash
# Su vm-103 — test interattivo con la stringa reale
sudo /var/ossec/bin/wazuh-logtest
# Incolla una riga reale dal log:
# Apr 21 20:56:03 soc-01 crowdsec: time="..." level=info msg="(...) scenario by ip X.X.X.X : 2m ban on Ip X.X.X.X"

# Se Phase 2 mostra "No decoder matched":
# - Verifica che il decoder usi <program_name>crowdsec</program_name>
# - Verifica che il Tag in rsyslog sia "crowdsec:" (con due punti)

# Se Phase 2 mostra solo il parent "crowdsec" senza srcip/scenario:
# - Verifica che il regex usi \.+ (non .+ — OS_Regex usa \. per "qualsiasi char")
sudo cat /var/ossec/etc/decoders/crowdsec-decoder.xml | grep regex
# Deve contenere: \.+ (backslash-punto-plus)
```

### IP bannato ma ancora raggiungibile — nftables non attivo

```bash
# Su SOC-01

# Verifica backend firewall attivo
nft list ruleset 2>/dev/null && echo "nftables OK" || echo "nftables non disponibile"
iptables -L -n 2>/dev/null | head -3

# Se il host usa iptables ma hai installato il bouncer nftables:
apt remove crowdsec-firewall-bouncer-nftables -y
apt install crowdsec-firewall-bouncer-iptables -y
systemctl enable --now crowdsec-firewall-bouncer
```

---

## Prossimi passi

Dopo aver completato e verificato questa checklist:

1. Commit su Git:
   ```bash
   git add runbooks/crowdsec-deploy.md
   git commit -m "runbooks(crowdsec): v1.2 — fix Debian 12: rsyslog RFC3164, acquis.d migration, sshd-session parser"
   ```

2. Aggiornare `docs/01-threat-model.md`:
   - Sez. UC-01: aggiornare risposta prevista da `fail2ban` → `CrowdSec cs-firewall-bouncer`
   - Stato: `Implementato` (se il test brute force ha generato l'alert in Wazuh)
   - R-10: aggiornare stato mitigazione con CrowdSec come controllo attivo

3. Commit threat model aggiornato:
   ```bash
   git add docs/01-threat-model.md
   git commit -m "docs(threat-model): update v1.3 — UC-01 CrowdSec implementato, R-10 mitigato"
   ```

4. Procedere con il runbook successivo di Fase 3, oppure aprire Fase 4:
   - **Fase 4:** `runbooks/thehive-deploy.md` — TheHive 5 + Cortex 3 (vm-104, `192.168.68.205`)
   - Integrazione Wazuh API → case creation automatico su alert CrowdSec (rule 100051)

---

*File: `runbooks/crowdsec-deploy.md` · v1.2 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
