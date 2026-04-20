# Runbook — Wazuh → Slack Alert Integration (vm-103)
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `wazuh-slack.md`  
**Versione:** 1.0 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 3 — SIEM & Detection  
**Prerequisito:** `wazuh-deploy.md` completato — vm-103 operativa, tutti e 5 gli UC attivi e testati, `wazuh-manager` in stato `active (running)`

> **Scopo:** Configurare l'integrazione nativa Wazuh → Slack usando il blocco `<integration>` in `ossec.conf`, sostituire lo script built-in con una versione custom che genera messaggi contestuali per ogni Use Case, e verificare end-to-end che ogni alert di livello ≥ 10 generi una notifica leggibile nel canale `#homesoc-alerts`. Al termine di questo runbook ogni scatto delle rule 100001 (UC-01), 100020/100023 (UC-03), 100030 (UC-04) e 100040 (UC-06) produrrà una notifica Slack con contesto specifico del use case.

**Regole coinvolte:**

| Rule ID | Use Case | Level | Inclusa |
|---|---|---|---|
| 100001 | UC-01 — SSH brute force | 10 | ✅ |
| 100020 | UC-03 — FIM macOS (native) | 12 | ✅ |
| 100023 | UC-03 — FIM macOS (diff workaround) | 10 | ✅ |
| 100030 | UC-04 — NAS port monitor | 12 | ✅ |
| 100040 | UC-06 — Rogue device | 10 | ✅ |
| 100010 | UC-02 — NextDNS beaconing IoT | 8 | ❌ (level 8, sotto threshold) |

**Changelog:**
- v1.0 — Aprile 2026 — Prima stesura

---

## Indice

1. [Prerequisiti](#1-prerequisiti)
2. [Creazione Slack App e Incoming Webhook](#2-creazione-slack-app-e-incoming-webhook)
3. [Configurazione integrazione in ossec.conf](#3-configurazione-integrazione-in-ossecconf)
4. [Script slack.py custom — messaggi contestuali per UC](#4-script-slackpy-custom--messaggi-contestuali-per-uc)
5. [Riavvio e verifica servizi](#5-riavvio-e-verifica-servizi)
6. [Test sintetico — alert senza eventi reali](#6-test-sintetico--alert-senza-eventi-reali)
7. [Formato messaggi Slack per use case](#7-formato-messaggi-slack-per-use-case)
8. [Notifiche aggiuntive consigliate — estensioni future](#8-notifiche-aggiuntive-consigliate--estensioni-future)
9. [Verifica finale e checklist](#9-verifica-finale-e-checklist)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisiti

### 1.1 Stato Wazuh richiesto

```bash
# Su vm-103
for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
  echo "  ${svc}: $(systemctl is-active $svc)"
done
# Output atteso: tutti e tre su "active"
```

### 1.2 Verifica integratord disponibile

```bash
# Su vm-103
ls /var/ossec/bin/wazuh-integratord
# Deve esistere — incluso nel pacchetto wazuh-manager
```

### 1.3 Accesso Slack richiesto

- Account Slack con permessi per creare App nel workspace
- Canale `#homesoc-alerts` da creare (o nome a scelta)

---

## 2. Creazione Slack App e Incoming Webhook

Operazione da browser, non da vm-103.

### 2.1 Crea il canale Slack

Client Slack → **Channels → + → Create a channel**
- Nome: `homesoc-alerts`
- Tipo: **Private** (gli alert contengono IP e dati infrastruttura)

### 2.2 Crea la Slack App

**https://api.slack.com/apps** → **Create New App → From scratch**
- App Name: `HomeSOC Wazuh`
- Workspace: workspace personale
- **Create App**

### 2.3 Abilita Incoming Webhooks

Pannello App → **Features → Incoming Webhooks** → toggle **ON**  
Scorrere in fondo → **Add New Webhook to Workspace** → seleziona `#homesoc-alerts` → **Allow**

### 2.4 Salva la Webhook URL

Slack mostra una URL nel formato:
```
https://hooks.slack.com/services/TXXXXXXXXX/BXXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXXX
```

> ⚠️ **Sicurezza:** questa URL è una credenziale. Salvarla nel password manager. Non commitarla mai in chiaro su Git.

Test rapido dal Mac:

```bash
# Sul Mac
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"✅ HomeSOC webhook test — funziona!"}' \
  "https://hooks.slack.com/services/TXXXXXXXXX/BXXXXXXXXX/XXXXXXXXXXXXXXXXX"
# Output atteso: ok
```

> ✅ **Checkpoint:** Il messaggio deve comparire nel canale prima di procedere.

---

## 3. Configurazione integrazione in ossec.conf

### 3.1 Backup

```bash
# Su vm-103
sudo cp /var/ossec/etc/ossec.conf \
  /var/ossec/etc/ossec.conf.bak-$(date +%Y%m%d)

# Verifica backup — il glob richiede sudo bash per espansione corretta
sudo bash -c 'ls -lh /var/ossec/etc/ossec.conf.bak-*'
# oppure: sudo ls /var/ossec/etc/ | grep bak
```

### 3.2 Trova il punto di inserimento

```bash
# Su vm-103
sudo grep -n "</global>\|<alerts>\|</ossec_config>" \
  /var/ossec/etc/ossec.conf | head -10
```

Il blocco `<integration>` va inserito **subito dopo** la prima occorrenza di `</global>`.

> ℹ️ `ossec.conf` può contenere più blocchi `</global>` e `</ossec_config>` — è la struttura modulare di Wazuh, non un errore.

### 3.3 Modifica ossec.conf

```bash
# Su vm-103
sudo nano +22 /var/ossec/etc/ossec.conf
# (sostituire 22 con il numero di riga restituito dal grep al punto 3.2)
```

Incollare subito dopo `</global>`:

```xml
  <!-- ============================================================
       HomeSOC — Slack Integration
       Alert level >= 10 → #homesoc-alerts
       UC-01 (100001) · UC-03 (100020/100023)
       UC-04 (100030) · UC-06 (100040)
       Script custom: integrations/slack.py
       Runbook: wazuh-slack.md
       ============================================================ -->
  <integration>
    <n>slack</n>
    <hook_url>https://hooks.slack.com/services/TXXXXXXXXX/BXXXXXXXXX/XXXXXXXXXXXXXXXXX</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>
```

> ⚠️ Il tag corretto è `<n>slack</n>` — **non** `<n>slack</n>`. Usare `<n>` produce `ERROR: Invalid element in the configuration: 'n'` e impedisce il riavvio del manager.

Sostituire la `hook_url` con quella reale. Salvare: **Ctrl+X → Y → Invio**

### 3.4 Verifica sintassi

```bash
# Su vm-103
# Il binario corretto è wazuh-analysisd (non ossec-analysisd)
sudo /var/ossec/bin/wazuh-analysisd -t
# Nessun output = configurazione OK
# Se escono errori: ripristinare il backup e correggere prima di riavviare
```

> ⚠️ Non procedere al riavvio se il comando produce errori.

---

## 4. Script slack.py custom — messaggi contestuali per UC

Lo script built-in di Wazuh invia un dump generico identico per tutti gli alert. Lo sostituiamo con una versione custom che genera messaggi leggibili e contestualizzati per ogni use case.

### 4.1 Backup script originale

```bash
# Su vm-103
sudo cp /var/ossec/integrations/slack.py \
  /var/ossec/integrations/slack.py.bak-$(date +%Y%m%d)
```

### 4.2 Installazione script custom

Lo script custom si trova nel repository in `integrations/slack.py`. Copiarlo su vm-103:

```bash
# Dal Mac — copia via scp
scp integrations/slack.py alessandrogaburro@192.168.68.204:/tmp/slack_custom.py

# Su vm-103 — installa e imposta permessi corretti
sudo cp /tmp/slack_custom.py /var/ossec/integrations/slack.py
sudo chown root:wazuh /var/ossec/integrations/slack.py
sudo chmod 750 /var/ossec/integrations/slack.py
```

### 4.3 Struttura dello script custom

Lo script mantiene invariato il plumbing originale (lettura file alert, invio HTTP, gestione errori) e sostituisce solo `generate_msg()` con routing per rule ID:

```python
def generate_msg(alert, options):
    rule_id = str(alert['rule']['id'])
    data    = alert.get('data', {})

    if rule_id == '100001':
        msg = _msg_uc01(alert, data)          # SSH brute force
    elif rule_id in ('100020', '100023'):
        msg = _msg_uc03(alert, data, rule_id) # FIM macOS
    elif rule_id in ('100030', '100031'):
        msg = _msg_uc04(alert, data, rule_id) # NAS port monitor
    elif rule_id in ('100040', '100041'):
        msg = _msg_uc06(alert, data, rule_id) # Rogue device
    else:
        msg = _msg_generic(alert, data)       # fallback originale
```

Ogni funzione `_msg_ucXX` estrae i campi decoded (`data.get('fim.file')`, `data.get('rogue.mac')`, ecc.) con fallback sul `full_log` se il decoder non ha estratto i campi strutturati. Le rule built-in di Wazuh che raggiungono level ≥ 10 vengono gestite dal fallback generico — comportamento corretto.

---

## 5. Riavvio e verifica servizi

```bash
# Su vm-103
sudo systemctl restart wazuh-manager
sleep 15
sudo systemctl status wazuh-manager --no-pager | head -8
# Atteso: Active: active (running)

# Verifica che wazuh-integratord sia partito
sudo ps aux | grep integratord | grep -v grep
# Atteso: /var/ossec/bin/wazuh-integratord
```

> ✅ **Checkpoint:** Se `wazuh-integratord` non compare, il blocco `<integration>` ha un errore — controllare `ossec.log`.

---

## 6. Test sintetico — alert senza eventi reali

### 6.1 Strategia

`wazuh-logtest` verifica solo parsing e regole, non attiva `wazuh-integratord`. Per testare la pipeline completa occorre iniettare un log nel formato **esatto** del decoder nel file **esatto** monitorato dal logcollector.

> ⚠️ Il formato del log sintetico deve corrispondere a quello reale prodotto dagli script. Un formato sbagliato non viene matchato dal decoder e non genera alert.

### 6.2 Test UC-06 — rogue device (metodo consigliato)

```bash
# Su vm-103
echo "$(date -Iseconds) homesoc rogue-device: event=\"new_device\" mac=\"DE:AD:BE:EF:00:01\" ip=\"192.168.68.250\" status=\"not_in_whitelist\"" \
  | sudo tee -a /var/log/homesoc/rogue-device.log

sleep 10
sudo grep "100040" /var/ossec/logs/alerts/alerts.log | tail -3
```

> ⚠️ Il path corretto è `/var/log/homesoc/rogue-device.log`. Verificare con: `sudo grep -A3 "rogue" /var/ossec/etc/ossec.conf | grep location`

### 6.3 Test UC-04 — NAS port monitor

```bash
# Su vm-103
echo "$(date -Iseconds) homesoc nas-monitor: event=\"unexpected_port\" host=\"192.168.68.150\" port=\"8443\" proto=\"tcp\" status=\"new_port\"" \
  | sudo tee -a /var/log/homesoc/nas-monitor.log

sleep 10
sudo grep "100030" /var/ossec/logs/alerts/alerts.log | tail -3
```

### 6.4 Test UC-01 — SSH brute force (dal Mac)

```bash
# Sul Mac — ripetere 6-7 volte rapidamente senza attendere tra i tentativi
ssh utente_falso@192.168.68.204
# Password: qualsiasi stringa errata
```

### 6.5 Verifica notifica Slack

```bash
# Su vm-103
sudo tail -20 /var/ossec/logs/integrations.log
```

La notifica deve arrivare entro 30–60 secondi.

> ℹ️ Durante il test possono arrivare alert reali in contemporanea — gli script rogue-device e nas-monitor girano periodicamente e rilevano dispositivi reali in rete.

---

## 7. Formato messaggi Slack per use case

### UC-01 — SSH Brute Force · rule 100001 · level 10 · colore rosso

```
🔴 SSH Brute Force rilevato — UC-01
Tentativi ripetuti di accesso SSH falliti
<IP> ha superato la soglia di tentativi SSH falliti su vm-103-wazuh.

IP sorgente    Agent          Rule               Timestamp
192.168.68.x   vm-103-wazuh   100001 · Level 10  YYYY-MM-DD HH:MM:SS

HomeSOC · MITRE T1110.001
```

### UC-03 — FIM macOS · rule 100020/100023 · level 12/10 · colore arancio

```
🟠 Modifica file critico — UC-03 FIM
File system integrity: file modificato su macOS
Il file <path> è stato modificato sul MacBook Pro M1.

File                              Evento                Agent                Rule
/Users/alessandrogaburro/.zshrc   Modificato/Eliminato  macbook-pro-m1-ale   100023 · Level 10

HomeSOC · MITRE T1565.001
```

### UC-04 — NAS Port Monitor · rule 100030 · level 12 · colore rosso

```
🔴 Porta inattesa sul NAS — UC-04
NAS: porta non prevista rilevata
Il NAS <host> espone la porta <porta/proto> che non è nella lista attesa.

Host NAS        Porta      Agent         Rule
192.168.68.150  8443/tcp   vm-103-wazuh  100030 · Level 12

HomeSOC · MITRE T1078
```

### UC-06 — Rogue Device · rule 100040 · level 10 · colore giallo

```
🟡 Dispositivo sconosciuto in rete — UC-06
Rogue device: MAC non in whitelist
Rilevato dispositivo non autorizzato sulla LAN.

MAC address        IP assegnato     Rule               Timestamp
DE:AD:BE:EF:00:01  192.168.68.250   100040 · Level 10  YYYY-MM-DD HH:MM:SS

HomeSOC · MITRE T1200
```

---

## 8. Notifiche aggiuntive consigliate — estensioni future

Le notifiche attualmente configurate coprono gli UC del threat model. Esistono però eventi ad alto valore operativo già rilevabili da Wazuh con le rule built-in, che sarebbe utile ricevere in tempo reale su Slack. Sono elencati in ordine di priorità e facilità di implementazione.

### 8.1 Agent disconnesso — priorità alta

**Perché è utile:** se il Wazuh Agent sul MacBook si disconnette inaspettatamente (crash, rimozione, problema di rete), smette di inviare log e gli UC-03/FIM diventano silenti. Senza questa notifica, un attaccante che disabilita l'agent passa inosservato.

**Rule built-in:** `501` (agent disconnesso) e `502` (agent riconnesso) — già presenti in Wazuh, level 3 di default.

**Implementazione:** alzare il level della rule 501 a 10 in `local_rules.xml` con un override, oppure aggiungere un filtro per rule ID nel blocco `<integration>` oltre al threshold di level.

```xml
<!-- Override rule 501 per alzare il level -->
<rule id="100050" level="12">
  <if_sid>501</if_sid>
  <description>HomeSOC: Wazuh Agent disconnesso — monitoraggio cieco</description>
</rule>
```

### 8.2 Accesso SSH riuscito con utente root — priorità alta

**Perché è utile:** un login SSH diretto come root su vm-103 è anomalo (il setup usa `alessandrogaburro` + sudo). Se scatta, o è un errore operativo o una compromissione attiva.

**Rule built-in:** `5715` (login SSH riuscito) filtrata per utente `root`.

```xml
<rule id="100051" level="12">
  <if_sid>5715</if_sid>
  <user>root</user>
  <description>HomeSOC: Login SSH root riuscito su vm-103</description>
</rule>
```

### 8.3 Escalation privilegi — uso di sudo — priorità media

**Perché è utile:** ogni esecuzione `sudo` su vm-103 o sul MacBook è tracciata da Wazuh (rule 5402). In un contesto homelab il numero di sudo al giorno è basso e prevedibile — un picco anomalo o un comando sudo inatteso (es. da un utente nuovo) merita visibilità.

**Rule built-in:** `5402` (sudo eseguito), level 3 di default. Utile configurare un alert solo per comandi critici (es. `sudo passwd`, `sudo visudo`, `sudo systemctl stop wazuh-manager`).

### 8.4 Nuovo utente o gruppo creato — priorità media

**Perché è utile:** la creazione di un nuovo account locale è un indicatore classico di persistenza post-compromissione (MITRE T1136). Su vm-103 non ci sono motivi operativi per creare nuovi utenti dopo il setup iniziale.

**Rule built-in:** `5902` (useradd) e `5904` (groupadd), level 8 di default — sotto il threshold attuale. Alzare a 12 con un override.

```xml
<rule id="100052" level="12">
  <if_sid>5902</if_sid>
  <description>HomeSOC: Nuovo utente creato su vm-103 — possibile persistenza</description>
</rule>
```

### 8.5 Modifica regole firewall (UFW) — priorità media

**Perché è utile:** una modifica alle regole UFW su vm-103 (apertura di nuove porte, disabilitazione del firewall) è un'operazione rara e impattante. Se avviene senza un'azione operativa consapevole, è un segnale di compromissione.

**Implementazione:** Wazuh monitora `/var/log/ufw.log` ma non ha rule built-in ad alto level per le modifiche alle regole (distinto dagli eventi di traffico). Serve un decoder custom per i log di `ufw` in modalità modifica e una rule dedicata.

### 8.6 Installazione pacchetti non pianificata — priorità bassa

**Perché è utile:** un `apt install` non pianificato su vm-103 può indicare che un attaccante sta installando tool post-compromissione (MITRE T1072). In un homelab l'aggiornamento del sistema è pianificato — qualsiasi installazione fuori da queste finestre è anomala.

**Rule built-in:** `2900` (dpkg/apt), level 3. Alzare il level o filtrare per orario fuori dalla finestra di manutenzione con una regola temporizzata.

### 8.7 Accesso a file sensibili fuori orario — priorità bassa

**Perché è utile:** combinando FIM con logica temporale, è possibile alertare solo quando un file critico viene modificato in orari inattesi (es. notte). Riduce i falsi positivi di UC-03 durante l'uso normale del Mac durante il giorno.

**Implementazione:** richiede una rule con `<time_after>` e `<time_before>` in Wazuh — funzionalità disponibile ma da configurare manualmente.

---

### 8.8 Notifiche infrastruttura SOC-01 — servizi HomeSOC

Oltre agli eventi di sicurezza puri, ci sono eventi operativi legati ai servizi che girano su SOC-01 che vale la pena ricevere in tempo reale. Sono distinti in due categorie: notifiche implementabili via Wazuh (log → decoder → rule → Slack) e notifiche implementabili via integrazione nativa del servizio stesso.

#### Greenbone (ct-102) — nuove vulnerabilità critiche

**Perché è utile:** Greenbone esegue scan periodici sulla LAN. Quando un host che era pulito presenta improvvisamente una vulnerabilità critica o high, è un segnale che qualcosa è cambiato — aggiornamento saltato, nuovo servizio esposto, device IoT con firmware obsoleto. Riceverlo in tempo reale evita di dover controllare la dashboard manualmente dopo ogni scan.

**Implementazione via Wazuh:** Greenbone scrive i risultati in log XML nel container. Si può configurare un logcollector su ct-102 che legge i report, un decoder che estrae severity/host/CVE e una rule che scatta per severity `Critical` o `High`.

**Implementazione nativa:** Greenbone Community Edition non ha webhook Slack nativa. L'approccio più pratico è un cron script su ct-102 che legge l'API GVM e scrive un log strutturato, poi Wazuh lo ingesta.

#### Uptime Kuma (ct-101) — servizio down/up

**Perché è utile:** Uptime Kuma monitora già tutti i servizi della rete (SOC-01, vm-103 dashboard, ct-102 Greenbone, vm-100 Home Assistant, NAS, gateway). Sapere in tempo reale che un servizio è andato giù — prima ancora di aprire la dashboard — è utile sia operativamente che come early warning di incidenti.

**Implementazione nativa:** Uptime Kuma ha integrazione Slack nativa. Non passa da Wazuh — è una webhook diretta. Si configura in **Settings → Notifications → Add Notification → Slack** nella UI di Uptime Kuma. È la soluzione più semplice e immediata tra tutte quelle in questa sezione, e può usare lo stesso canale `#homesoc-alerts` o un canale dedicato `#homesoc-uptime`.

#### Home Assistant (vm-100) — eventi di sicurezza domotica

**Perché è utile:** Home Assistant gestisce il Shelly relay (192.168.68.89), i Google Nest e potenzialmente le telecamere. Può rilevare eventi anomali: porta aperta in orari inattesi, motion detection di notte, device domotico che cambia stato senza automazione attiva.

**Implementazione nativa:** Home Assistant ha un'integrazione Slack nativa tramite il componente `notify.slack`. Si configura in `configuration.yaml` e può inviare notifiche su qualsiasi automazione. Non richiede Wazuh.

#### Proxmox (SOC-01) — VM/CT down inatteso

**Perché è utile:** se vm-103 (Wazuh) o ct-102 (Greenbone) si spengono inaspettatamente, il monitoring si interrompe silenziosamente. Proxmox non ha una webhook Slack nativa, ma scrive eventi nel proprio log (`/var/log/pve/tasks/`).

**Implementazione via Wazuh:** configurare un logcollector su SOC-01 che legge il log di Proxmox e triggera alert su eventi `qmstop` (VM spenta) o `vzstop` (CT spento) non pianificati. In alternativa, Uptime Kuma con probe HTTP verso i servizi esposti (porta 443 di vm-103, porta 9392 di Greenbone) copre già questo caso indirettamente.

#### CrowdSec (SOC-01) — IP bannato

**Perché è utile:** quando CrowdSec sarà operativo, ogni ban di un IP è un evento rilevante — indica un attacco attivo bloccato. CrowdSec ha integrazione nativa con Slack tramite il hub di notifiche.

**Implementazione:** configurabile dopo il deploy di CrowdSec tramite `cscli notifications` — sarà trattato nel runbook `crowdsec-deploy.md`.

---

### Tabella riepilogativa

**Notifiche Wazuh — sicurezza host e agenti**

| Notifica | Rule | Priorità | Effort | MITRE |
|---|---|---|---|---|
| Agent disconnesso | 501 → override 100050 | 🔴 Alta | Basso | — |
| SSH root login | 5715 → override 100051 | 🔴 Alta | Basso | T1078 |
| Sudo escalation anomala | 5402 → filtro custom | 🟠 Media | Medio | T1548.003 |
| Nuovo utente creato | 5902 → override 100052 | 🟠 Media | Basso | T1136 |
| Modifica regole UFW | custom decoder + rule | 🟠 Media | Alto | T1562.004 |
| apt install non pianificato | 2900 → override | 🟡 Bassa | Medio | T1072 |
| FIM fuori orario | UC-03 + time filter | 🟡 Bassa | Alto | T1565.001 |

**Notifiche infrastruttura SOC-01**

| Notifica | Servizio | Via | Priorità | Effort |
|---|---|---|---|---|
| Servizio down/up | Uptime Kuma | Integrazione nativa Slack | 🔴 Alta | Bassissimo |
| IP bannato | CrowdSec | cscli notifications | 🔴 Alta | Basso (post-deploy) |
| Vulnerabilità critica/high | Greenbone | Wazuh (script + log) | 🟠 Media | Alto |
| VM/CT down inatteso | Proxmox | Wazuh (logcollector) | 🟠 Media | Medio |
| Evento sicurezza domotica | Home Assistant | Integrazione nativa Slack | 🟡 Bassa | Basso |

> ℹ️ **Priorità immediata:** la notifica Uptime Kuma → Slack è la più facile da aggiungere (5 minuti di configurazione nella UI) e copre il caso più impattante — sapere quando un servizio critico del HomeSOC è offline.

---

## 9. Verifica finale e checklist

**Slack:**
- [ ] App `HomeSOC Wazuh` creata su api.slack.com
- [ ] Incoming Webhook attiva su `#homesoc-alerts`
- [ ] Webhook URL salvata nel password manager
- [ ] Test curl → `ok` + messaggio nel canale

**Configurazione Wazuh:**
- [ ] Backup `ossec.conf.bak-<DATA>` creato
- [ ] Blocco `<integration>` con tag `<n>` (non `<n>`) e URL reale
- [ ] `wazuh-analysisd -t` → nessun output (= OK)
- [ ] `wazuh-manager` riavviato e `active (running)`
- [ ] `wazuh-integratord` visibile con `ps aux | grep integratord`

**Script custom:**
- [ ] Backup `slack.py.bak-<DATA>` creato
- [ ] Script custom installato con `chown root:wazuh` e `chmod 750`

**Test end-to-end:**
- [ ] Log sintetico UC-06 iniettato nel path corretto (`/var/log/homesoc/rogue-device.log`)
- [ ] Alert UC-06 in `alerts.log` con rule 100040 e level 10
- [ ] Notifica Slack UC-06 con formato custom (emoji + campi strutturati)
- [ ] Test UC-01 SSH brute force → notifica Slack ricevuta
- [ ] `integrations.log` senza errori HTTP

---

## 10. Troubleshooting

### wazuh-manager non riparte dopo modifica ossec.conf

```bash
# Su vm-103
sudo journalctl -xeu wazuh-manager.service | tail -20
# Causa più comune: tag <n> invece di <n>

sudo grep -A6 "<integration>" /var/ossec/etc/ossec.conf
# Deve mostrare <n>slack</n>

# Ripristina backup se necessario
sudo cp /var/ossec/etc/ossec.conf.bak-$(date +%Y%m%d) /var/ossec/etc/ossec.conf
```

### wazuh-integratord non compare dopo riavvio

```bash
# Su vm-103
sudo grep -i "integrat\|error" /var/ossec/logs/ossec.log | tail -20

# Verifica URL presente e corretta
sudo grep hook_url /var/ossec/etc/ossec.conf

# Test diretto della URL
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"test"}' \
  "$(sudo grep -oP '(?<=<hook_url>)[^<]+' /var/ossec/etc/ossec.conf)"
```

### Nessuna notifica Slack dopo iniezione log

```bash
# Su vm-103
# Step 1: verifica alert generato
sudo grep "100040\|100030\|100001" /var/ossec/logs/alerts/alerts.log | tail -5
# Se vuoto: decoder non ha matchato — verificare formato e path del log

# Step 2: verifica path monitorato
sudo grep -A3 "rogue-device\|nas-monitor" /var/ossec/etc/ossec.conf | grep location

# Step 3: se alert c'è ma Slack no
sudo tail -30 /var/ossec/logs/integrations.log
```

### ls con glob su /var/ossec/etc/ restituisce "Permission denied"

```bash
# Il glob viene espanso dalla shell prima di sudo — usare:
sudo bash -c 'ls -lh /var/ossec/etc/ossec.conf.bak-*'
# oppure
sudo ls /var/ossec/etc/ | grep bak
```

### integrations.log riporta HTTP 403

Webhook URL revocata. Rigenerare su api.slack.com → App → Incoming Webhooks → Add New Webhook, aggiornare `ossec.conf` e riavviare `wazuh-manager`.

---

## Prossimi passi

1. Commit su Git — verificare che la webhook URL non sia nel file:
   ```bash
   grep hook_url wazuh-slack.md
   # Deve mostrare solo il placeholder

   git add wazuh-slack.md integrations/slack.py
   git commit -m "runbooks(wazuh-slack): v1.0 — Slack integration, script custom UC"
   ```

2. Aggiornare `CHANGELOG.md` con l'aggiunta dell'integrazione Slack e dello script custom.

3. Aggiornare `01-threat-model.md` sez. 6.1: "Notifiche Slack attive per UC-01, UC-03, UC-04, UC-06 (level ≥ 10)"

4. Valutare implementazione delle notifiche aggiuntive dalla sez. 8 — in particolare agent disconnect (100050) e SSH root login (100051), che hanno effort basso e valore alto.

5. Procedere con **`crowdsec-deploy.md`** (Fase 3 — installazione diretta su SOC-01)

---

*File: `wazuh-slack.md` · v1.0 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
