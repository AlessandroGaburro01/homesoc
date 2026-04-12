# Runbook — Home Assistant OS Deploy (vm-100)
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `runbooks/homeassistant-deploy.md`  
**Versione:** 1.0 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 2 — Deploy  
**Prerequisito:** `runbooks/proxmox-setup.md` completato — SOC-01 operativo, pool `phase2` creato

> **Scopo:** Creare e configurare `vm-100` su Proxmox VE con Home Assistant OS (HAOS). Al termine di questo runbook HAOS deve essere raggiungibile via browser, configurato con IP statico DHCP reservation, autenticazione MFA attiva, e pronto a integrare i device IoT della rete domestica come fonte di osservabilità per il SOC.

---

## Indice

1. [Prerequisiti](#1-prerequisiti)
2. [Creazione VM su Proxmox](#2-creazione-vm-su-proxmox)
3. [Download e import immagine HAOS](#3-download-e-import-immagine-haos)
4. [Configurazione VM — impostazioni finali](#4-configurazione-vm--impostazioni-finali)
5. [Primo avvio e onboarding](#5-primo-avvio-e-onboarding)
6. [IP statico — DHCP reservation](#6-ip-statico--dhcp-reservation)
7. [Hardening e sicurezza](#7-hardening-e-sicurezza)
8. [Integrazioni SOC-rilevanti](#8-integrazioni-soc-rilevanti)
9. [Backup snapshot](#9-backup-snapshot)
10. [Verifica finale e checklist](#10-verifica-finale-e-checklist)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Prerequisiti

### 1.1 Requisiti infrastrutturali

Prima di procedere verificare che il runbook `proxmox-setup.md` sia completato al 100%:

```bash
# Su SOC-01 — verifica che Proxmox sia operativo
pveversion
# Output atteso: pve-manager/8.x.x

# Verifica storage disponibile
pvesm status
# local-lvm deve avere ≥ 80 GB liberi (totale Fase 2)

# Verifica RAM disponibile
free -h
# Deve essere disponibile almeno 2 GB per vm-100

# Verifica che il pool phase2 esista
pvesh get /pools/phase2
```

> ✅ **Checkpoint:** Se uno di questi comandi fallisce, tornare al runbook `proxmox-setup.md` e completare le verifiche mancanti prima di continuare.

### 1.2 Specifiche vm-100

| Parametro | Valore |
|---|---|
| VM ID | `100` |
| Nome | `vm-100-homeassistant` |
| OS | Home Assistant OS (HAOS) — immagine ufficiale |
| vCPU | 2 |
| RAM | 2 GB (2048 MB) — balloon abilitato, min 1 GB |
| Storage | 32 GB su `local-lvm` |
| Network | `vmbr0` (LAN — 192.168.68.0/24) |
| Boot firmware | **UEFI** (obbligatorio per HAOS) |
| Machine type | `q35` |
| IP target | `192.168.68.201` (DHCP reservation da impostare) |

> ⚠️ HAOS **richiede** UEFI e machine type `q35`. Una VM creata con BIOS SeaBIOS non avvierà correttamente l'immagine ufficiale.

### 1.3 Informazioni di rete

| Parametro | Valore |
|---|---|
| IP vm-100 | `192.168.68.201` (DHCP reservation) |
| Gateway | `192.168.68.1` (Deco BE65) |
| DNS | `192.168.68.1` |
| Porta Web UI HAOS | `8123/tcp` |
| MAC da annotare | Leggere dopo creazione VM (passo 2.5) |

### 1.4 Software richiesto (MacBook admin)

- Browser moderno — accesso Web UI Proxmox (`https://192.168.68.200:8006`) e HAOS (`http://192.168.68.201:8123`)
- Client SSH — accesso a SOC-01 per i comandi CLI
- `curl` (preinstallato su macOS)

---

## 2. Creazione VM su Proxmox

La creazione si esegue dalla **Web UI Proxmox** (`https://192.168.68.200:8006`) tramite la procedura guidata, oppure interamente via CLI (metodo alternativo in sezione 2.6).

### 2.1 Avvia la creazione guidata

**Web UI:** `soc-01` → **Create VM** (pulsante in alto a destra)

### 2.2 Tab "General"

| Campo | Valore |
|---|---|
| Node | `soc-01` |
| VM ID | `100` |
| Name | `vm-100-homeassistant` |
| Pool | `phase2` |

### 2.3 Tab "OS"

| Campo | Valore |
|---|---|
| Use CD/DVD disc image | **Deselezionare** — nessuna ISO (l'OS viene importato come disco) |
| Guest OS — Type | `Linux` |
| Guest OS — Version | `6.x - 2.6 Kernel` |

### 2.4 Tab "System"

| Campo | Valore |
|---|---|
| Machine | `q35` ← **obbligatorio** |
| BIOS | `OVMF (UEFI)` ← **obbligatorio** |
| EFI Storage | `local-lvm` |
| EFI Disk size | `4M` (default) |
| Pre-Enroll keys | **deselezionare** |
| SCSI Controller | `VirtIO SCSI single` |
| Qemu Agent | ✅ **Abilitare** |

### 2.5 Tab "Disks"

> ⚠️ **ELIMINARE il disco proposto dal wizard.** Il disco di HAOS viene importato separatamente nel passo 3. Cliccare sull'icona cestino accanto al disco proposto e procedere con "Next".

Il risultato deve essere: **nessun disco configurato** in questa fase.

### 2.6 Tab "CPU"

| Campo | Valore |
|---|---|
| Sockets | `1` |
| Cores | `2` |
| Type | `x86-64-v2-AES` (o `host` per prestazioni migliori — scelta conservativa: `x86-64-v2-AES`) |

### 2.7 Tab "Memory"

| Campo | Valore |
|---|---|
| Memory (MiB) | `2048` |
| Ballooning Device | ✅ **Abilitare** |
| Minimum memory (MiB) | `1024` |

### 2.8 Tab "Network"

| Campo | Valore |
|---|---|
| Bridge | `vmbr0` |
| Model | `VirtIO (paravirtualized)` |
| VLAN Tag | *(lasciare vuoto)* |
| Firewall | ✅ Abilitare (Proxmox firewall layer) |

> 📌 **Annotare il MAC address** mostrato in questa schermata — servirà per la DHCP reservation su Deco BE65 (passo 6).

### 2.9 Tab "Confirm"

Rivedere il riepilogo. Verificare:
- Machine: `q35`
- BIOS: `OVMF (UEFI)`
- CPU: 2 core
- RAM: 2048 MB
- Nessun disco aggiuntivo rispetto al disco EFI

**Deselezionare** "Start after created" — la VM deve essere avviata **solo dopo** l'import del disco (passo 3).

Click **Finish**.

---

## 3. Download e import immagine HAOS

L'immagine ufficiale HAOS è distribuita in formato `.qcow2` (KVM/QEMU). Viene importata direttamente in Proxmox come disco virtuale della VM.

### 3.1 Download immagine HAOS su SOC-01

Accedere a SOC-01 via SSH:

```bash
ssh -p 2222 root@192.168.68.200
```

Scaricare l'immagine HAOS per KVM/QEMU:

```bash
# Verifica la versione più recente su:
# https://github.com/home-assistant/operating-system/releases
# Cerca il file: haos_ova-X.X.qcow2.xz

# Crea directory di lavoro temporanea
mkdir -p /tmp/haos-import && cd /tmp/haos-import

# Scarica l'immagine (sostituire X.X con la versione attuale)
# Esempio con versione 13.x (verificare la più recente sul sito)
HAOS_VERSION="13.2"
curl -L -O "https://github.com/home-assistant/operating-system/releases/download/${HAOS_VERSION}/haos_ova-${HAOS_VERSION}.qcow2.xz"

# Verifica dimensione download (~300-400 MB compressa)
ls -lh haos_ova-${HAOS_VERSION}.qcow2.xz
```

> ✅ **Checkpoint:** Il file `.qcow2.xz` deve essere scaricato completamente. Se il download si interrompe, usare `curl -C - -L -O` per riprendere.

### 3.2 Verifica SHA256

```bash
# Scarica il file di checksum
curl -L -O "https://github.com/home-assistant/operating-system/releases/download/${HAOS_VERSION}/haos_ova-${HAOS_VERSION}.qcow2.xz.sha256"

# Verifica integrità
sha256sum -c haos_ova-${HAOS_VERSION}.qcow2.xz.sha256
# Output atteso: haos_ova-X.X.qcow2.xz: OK
```

> ⚠️ Non procedere se la verifica SHA256 fallisce. Il file è corrotto — riscaricarlo.

### 3.3 Decompressione immagine

```bash
# Decomprime l'archivio xz (operazione ~30 secondi)
xz -d haos_ova-${HAOS_VERSION}.qcow2.xz

# Verifica risultato (file .qcow2 decompresso, ~1-2 GB)
ls -lh haos_ova-${HAOS_VERSION}.qcow2
```

### 3.4 Import disco in Proxmox (vm-100)

```bash
# Importa l'immagine come disco SCSI della vm-100
# Sintassi: qm importdisk <vmid> <source> <storage>
qm importdisk 100 haos_ova-${HAOS_VERSION}.qcow2 local-lvm

# Output atteso (l'operazione richiede 1-3 minuti):
# importing disk '/tmp/haos-import/haos_ova-X.X.qcow2' to VM 100 ...
# Successfully imported disk as 'unused0:local-lvm:vm-100-disk-1'
```

> ✅ **Checkpoint:** Al termine il disco appare come `unused0` nella configurazione VM (visibile in Web UI: `vm-100` → Hardware → `unused0`).

### 3.5 Pulizia file temporanei

```bash
# Rimuovi i file di import temporanei
cd /tmp && rm -rf haos-import/
```

---

## 4. Configurazione VM — impostazioni finali

Dopo l'import del disco è necessario collegarlo alla VM e configurare l'ordine di boot.

### 4.1 Collegare il disco importato

**Via Web UI:**

1. `vm-100` → **Hardware** → selezionare `Unused Disk 0`
2. Click **Edit**
3. Impostare:
   - Bus/Device: `SCSI` → `scsi0`
   - Cache: `Write back` (migliori performance con HAOS)
   - SSD emulation: ✅ abilitare (ottimizza comportamento disco)
   - Discard: ✅ abilitare (TRIM support)
4. Click **Add**

**Alternativa via CLI:**

```bash
# Collega il disco (verificare il nome esatto con: qm config 100 | grep unused)
qm set 100 --scsi0 local-lvm:vm-100-disk-1,cache=writeback,ssd=1,discard=on

# Verifica configurazione
qm config 100 | grep scsi
```

### 4.2 Configurare boot order

**Via Web UI:**

1. `vm-100` → **Options** → **Boot Order** → **Edit**
2. Abilitare solo `scsi0` come dispositivo di boot
3. Trascinare `scsi0` in prima posizione
4. Disabilitare eventuali altri dispositivi (net0, ide2)
5. Click **OK**

**Alternativa via CLI:**

```bash
qm set 100 --boot order=scsi0
```

### 4.3 Ridimensionamento disco (opzionale — consigliato)

HAOS gestisce automaticamente lo spazio disponibile al primo avvio. Il disco importato è ~32 GB by design nella nostra specifica — verificare:

```bash
# Verifica dimensione disco attuale
qm config 100 | grep scsi0
# Output atteso: scsi0: local-lvm:vm-100-disk-1,size=32G

# Se la dimensione fosse minore (es. 6G — dimensione immagine di default HAOS)
# espandere a 32G:
qm resize 100 scsi0 32G
```

> ℹ️ HAOS al primo avvio espande automaticamente la sua partizione dati sull'intero spazio disponibile del disco.

### 4.4 Aggiunta note VM

**Web UI:** `vm-100` → **Notes** → Edit

```
vm-100 — Home Assistant OS
Deploy: Aprile 2026 | HAOS v13.x
IP: 192.168.68.201 (DHCP reservation)
Web UI: http://192.168.68.201:8123
Fase 2 HomeSOC — pool: phase2
```

### 4.5 Riepilogo configurazione finale

Verificare con `qm config 100`:

```bash
qm config 100
```

Output atteso:

```
balloon: 1024
boot: order=scsi0
cores: 2
efidisk0: local-lvm:vm-100-disk-0,efitype=4m,pre-enrolled-keys=0,size=4M
machine: pc-q35-8.x
memory: 2048
meta: creation-qemu=8.x.x,ctime=...
name: vm-100-homeassistant
net0: virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr0,firewall=1
numa: 0
ostype: l26
pool: phase2
scsi0: local-lvm:vm-100-disk-1,cache=writeback,discard=on,size=32G,ssd=1
scsihw: virtio-scsi-single
sockets: 1
vga: std
vmgenid: ...
```

---

## 5. Primo avvio e onboarding

### 5.1 Avvio vm-100

**Web UI:** `vm-100` → **Start**

Oppure via CLI:

```bash
qm start 100

# Monitora l'avvio tramite console
# Web UI: vm-100 → Console (pulsante ">_")
```

### 5.2 Monitoraggio boot via console Proxmox

**Web UI:** `vm-100` → **Console**

Il boot HAOS passa attraverso le seguenti fasi (durata totale: ~3-5 minuti al primo avvio):

1. `GRUB UEFI bootloader` — schermata boot
2. `ha-boot` — inizializzazione sistema base
3. `Resizing data partition...` — espansione disco (solo primo avvio)
4. `Starting Home Assistant Supervisor...`
5. `Home Assistant Core installing...` — **questo passo richiede 5-10 minuti** con download componenti

```bash
# Alternativa: monitora dalla console Proxmox direttamente
# Attendere la riga finale nella console:
# "Home Assistant is running"
# oppure verificare che la porta 8123 sia in ascolto:

# Da SOC-01 — polling sull'IP assegnato da DHCP (prima della reservation):
# Nota: HAOS ottiene un IP DHCP dal Deco al primo avvio — vedere passo 5.3
```

### 5.3 Identificare l'IP iniziale assegnato da DHCP

Prima di configurare la reservation statica, identificare l'IP DHCP assegnato da Deco BE65 a HAOS:

```bash
# Da SOC-01 — scansiona la rete per trovare il nuovo device
# (installare nmap se non presente)
apt install -y nmap

# Scan host attivi sulla subnet
nmap -sn 192.168.68.0/24 | grep -E "report for|MAC"
```

Alternativa via Deco BE65:
1. Aprire l'app **TP-Link Deco** sul telefono
2. **More** → **Advanced** → **DHCP Server** → **Client List**
3. Identificare il device con hostname `homeassistant` o `haos`

> 📌 **Annotare l'IP DHCP temporaneo** — servirà per accedere alla Web UI nel passo 5.4 e per leggere il MAC address per la reservation (passo 6).

### 5.4 Accesso Web UI per onboarding iniziale

```
http://<IP-DHCP-temporaneo>:8123
```

Il browser mostrerà la schermata **"Preparing Home Assistant"** con una barra di progresso. Attendere il completamento (può richiedere fino a 10-15 minuti per il download dei componenti al primo avvio).

> ✅ **Checkpoint:** Quando compare la schermata **"Welcome to Home Assistant"** (setup wizard), la fase di installazione è completa.

### 5.5 Procedura di onboarding

**Schermata "Create your account":**

| Campo | Valore |
|---|---|
| Name | `Alessandro` |
| Username | `ale` (o username preferito — non usare `admin` o `homeassistant`) |
| Password | Password complessa ≥16 caratteri (annotare in gestore password) |
| Confirm Password | *(ripetere)* |

Click **Create Account**.

**Schermata "What do you want to call your home?":**

| Campo | Valore |
|---|---|
| Name | `HomeSOC` |
| Latitude / Longitude | Inserire coordinate casa *(opzionale — utile per automazioni sun-based)* |
| Elevation | *(opzionale)* |
| Unit system | `Metric` |
| Currency | `Euro (€)` |

**Schermata "Select your integrations":**

HAOS proporrà integrazioni rilevate automaticamente (dispositivi Philips Hue, Google Cast, etc.). Per ora: **Skip this step** — le integrazioni verranno aggiunte con criterio nelle sezioni successive.

**Schermata "Finish":**

Click **Finish** → si accede alla dashboard principale di HAOS.

---

## 6. IP statico — DHCP reservation

### 6.1 Leggere il MAC address di vm-100

**Metodo 1 — Da Proxmox Web UI:**

`vm-100` → **Hardware** → `net0` → il MAC address è visibile nel campo VirtIO.

**Metodo 2 — Da CLI Proxmox:**

```bash
qm config 100 | grep net0
# Output: net0: virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr0,firewall=1
# Il MAC address è XX:XX:XX:XX:XX:XX
```

**Metodo 3 — Da Web UI HAOS:**

`Settings` → `System` → `Network` → selezionare l'interfaccia di rete → il MAC è visibile nella scheda.

> 📌 **Annotare il MAC address** nel file `docs/Inventario_IP_Pulito.csv` del progetto.

### 6.2 Creare DHCP reservation su Deco BE65

1. Aprire l'app **TP-Link Deco** sul telefono
2. **More** → **Advanced** → **DHCP Server**
3. Nella sezione **Reservations** → **Add**
4. Inserire:
   - **IP Address:** `192.168.68.201`
   - **MAC Address:** *(MAC letto al passo 6.1)*
   - **Device Name:** `vm-100-homeassistant`
5. **Save**

### 6.3 Applicare il nuovo IP

HAOS deve essere riavviato per acquisire il nuovo IP dalla reservation DHCP:

```bash
# Da SOC-01 — riavvia la VM
qm reboot 100

# Attendi ~2 minuti, poi verifica che il nuovo IP sia attivo
ping -c 4 192.168.68.201
```

**Alternativa — reboot da Web UI HAOS:**

`Settings` → `System` → `Restart` → **Restart Home Assistant** (questo riavvia solo il software; per cambiare IP serve riavviare la VM intera da Proxmox come sopra).

> ✅ **Checkpoint:** `ping 192.168.68.201` deve rispondere. La Web UI HAOS deve essere raggiungibile su `http://192.168.68.201:8123`.

### 6.4 Aggiornare la configurazione rete interna HAOS (opzionale ma consigliato)

Per rendere l'IP statico a livello di sistema operativo HAOS (ridondanza rispetto alla DHCP reservation):

**Web UI HAOS:** `Settings` → `System` → `Network`

1. Selezionare l'interfaccia di rete (es. `eth0`)
2. Passare da `Automatic (DHCP)` a `Static`
3. Inserire:
   - IP address: `192.168.68.201/24`
   - Gateway: `192.168.68.1`
   - DNS: `192.168.68.1`
4. **Save** → **Apply**

> ⚠️ Dopo aver applicato la configurazione statica interna, aggiornare l'URL del browser a `http://192.168.68.201:8123`.

---

## 7. Hardening e sicurezza

### 7.1 Aggiornamento iniziale HAOS

```
Settings → System → Updates
```

Verificare e installare tutti gli aggiornamenti disponibili per:
- **Home Assistant Core**
- **Home Assistant OS**
- **Home Assistant Supervisor**

Oppure da `Settings` → `System` → cercare il badge "Update available".

### 7.2 Abilitare autenticazione MFA (TOTP)

> ⚠️ **Step critico per il portfolio HomeSOC.** L'accesso HAOS senza MFA è inaccettabile — espone la gestione IoT di casa a chiunque acceda alla porta 8123.

**Web UI HAOS:** *(già loggato come `ale`)*

1. Click sull'icona profilo in basso a sinistra
2. `Profile` → sezione **Multi-factor Authentication**
3. Click **Enable** accanto a **TOTP**
4. Scansionare il QR code con un'app TOTP (Bitwarden/Aegis/Authy)
5. Inserire il codice a 6 cifre per confermare
6. Salvare i **backup codes** in un posto sicuro (gestore password)

> ✅ **Checkpoint:** Al prossimo login su `http://192.168.68.201:8123` verrà richiesto il codice TOTP.

### 7.3 Disabilitare accesso remoto cloud non necessario

HAOS di default abilita il **Nabu Casa** cloud relay per accesso remoto. Per il HomeSOC l'accesso remoto è gestito tramite Tailscale (già configurato su SOC-01):

**Web UI HAOS:** `Settings` → `Home Assistant Cloud`

Verificare che **Nabu Casa** non sia attivato (o disabilitarlo se attivo) — l'accesso avverrà esclusivamente via Tailscale sulla VPN mesh.

### 7.4 Configurare trusted networks e protezione accessi

Modificare `configuration.yaml` per limitare l'accesso HTTP a IP interni:

**Web UI HAOS:** `Settings` → `Add-ons` → installare **Studio Code Server** (o accedere tramite **File Editor**)

Aggiungere alla fine di `configuration.yaml`:

```yaml
# Sicurezza HTTP — solo LAN + Tailscale
http:
  use_x_forwarded_for: false
  trusted_proxies: []
  ip_ban_enabled: true
  login_attempts_threshold: 5

# Logger — log level per diagnostica SOC
logger:
  default: warning
  logs:
    homeassistant.components.http: info
```

Riavviare HAOS per applicare: `Developer Tools` → **Restart**.

### 7.5 Installare HACS (Home Assistant Community Store) — opzionale

HACS permette di installare integrazioni community, incluse quelle utili per il SOC (es. webhook avanzati, integrazioni Uptime Kuma).

```bash
# Da SOC-01 — esegue lo script di installazione HACS nella VM tramite
# HAOS Advanced SSH (richiede add-on SSH & Web Terminal installato prima)
# Oppure via Add-on Store da Web UI — metodo consigliato:
```

**Web UI HAOS:** `Settings` → `Add-ons` → **Add-on Store** → cercare **SSH & Web Terminal** → Install → Start.

Una volta installato SSH:

```bash
# Connetti alla shell HAOS tramite il terminale del browser
# (SSH & Web Terminal add-on → OPEN WEB UI)

# Installa HACS
wget -O - https://get.hacs.xyz | bash -
# Riavvia HAOS quando richiesto
```

> ℹ️ HACS è opzionale in Fase 2 ma consigliato per le integrazioni delle fasi successive (Wazuh webhook, TheHive, etc.).

---

## 8. Integrazioni SOC-rilevanti

Questa sezione configura le integrazioni direttamente utili per il HomeSOC come fonte di osservabilità.

### 8.1 Inventario device IoT tramite integrazioni native

**Web UI HAOS:** `Settings` → `Devices & Services` → **Add Integration**

Aggiungere le integrazioni per i device IoT presenti in rete (dal threat model `01-threat-model.md`):

| Integrazione | Device target | Motivo SOC |
|---|---|---|
| **TP-Link Tapo** | Telecamere Tapo | Visibility telecamere, alert offline |
| **Shelly** | Shelly relay | Monitoring availability |
| **Roborock** | Robot Roborock (negozio) | Tracking attività |
| **Dreame** | Robot vacuum | Visibility attività IoT |
| **Google Cast** | Nest Hub, TV | Asset tracking |

> ℹ️ Non aggiungere integrazioni cloud esterne non necessarie. Privilegiare integrazioni locali (LAN-only) dove possibile per ridurre la superficie di attacco.

### 8.2 Uptime Kuma — webhook integration (preparazione Fase 2)

Uptime Kuma (ct-101, prossimo runbook) si integra con HAOS tramite webhook per inviare alert di availability nella dashboard SOC. Preparare il webhook endpoint in HAOS:

**Web UI HAOS:** `Settings` → `Automations & Scenes` → **Create Automation**

```yaml
# Automazione: ricezione alert Uptime Kuma
alias: "SOC - Uptime Kuma Alert"
description: "Riceve webhook da Uptime Kuma e notifica via mobile app"
trigger:
  - platform: webhook
    webhook_id: "uptimekuma-homesoc-alert"
    allowed_methods:
      - POST
    local_only: true
condition: []
action:
  - service: notify.mobile_app
    data:
      title: "⚠️ HomeSOC Alert"
      message: "{{ trigger.json.msg }}"
      data:
        tag: "uptime-kuma"
        channel: "HomeSOC Alerts"
mode: single
```

> 📌 Il `webhook_id` (`uptimekuma-homesoc-alert`) verrà usato nel runbook Uptime Kuma per configurare la notifica.

L'URL del webhook sarà:
```
http://192.168.68.201:8123/api/webhook/uptimekuma-homesoc-alert
```

### 8.3 Mobile App — notifiche push SOC

Installare **Home Assistant Companion App** sullo smartphone per ricevere alert push dal SOC:

1. Scaricare **Home Assistant** dall'App Store / Google Play
2. Aprire l'app → inserire l'indirizzo: `http://192.168.68.201:8123`
3. Effettuare il login → autorizzare l'integrazione con il dispositivo mobile
4. L'app registra automaticamente il servizio `notify.mobile_app_<dispositivo>`

> ✅ **Checkpoint:** Da `Developer Tools` → `Services` → `notify.mobile_app_<dispositivo>` → test invio notifica → lo smartphone riceve la notifica.

### 8.4 Configurazione dashboard SOC minimale

Creare una dashboard dedicata al monitoring del SOC per Fase 2:

**Web UI HAOS:** `Overview` → *(icona matita in alto a destra)* → **Manage Dashboards** → **Add Dashboard**

| Campo | Valore |
|---|---|
| Title | `HomeSOC Monitor` |
| Icon | `mdi:shield-check` |
| URL | `homesoc` |

Aggiungere card iniziali:

- **Entities card** — status device IoT critici (robot, telecamere, relay)
- **Logbook card** — attività recenti device
- **History Graph** — uptime device selezionati

*(Il popolamento completo della dashboard avviene progressivamente nelle fasi successive con dati da Wazuh, Greenbone, Uptime Kuma.)*

---

## 9. Backup snapshot

### 9.1 Backup automatico HAOS interno

HAOS include un sistema di backup interno. Configurare backup automatici giornalieri:

**Web UI HAOS:** `Settings` → `System` → **Backups** → **Automatic backups**

| Campo | Valore |
|---|---|
| Backup enabled | ✅ Abilitare |
| Schedule | `01:30` (30 min prima del backup vzdump Proxmox) |
| Keep last | `3` backup |
| Location | `default_backup` (storage interno HAOS) |

> ℹ️ Il backup interno HAOS salva la configurazione, automazioni, integrazioni e dati in formato `.tar`. È complementare allo snapshot Proxmox (che fa il backup dell'intera VM incluso l'OS).

### 9.2 Snapshot Proxmox manuale pre-configurazione

Prima di procedere con eventuali modifiche avanzate, eseguire uno snapshot Proxmox dello stato pulito:

```bash
# Da SOC-01
# Crea snapshot con etichetta descrittiva
qm snapshot 100 "haos-base-configured" --description "HAOS v$(cat /etc/os-release | grep VERSION_ID | cut -d= -f2) — configurazione base completata — MFA attivo — Aprile 2026"

# Verifica snapshot creato
qm listsnapshot 100
```

Output atteso:
```
             PARENT             SNAPNAME       TIME      DESCRIPTION
                                    current
                               haos-base-configured  XXXXXX  HAOS vX.X — configurazione base ...
```

### 9.3 Backup vzdump (Proxmox) — verifica inclusione in job schedulato

Verificare che vm-100 sia inclusa nel job di backup schedualto (configurato nel runbook proxmox-setup.md):

```bash
# Verifica configurazione backup job
cat /etc/pve/jobs.cfg | grep -A 20 "vzdump"
```

Se vm-100 non è inclusa, aggiungere manualmente:

**Web UI Proxmox:** `Datacenter` → `Backup` → selezionare il job esistente → **Edit** → selezionare `vm-100` nella lista VM.

---

## 10. Verifica finale e checklist

### 10.1 Checklist di completamento

**VM e Proxmox:**
- [ ] VM `vm-100-homeassistant` creata con ID 100
- [ ] Machine type `q35`, BIOS `OVMF (UEFI)` — verificare in `qm config 100`
- [ ] Disco `scsi0` 32 GB su `local-lvm` collegato e configurato
- [ ] `qemu-guest-agent` abilitato nella configurazione VM
- [ ] VM nel pool `phase2`
- [ ] Note VM aggiornate con IP e versione

**HAOS — Installazione:**
- [ ] HAOS avviato correttamente, porta 8123 raggiungibile
- [ ] Onboarding completato (account `ale`, home `HomeSOC`)
- [ ] Tutti gli update HAOS applicati (Core + OS + Supervisor)

**Rete:**
- [ ] MAC address vm-100 annotato in `Inventario_IP_Pulito.csv`
- [ ] DHCP reservation `192.168.68.201` creata su Deco BE65
- [ ] IP statico interno HAOS configurato (`192.168.68.201/24`, GW `192.168.68.1`)
- [ ] `ping 192.168.68.201` → OK da SOC-01 e MacBook
- [ ] Web UI `http://192.168.68.201:8123` raggiungibile

**Sicurezza:**
- [ ] MFA TOTP abilitato per utente `ale`
- [ ] Login HAOS verificato con codice TOTP
- [ ] Backup codes TOTP salvati nel gestore password
- [ ] `ip_ban_enabled: true`, `login_attempts_threshold: 5` in `configuration.yaml`
- [ ] Nabu Casa cloud disabilitato (accesso solo via Tailscale/LAN)

**Integrazioni:**
- [ ] Almeno 1 integrazione device IoT configurata
- [ ] Webhook Uptime Kuma configurato (`uptimekuma-homesoc-alert`)
- [ ] Mobile app installata e notifica di test ricevuta
- [ ] Dashboard `HomeSOC Monitor` creata

**Backup:**
- [ ] Backup automatico HAOS interno configurato (01:30, keep 3)
- [ ] Snapshot Proxmox `haos-base-configured` creato
- [ ] vm-100 inclusa nel job backup vzdump schedulato

### 10.2 Comandi diagnostici di riepilogo

```bash
# Da SOC-01
echo "=== VM Status ===" && qm status 100
echo "=== VM Config ===" && qm config 100
echo "=== VM Snapshots ===" && qm listsnapshot 100
echo "=== Network Ping HAOS ===" && ping -c 3 192.168.68.201
echo "=== Port 8123 Check ===" && nc -zv 192.168.68.201 8123 && echo "OPEN" || echo "CLOSED"
echo "=== Storage ===" && pvesm status
echo "=== RAM disponibile ===" && free -h
```

Output atteso:

```
=== VM Status ===
status: running
=== Port 8123 Check ===
Connection to 192.168.68.201 8123 port [tcp/*] succeeded!
OPEN
```

---

## 11. Troubleshooting

### HAOS non avvia — schermata nera nella console

**Causa più comune:** VM creata con BIOS SeaBIOS invece di OVMF (UEFI).

```bash
# Verifica la configurazione
qm config 100 | grep bios
# Se output è "bios: seabios" → PROBLEMA

# Correggi: spegni la VM e cambia BIOS
qm stop 100
qm set 100 --bios ovmf --machine q35
qm start 100
```

> ⚠️ Se la VM era già avviata con SeaBIOS, potrebbe essere necessario ricreare l'EFI disk. Consultare la documentazione HAOS su community.home-assistant.io.

### Porta 8123 non raggiungibile dopo il boot

HAOS richiede tempo per l'inizializzazione. Attendere fino a 15 minuti al primo avvio.

```bash
# Verifica che la VM sia in running
qm status 100

# Monitora il boot dalla console Proxmox (Web UI: vm-100 → Console)
# Attendere il messaggio "Home Assistant is running" o simile

# Dopo ~10 minuti, verifica la porta
nc -zv 192.168.68.201 8123
```

Se dopo 15 minuti la porta non risponde, verificare che HAOS abbia ottenuto un IP:

```bash
# Scansiona la rete
nmap -sn 192.168.68.0/24 | grep -B1 "homeassistant\|haos"
```

### HAOS ottiene IP diverso dalla reservation

```bash
# Verifica che la reservation DHCP sul Deco sia per il MAC corretto
qm config 100 | grep net0
# Confrontare il MAC con quello nella reservation Deco
```

Se il MAC non corrisponde, aggiornare la reservation sul Deco BE65 con il MAC corretto letto da `qm config 100`.

### Disco importato non visibile come unused0

```bash
# Verifica lo stato dell'import
qm config 100

# Se non compare unused0, verifica nello storage
pvesm list local-lvm | grep vm-100

# Re-import se necessario (prima rimuovere disco eventualmente parziale)
qm importdisk 100 /tmp/haos_ova-XX.qcow2 local-lvm --format raw
```

### HAOS mostra errore "Login failed" dopo MFA

Verificare che l'orario di sistema di SOC-01 sia sincronizzato (TOTP è time-sensitive):

```bash
# Verifica sincronizzazione NTP
timedatectl status
# "System clock synchronized: yes" → OK

# Se non sincronizzato
timedatectl set-ntp true
systemctl restart systemd-timesyncd
```

### Cannot connect after IP change to 192.168.68.201

```bash
# Flush ARP cache sul MacBook
sudo arp -d 192.168.68.201

# Verifica che il Deco abbia assegnato il nuovo IP
# App Deco → DHCP Client List → cercare vm-100-homeassistant / 192.168.68.201

# Test connettività da SOC-01
ping -c 4 192.168.68.201
curl -s -o /dev/null -w "%{http_code}" http://192.168.68.201:8123
# Atteso: 200 (o redirect 302)
```

---

## Prossimi passi

Dopo aver completato e verificato questa checklist:

1. Commit su Git:
   ```bash
   git add runbooks/homeassistant-deploy.md
   git commit -m "runbooks(homeassistant): add Phase 2 deploy runbook v1.0"
   ```

2. Aggiornare `docs/Inventario_IP_Pulito.csv` con:
   - IP: `192.168.68.201`
   - MAC: *(valore letto da `qm config 100`)*
   - Hostname: `vm-100-homeassistant`
   - Servizio: `Home Assistant OS 8123/tcp`

3. Procedere con il runbook successivo: **`runbooks/uptimekuma-deploy.md`**
   - Crea ct-101 su Proxmox (2 vCPU, 1 GB RAM, 16 GB, vmbr0)
   - Installa Uptime Kuma + Portainer in container LXC Debian 12
   - Configura probe su tutti gli asset della rete (`192.168.68.0/24`)
   - Configura webhook verso HAOS (`192.168.68.201:8123/api/webhook/uptimekuma-homesoc-alert`)

4. Procedere con: **`runbooks/greenbone-deploy.md`**
   - Crea ct-102 su Proxmox (4 vCPU, 4 GB RAM, 32 GB, vmbr0)
   - Installa Greenbone Community Edition
   - Prima scan: UC-05 — Vulnerabilità su POS/Cassa Negozio

---

*File: `runbooks/homeassistant-deploy.md` · v1.0 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
