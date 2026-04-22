# Runbook — Wazuh SIEM Deploy (vm-103)
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `runbooks/wazuh-deploy.md`  
**Versione:** 1.3 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 3 — SIEM & Detection  
**Prerequisito:** `runbooks/proxmox-setup.md` completato — SOC-01 operativo, pool `phase2` creato; RAM SOC-01 aggiornata a **32 GB** (vm-103 non entra nel layout a 16 GB)

> **Scopo:** Creare e configurare `vm-103` su Proxmox VE come VM Ubuntu 22.04 LTS, installare Wazuh 4.x in configurazione single-node (Manager + Indexer + Dashboard), enrollare il Wazuh Agent sul MacBook Pro M1 (END-05), e deployare le detection rule custom per UC-01, UC-02, UC-03, UC-04 e UC-06 mappate sul threat model del progetto. Al termine di questo runbook Wazuh deve essere operativo, la Dashboard deve mostrare eventi attivi dal MacBook, e tutte le regole custom devono essere caricate e testate.

**Changelog:**
- v1.3 — Aprile 2026 — Fix FP UC-04: nas-monitor.sh guard NAS offline (previene FP post-reboot), local_rules.xml v1.3 (regole 100030/100031 riscritte per decoder nas-monitor-fields, aggiunta rule 100032 nas_offline L3, fix frequency/timeframe come attributi su 100001/100002/100011)
- v1.2 — Aprile 2026 — Fase 3 completa: FIM workaround macOS (script MD5/diff, rule 100023), UC-04 operativo (NAS port monitor, script nas-monitor.sh, regole 100030/100031), fix username alessandrogaburro, decoder fim-macos e nas-monitor, tutti UC operativi
- v1.1 — Aprile 2026 — Fix post-deploy: decoder nextdns (parent/child + pcre2), decoder rogue-device (program_name), script nextdns (campo status/domain/reasons), regola 100041 (frequency/timeframe attributi), nmap parser, nota FDA macOS UC-03, UC-04 deferred (WD NAS no syslog)
- v1.0 — Aprile 2026 — Prima stesura

---

## Indice

1. [Prerequisiti](#1-prerequisiti)
2. [Creazione VM su Proxmox](#2-creazione-vm-su-proxmox)
3. [Installazione Ubuntu 22.04 LTS](#3-installazione-ubuntu-2204-lts)
4. [Configurazione base del sistema](#4-configurazione-base-del-sistema)
5. [Installazione Wazuh single-node](#5-installazione-wazuh-single-node)
6. [Primo accesso Dashboard](#6-primo-accesso-dashboard)
7. [Installazione Wazuh Agent su macOS M1](#7-installazione-wazuh-agent-su-macos-m1)
8. [Configurazione FIM su macOS — UC-03](#8-configurazione-fim-su-macos--uc-03)
9. [Detection rules custom — UC-01 · UC-02 · UC-03 · UC-04 · UC-06](#9-detection-rules-custom--uc-01--uc-02--uc-03--uc-04--uc-06)
10. [Ingestion log NextDNS — UC-02](#10-ingestion-log-nextdns--uc-02)
11. [Script rogue device detection — UC-06](#11-script-rogue-device-detection--uc-06)
12. [Script NAS port monitor — UC-04](#12-script-nas-port-monitor--uc-04)
13. [Verifica alert end-to-end](#13-verifica-alert-end-to-end)
    - 13.1 UC-01 Brute Force SSH
    - 13.2 UC-03 FIM (workaround)
    - 13.3 UC-06 Rogue Device
    - 13.4 UC-02 NextDNS
    - 13.5 UC-04 NAS Port Monitor
    - 13.6 Verifica Dashboard
14. [Backup snapshot](#14-backup-snapshot)
15. [Verifica finale e checklist](#15-verifica-finale-e-checklist)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. Prerequisiti

### 1.1 Requisiti infrastrutturali

```bash
# Su SOC-01 — verifica Proxmox operativo
pveversion
# Output atteso: pve-manager/8.x.x

# Verifica RAM disponibile — vm-103 richiede 6 GB (ideale 8 GB)
free -h
# La RAM totale di SOC-01 deve essere 32 GB — con 16 GB non avviare questa VM

# Verifica storage disponibile (vm-103 richiede 64 GB)
pvesm status
# local-lvm deve avere ≥ 64 GB liberi

# Verifica che il pool phase2 esista (o phase3 se distinto)
pvesh get /pools/phase2
```

> ⚠️ **REQUISITO RAM:** `vm-103` è classificata nel layout a 32 GB (vedi `docs/02-architecture.md` sez. 5.1). Con SOC-01 a 16 GB il sistema non ha headroom sufficiente — avviare questa VM solo dopo l'upgrade della RAM.

> ✅ **Checkpoint RAM:** `free -h | grep Mem` → il totale deve essere ≥ 30 GB (kernel overhead incluso).

### 1.2 Specifiche vm-103

| Parametro | Valore | Note |
|---|---|---|
| VM ID | `103` | — |
| Nome | `vm-103-wazuh` | — |
| OS | Ubuntu Server 22.04 LTS | Supporto ufficiale Wazuh 4.x |
| vCPU | 4 | — |
| RAM | **6 GB** (6144 MB) | Min Wazuh ufficiale: 4 GB · Raccomandato: 8 GB |
| Swap | 2 GB (su disco) | Configurato in fase OS install |
| Storage | **64 GB** su `local-lvm` | Wazuh Indexer (OpenSearch) è disk-hungry |
| Network | `vmbr0` (LAN — 192.168.68.0/24) | — |
| IP target | `192.168.68.204` (DHCP reservation) | — |
| VM type | VM completa (non LXC) | Wazuh Indexer richiede syscall non supportate in LXC |

> ⚠️ **RAM 6 GB:** è il valore dell'architettura di progetto. In produzione Wazuh raccomanda 8 GB per evitare OOM sull'Indexer. Con 32 GB su SOC-01 si può portare a 8 GB senza impattare le altre VM — valutare dopo il primo run.

### 1.3 Informazioni di rete

| Parametro | Valore |
|---|---|
| IP vm-103 | `192.168.68.204` (DHCP reservation) |
| Gateway | `192.168.68.1` (Deco BE65) |
| DNS | `192.168.68.1` |
| Wazuh Dashboard (HTTPS) | `https://192.168.68.204` · porta `443/tcp` |
| Wazuh API | `https://192.168.68.204:55000` |
| Agent enrollment | `192.168.68.204:1515/tcp` |
| Agent data | `192.168.68.204:1514/tcp` |

### 1.4 Download ISO Ubuntu 22.04 LTS

```bash
# Su SOC-01 — scarica ISO direttamente nel local storage Proxmox
wget -O /var/lib/vz/template/iso/ubuntu-22.04-live-server-amd64.iso \
  https://releases.ubuntu.com/22.04/ubuntu-22.04.5-live-server-amd64.iso

# Verifica checksum SHA256
sha256sum /var/lib/vz/template/iso/ubuntu-22.04-live-server-amd64.iso
# Confrontare con: https://releases.ubuntu.com/22.04/SHA256SUMS
```

> ℹ️ Il numero di versione patch (22.04.X) cambia nel tempo. Verificare l'URL attuale su `releases.ubuntu.com/22.04/` e usare l'ultima LTS disponibile.

---

## 2. Creazione VM su Proxmox

### 2.1 Creazione via CLI (metodo consigliato)

```bash
# Su SOC-01
# Leggi il nome esatto dell'ISO scaricata
ISO=$(ls /var/lib/vz/template/iso/ | grep ubuntu-22.04)
echo "ISO: $ISO"

qm create 103 \
  --name vm-103-wazuh \
  --cores 4 \
  --memory 6144 \
  --balloon 0 \
  --net0 virtio,bridge=vmbr0,firewall=1 \
  --ide2 local:iso/${ISO},media=cdrom \
  --scsi0 local-lvm:64,discard=on,iothread=1 \
  --scsihw virtio-scsi-single \
  --boot order=scsi0;ide2 \
  --ostype l26 \
  --cpu cputype=host \
  --agent enabled=1 \
  --onboot 1 \
  --pool phase2 \
  --description "vm-103 — Wazuh SIEM Manager+Indexer+Dashboard — Fase 3 HomeSOC"
```

### 2.2 Verifica e avvio per installazione

```bash
# Su SOC-01
qm config 103 | grep -E "cores|memory|scsi0|net0|boot"

# Avvia la VM per l'installazione OS
qm start 103

# Accedi via noVNC (Web UI Proxmox → vm-103 → Console)
# Oppure da terminale locale:
# Web browser → https://192.168.68.200:8006 → vm-103 → Console
```

### 2.3 Alternativa — Creazione via Web UI

**Web UI Proxmox** → `soc-01` → **Create VM**

| Tab | Campo | Valore |
|---|---|---|
| General | VM ID | `103` |
| General | Name | `vm-103-wazuh` |
| General | Pool | `phase2` |
| OS | ISO Image | `ubuntu-22.04-live-server-amd64.iso` |
| OS | Guest OS Type | Linux / Version 6.x (kernel) |
| System | SCSI Controller | `VirtIO SCSI Single` |
| System | Qemu Agent | ✅ Abilitato |
| Disks | Bus/Device | SCSI0 · Disk size `64` GiB · Discard ON |
| CPU | Cores | `4` · Type `host` |
| Memory | Memory | `6144` MiB · Balloon ❌ disabilitato |
| Network | Bridge | `vmbr0` · Model `VirtIO (paravirtualized)` |

---

## 3. Installazione Ubuntu 22.04 LTS

Accedere alla console VM via Web UI Proxmox (noVNC). L'installer Ubuntu text-based si avvia automaticamente dall'ISO.

### 3.1 Impostazioni installer Ubuntu

| Schermata | Valore da selezionare |
|---|---|
| Language | English (consigliato — log e messaggi di errore Wazuh in inglese) |
| Keyboard | Italian (o preferenza) |
| Installation type | **Ubuntu Server (minimized)** |
| Network | DHCP su `ens18` — l'IP statico si configura dopo l'install |
| Proxy | vuoto |
| Mirror | default Ubuntu |
| Storage | **Use entire disk** · partizione unica (semplifica gestione snapshot) |
| Swap | ✅ Abilitare swap file 2 GB nell'installer |
| Name | `Alessandro` |
| Server name | `vm-103-wazuh` |
| Username | `alessandrogaburro` |
| Password | (scegliere password sicura — annotare in password manager) |
| SSH | ✅ Install OpenSSH server — **Import SSH key** da GitHub o inserire chiave pubblica manuale |
| Featured snaps | Nessuno — skip |

> ✅ **Checkpoint:** Dopo il riavvio, verificare accesso SSH: `ssh alessandrogaburro@<IP-DHCP-vm-103>`. Il DHCP temporaneo è leggibile dalla console o dai log Proxmox.

### 3.2 Installazione qemu-guest-agent

```bash
# Dentro vm-103 (SSH o console)
sudo apt update && sudo apt install -y qemu-guest-agent
sudo systemctl enable --now qemu-guest-agent

# Verifica che Proxmox veda l'IP della VM
# (Su SOC-01): qm agent 103 network-get-interfaces
```

---

## 4. Configurazione base del sistema

### 4.1 IP statico (netplan)

```bash
# Dentro vm-103
# Identifica l'interfaccia di rete
ip link show
# Di solito: ens18 su VM Proxmox con VirtIO

sudo nano /etc/netplan/00-installer-config.yaml
```

Sostituire il contenuto con:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens18:
      dhcp4: false
      addresses:
        - 192.168.68.204/24
      routes:
        - to: default
          via: 192.168.68.1
      nameservers:
        addresses:
          - 192.168.68.1
          - 1.1.1.1
        search:
          - homesoc.lan
```

```bash
# Applica la configurazione
sudo netplan apply

# Verifica IP
ip addr show ens18
# Output atteso: inet 192.168.68.204/24

# Verifica gateway
ping -c 3 192.168.68.1
ping -c 3 8.8.8.8
```

> ℹ️ **Nota:** da questo momento connettersi sempre su `192.168.68.204` — il vecchio IP DHCP non è più valido.

### 4.2 Hostname e timezone

```bash
# Dentro vm-103
sudo hostnamectl set-hostname vm-103-wazuh

sudo timedatectl set-timezone Europe/Rome
timedatectl status
# NTP synchronized: yes

# Aggiorna /etc/hosts
sudo tee -a /etc/hosts << 'EOF'
192.168.68.204  vm-103-wazuh.homesoc.lan vm-103-wazuh
EOF
```

### 4.3 Aggiornamento sistema e pacchetti base

```bash
# Dentro vm-103
sudo apt update && sudo DEBIAN_FRONTEND=noninteractive apt full-upgrade -y

sudo apt install -y \
  curl wget gnupg ca-certificates lsb-release apt-transport-https \
  software-properties-common unzip jq net-tools htop iotop \
  iputils-ping ncat rsync cron logrotate

# Riavvio dopo kernel update (se presente)
sudo reboot
```

### 4.4 DHCP reservation su Deco BE65

Prima di procedere con l'installazione, fissare l'IP su Deco:

**Deco App** → `More` → `Address Reservation` → `Add`:

| Campo | Valore |
|---|---|
| MAC Address | *(leggere con `ip link show ens18 \| grep link/ether` dentro vm-103)* |
| IP Address | `192.168.68.204` |
| Device Name | `vm-103-wazuh` |

> ✅ Annotare il MAC in `Inventario_IP_Pulito.csv` dopo la lettura.

### 4.5 Firewall UFW

```bash
# Dentro vm-103
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH (solo LAN)
sudo ufw allow from 192.168.68.0/24 to any port 22 proto tcp comment "SSH LAN"

# Wazuh Agent enrollment e data (da MacBook e futuri agent)
sudo ufw allow from 192.168.68.0/24 to any port 1514 proto tcp comment "Wazuh agent data"
sudo ufw allow from 192.168.68.0/24 to any port 1515 proto tcp comment "Wazuh agent enrollment"

# Dashboard (solo LAN)
sudo ufw allow from 192.168.68.0/24 to any port 443 proto tcp comment "Wazuh Dashboard"

# API Wazuh (solo LAN — per integrazione futura TheHive)
sudo ufw allow from 192.168.68.0/24 to any port 55000 proto tcp comment "Wazuh API"

# Syslog in (futuro — router, device di rete)
sudo ufw allow from 192.168.68.0/24 to any port 514 proto udp comment "Syslog in"
sudo ufw allow from 192.168.68.0/24 to any port 601 proto tcp comment "Syslog TCP"

sudo ufw enable
sudo ufw status numbered
```

---

## 5. Installazione Wazuh single-node

Wazuh 4.x in modalità single-node installa tre componenti sulla stessa macchina: **Wazuh Manager** (HIDS/SIEM engine), **Wazuh Indexer** (OpenSearch — storage e query degli alert), **Wazuh Dashboard** (UI basata su OpenSearch Dashboards).

### 5.1 Download e verifica script di installazione

```bash
# Dentro vm-103
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.x/config.yml

# Verifica checksum (buona pratica su sistemi di sicurezza)
# Le somme SHA512 ufficiali sono pubblicate su: https://documentation.wazuh.com/current/quickstart.html
```

### 5.2 Configurazione cluster (single-node)

Modificare `config.yml` per il layout single-node:

```bash
cat > config.yml << 'EOF'
nodes:
  # Wazuh indexer
  indexer:
    - name: wazuh-indexer
      ip: 192.168.68.204

  # Wazuh server
  server:
    - name: wazuh-server
      ip: 192.168.68.204

  # Wazuh dashboard
  dashboard:
    - name: wazuh-dashboard
      ip: 192.168.68.204
EOF
```

### 5.3 Installazione

> ⚠️ **ATTENZIONE:** Il comando seguente scarica e installa tutto lo stack Wazuh. Richiede **15–30 minuti** e connettività internet stabile. L'Indexer (OpenSearch) è il componente più pesante.

```bash
# Dentro vm-103
# Flag -a = all-in-one (manager + indexer + dashboard)
sudo bash wazuh-install.sh -a

# Output finale atteso (salvare le credenziali mostrate a schermo):
# INFO: --- Summary ---
# INFO: You can access the web interface https://192.168.68.204
#    User: admin
#    Password: <PASSWORD-GENERATA>
# INFO: Installation finished.
```

> ✅ **CRITICO:** Copiare e salvare la password admin mostrata a termine installazione nel proprio password manager. Non è recuperabile senza reset.

### 5.4 Verifica servizi post-installazione

```bash
# Dentro vm-103
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard

# Tutti devono essere active (running)
# Verifica rapida:
for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
  echo -n "${svc}: "
  systemctl is-active $svc
done

# Verifica porta Dashboard
sudo ss -tlnp | grep -E "443|55000|9200|1514|1515"
```

### 5.5 Verifica Wazuh Manager

```bash
# Dentro vm-103
sudo /var/ossec/bin/ossec-control status
# Output atteso: tutti i processi in "running"

sudo /var/ossec/bin/agent_control -l
# Lista agent connessi (vuota all'inizio — normale)

# Verifica API Wazuh (le credenziali sono separate dalla Dashboard)
curl -k -u wazuh-wui:wazuh-wui \
  https://192.168.68.204:55000/security/user/authenticate?raw=true
# Deve restituire un token JWT
```

---

## 6. Primo accesso Dashboard

### 6.1 Accesso e cambio password

1. Dal browser sul MacBook: `https://192.168.68.204`
2. Accettare il certificato self-signed (avviso browser — normale)
3. Credenziali: `admin` / `<password salvata al passo 5.3>`
4. **Cambiare subito la password** → icona utente in alto a destra → **Change password**

### 6.2 Verifica stato cluster

**Dashboard** → `☰` → **Indexer management** → **Index Management**

Il cluster deve essere in stato verde (`green`) con tutti gli indici `wazuh-alerts-*` presenti.

Se lo stato è `yellow`: normale con single-node (le repliche non possono essere allocate sulla stessa istanza) — non richiede azione.

### 6.3 Configurazione generale iniziale

**Dashboard** → `☰` → **Management** → **Stack Management** → **Index Patterns**:

Verificare che il pattern `wazuh-alerts-*` sia configurato con `timestamp` come campo data.

---

## 7. Installazione Wazuh Agent su macOS M1

Il Wazuh Agent per macOS supporta nativamente Apple Silicon (ARM64/M1/M2). Il pacchetto `.pkg` si installa senza emulazione Rosetta.

### 7.1 Download e installazione

```bash
# Sul MacBook Pro M1 (END-05 — 192.168.68.108) — terminale macOS
# Verifica versione Wazuh Manager installata
# (Su vm-103): sudo /var/ossec/bin/wazuh-control info | grep VERSION

# Download agent ARM64 (sostituire X.Y.Z con la versione del Manager)
WAZUH_VER="4.9.2"  # verificare la versione esatta dal Manager

curl -so ~/Downloads/wazuh-agent-${WAZUH_VER}-1.arm64.pkg \
  "https://packages.wazuh.com/4.x/macos/wazuh-agent-${WAZUH_VER}-1.arm64.pkg"

# Verifica checksum (confrontare con Wazuh docs)
shasum -a 512 ~/Downloads/wazuh-agent-${WAZUH_VER}-1.arm64.pkg
```

### 7.2 Installazione con enrollment automatico

```bash
# Sul MacBook Pro M1
# Installazione con parametri di enrollment inline
sudo WAZUH_MANAGER='192.168.68.204' \
  WAZUH_AGENT_NAME='macbook-pro-m1-ale' \
  WAZUH_AGENT_GROUP='macos,endpoints' \
  installer -pkg ~/Downloads/wazuh-agent-${WAZUH_VER}-1.arm64.pkg -target /
```

### 7.3 Avvio e verifica agent

```bash
# Sul MacBook Pro M1
# Avvio del servizio agent
sudo /Library/Ossec/bin/wazuh-control start

# Verifica stato
sudo /Library/Ossec/bin/wazuh-control status
# Output atteso: wazuh-agentd running

# Verifica connessione al Manager
sudo /Library/Ossec/bin/agent_control -i 001
# Se 001 non esiste ancora, attendere 30 secondi e riprovare
```

```bash
# Su vm-103 — verifica che l'agent sia registrato
sudo /var/ossec/bin/agent_control -l
# Output atteso:
# ID: 001, Name: macbook-pro-m1-ale, IP: 192.168.68.108, Active
```

> ✅ **Checkpoint:** In Dashboard → **Agents** deve comparire `macbook-pro-m1-ale` con stato **Active** e heartbeat recente.

### 7.4 Verifica logs macOS inviati al Manager

```bash
# Su vm-103 — verifica ricezione eventi dal MacBook
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep macbook
# Devono comparire eventi entro 60 secondi dall'avvio agent
```

---

## 8. Configurazione FIM su macOS — UC-03

Il File Integrity Monitoring (FIM) monitora modifiche a file e directory critiche. Configurato sull'agent macOS per UC-03 (T1565.001 — Data Manipulation / Persistence).

### 8.1 Modifica ossec.conf sul MacBook

> ℹ️ **Nota v1.1:** la sezione `<syscheck>` con `<frequency>` si trova indicativamente alla **riga 92** di `/Library/Ossec/etc/ossec.conf` (non riga 40 come indicato in alcune versioni di documentazione Wazuh). Verificare con `grep -n "syscheck\|frequency" /Library/Ossec/etc/ossec.conf` prima di editare.

```bash
# Sul MacBook Pro M1
sudo nano /Library/Ossec/etc/ossec.conf
```

Aggiungere/modificare la sezione `<syscheck>`:

```xml
<ossec_config>
  <syscheck>
    <!-- Frequenza scan completo (in secondi) — 43200 = 12 ore -->
    <frequency>43200</frequency>

    <!-- Real-time monitoring su directory ad alto rischio -->
    <directories check_all="yes" report_changes="yes" realtime="yes">
      /Users/alessandrogaburro
    </directories>

    <!-- LaunchAgents/LaunchDaemons — persistence comune per malware macOS -->
    <directories check_all="yes" report_changes="yes" realtime="yes">
      /Library/LaunchAgents
    </directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">
      /Library/LaunchDaemons
    </directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">
      /Users/alessandrogaburro/Library/LaunchAgents
    </directories>

    <!-- SSH keys — esfiltrazione credenziali -->
    <directories check_all="yes" report_changes="yes" realtime="yes">
      /Users/alessandrogaburro/.ssh
    </directories>

    <!-- Configurazioni di sistema critiche -->
    <directories check_all="yes">/etc</directories>
    <directories check_all="yes">/private/etc</directories>

    <!-- Esclusioni — directory volatili che genererebbero troppo rumore -->
    <ignore>/Users/alessandrogaburro/Library/Caches</ignore>
    <ignore>/Users/alessandrogaburro/Library/Application Support/Google/Chrome/Default/Cache</ignore>
    <ignore>/Users/alessandrogaburro/.Trash</ignore>
    <ignore>/Users/alessandrogaburro/Downloads</ignore>
    <ignore type="sregex">\.DS_Store$</ignore>
    <ignore type="sregex">\.localized$</ignore>

    <!-- Alert anche alla prima scan (mostra baseline) -->
    <alert_new_files>yes</alert_new_files>
  </syscheck>
</ossec_config>
```

### 8.2 Restart agent per applicare FIM

```bash
# Sul MacBook Pro M1
sudo /Library/Ossec/bin/wazuh-control restart

# Verifica che il FIM si avvii correttamente (nessun errore)
sudo tail -50 /Library/Ossec/logs/ossec.log | grep -E "syscheck|FIM|error"
```

> ℹ️ **Privacy MAC su macOS:** il MAC C6:A3:2A:A3:A8:0F di END-05 potrebbe essere randomizzato (TODO-5 dal threat model). Verificare in **Impostazioni di Sistema** → **Wi-Fi** → rete connessa → **Indirizzo Wi-Fi privato**. Se attivo, il MAC cambia a ogni connessione — configurare la DHCP reservation sul Deco usando il MAC fisico (visibile nelle impostazioni) oppure disabilitare il MAC privato per la rete HomeSOC.

---

### 8.3 ⚠️ Limite noto — Full Disk Access (FDA) su macOS con SIP attivo

**Problema riscontrato in produzione:** le directory `/Users/alessandrog` e `/Users/alessandrogaburro/Library/LaunchAgents` **non vengono monitorate** dal motore FIM nonostante siano presenti in `ossec.conf`. Il motivo è che macOS richiede il **Full Disk Access (FDA)** per leggere il contenuto delle home directory e dei LaunchAgents utente, e FDA non può essere assegnato via CLI a un processo senza bundle `.app` firmato con SIP attivo.

**Effetto operativo:**
- `/private/etc` → ✅ monitorata (regola 553 built-in Wazuh funziona)
- `/Library/LaunchAgents` (system-level) → ✅ monitorata (accessibile senza FDA)
- `/Library/LaunchDaemons` → ✅ monitorata
- `/Users/alessandrogaburro/` → ❌ non monitorata (richiede FDA)
- `/Users/alessandrogaburro/Library/LaunchAgents` → ❌ non monitorata (richiede FDA)
- `/Users/alessandrogaburro/.ssh` → ❌ non monitorata (richiede FDA)

**Workaround attuale:** monitoraggio di `/private/etc` copre le configurazioni di sistema critiche (alert via rule 553 built-in). La regola custom 100020 trigghera correttamente su `/Library/LaunchAgents` system-level.

**Soluzioni future da valutare:**
1. **MDM profile** — assegnare FDA al processo Wazuh Agent tramite profilo MDM (es. Mosyle, Jamf) che bypassa il requirement GUI. Non applicabile in contesto home senza MDM.
2. **Wrapper .app firmato** — creare un bundle `.app` firmato che wrappa `wazuh-agentd` e riceve FDA manualmente da GUI (*Impostazioni di Sistema → Privacy e sicurezza → Accesso completo al disco → +*). Approach manuale, richiede re-grant ad ogni aggiornamento agent.
3. **auditd / EndpointSecurity Framework** — alternativa a FIM basata su Framework Apple nativo; richiede entitlement speciale (`com.apple.developer.endpoint-security.client`) non disponibile per software non firmati da Apple.

**Stato UC-03:** ⚠️ Parziale — il motore FIM gira, `/private/etc` e `/Library/LaunchAgents` (system) sono monitorate, ma la home directory e i LaunchAgents utente non lo sono per limite FDA. Documentato come known limitation nel portfolio.

> 📝 **Nota portfolio:** questa limitazione è documentata esplicitamente nel runbook perché dimostra comprensione della security architecture macOS (SIP, FDA, codesigning) — valore aggiunto per il portfolio Blue Team rispetto a un deploy puramente funzionante ma non documentato nei suoi vincoli.

---

### 8.4 Workaround FIM macOS — script MD5/diff (UC-03 operativo)

Poiché `wazuh-syscheckd` non riesce ad accedere alla home directory e ai LaunchAgents utente per il blocco TCC, si implementa un FIM alternativo basato su snapshot MD5 periodici con confronto diff. Il meccanismo è equivalente al FIM nativo per le directory monitorate e non richiede FDA.

**Directory monitorate dal workaround:**
- `/Users/alessandrogaburro/.ssh` — chiavi SSH, authorized_keys (T1098.004)
- `/Users/alessandrogaburro/Library/LaunchAgents` — persistence malware utente (T1543.001)
- `~/.zshrc`, `~/.bash_profile` — profilo shell (T1546.004)

#### 8.4.1 Script snapshot sul MacBook

```bash
# Sul MacBook Pro M1
sudo tee /Library/Ossec/fim-snapshot.sh << 'EOF'
#!/bin/bash
# ============================================================
# HomeSOC — FIM workaround macOS (UC-03 / T1565.001)
# Confronta snapshot MD5 e logga solo le modifiche
# File: /Library/Ossec/fim-snapshot.sh
# Cron: ogni 5 minuti
# Output: /Library/Ossec/logs/fim-changes.log
# ============================================================

SNAPSHOT="/Library/Ossec/fim-baseline.txt"
CURRENT="/tmp/fim-current.txt"
LOG="/Library/Ossec/logs/fim-changes.log"

# Genera snapshot corrente
find /Users/alessandrogaburro/.ssh \
     /Users/alessandrogaburro/Library/LaunchAgents \
     -type f 2>/dev/null | sort | xargs md5 -r 2>/dev/null > "$CURRENT"

for f in /Users/alessandrogaburro/.zshrc \
          /Users/alessandrogaburro/.bashrc \
          /Users/alessandrogaburro/.bash_profile; do
  [ -f "$f" ] && md5 -r "$f" 2>/dev/null >> "$CURRENT"
done

# Prima esecuzione: salva baseline e termina
if [ ! -f "$SNAPSHOT" ]; then
  cp "$CURRENT" "$SNAPSHOT"
  echo "$(date -Iseconds) homesoc fim-macos: event=\"baseline_created\" files=\"$(wc -l < $CURRENT | tr -d ' ')\"" >> "$LOG"
  exit 0
fi

# Confronta con baseline
diff "$SNAPSHOT" "$CURRENT" | while read -r line; do
  case "$line" in
    "< "*)
      HASH=$(echo "$line" | awk '{print $2}')
      FILE=$(echo "$line" | awk '{print $3}')
      echo "$(date -Iseconds) homesoc fim-macos: event=\"modified_or_deleted\" file=\"${FILE}\" old_hash=\"${HASH}\"" >> "$LOG"
      ;;
    "> "*)
      HASH=$(echo "$line" | awk '{print $2}')
      FILE=$(echo "$line" | awk '{print $3}')
      echo "$(date -Iseconds) homesoc fim-macos: event=\"modified_or_new\" file=\"${FILE}\" new_hash=\"${HASH}\"" >> "$LOG"
      ;;
  esac
done

# Aggiorna baseline
cp "$CURRENT" "$SNAPSHOT"
EOF
sudo chmod +x /Library/Ossec/fim-snapshot.sh

# Prima esecuzione — crea la baseline
sudo /Library/Ossec/fim-snapshot.sh
sudo cat /Library/Ossec/logs/fim-changes.log
# Atteso: event="baseline_created" files="N"
```

#### 8.4.2 Aggiunta logcollector in ossec.conf (MacBook)

```bash
# Sul MacBook Pro M1
sudo python3 << 'EOF'
CONF = '/Library/Ossec/etc/ossec.conf'
with open(CONF, 'r') as f:
    content = f.read()

if 'fim-changes.log' in content:
    print("INFO: già presente")
    exit(0)

LOCALFILE = """
  <!-- HomeSOC FIM workaround macOS (UC-03) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/Library/Ossec/logs/fim-changes.log</location>
  </localfile>
"""
content = content.replace('</ossec_config>', LOCALFILE + '\n</ossec_config>')
with open(CONF, 'w') as f:
    f.write(content)
print("OK: localfile fim-changes aggiunto")
EOF

sudo /Library/Ossec/bin/wazuh-control restart
```

#### 8.4.3 Cron sul MacBook

```bash
# Sul MacBook Pro M1
sudo crontab -e
# Aggiungere:
# */5 * * * * /Library/Ossec/fim-snapshot.sh
```

#### 8.4.4 Decoder e regola su vm-103

```bash
# Su vm-103
sudo tee /var/ossec/etc/decoders/fim-macos-decoder.xml << 'EOF'
<!--
  HomeSOC — Decoder FIM workaround macOS
  File: /var/ossec/etc/decoders/fim-macos-decoder.xml
-->
<decoder name="fim-macos">
  <program_name>^fim-macos$</program_name>
</decoder>

<decoder name="fim-macos-fields">
  <parent>fim-macos</parent>
  <regex type="pcre2">event="(\S+)" file="([^"]+)" (?:old|new)_hash="(\S+)"</regex>
  <order>fim.event,fim.file,fim.hash</order>
</decoder>
EOF
```

> ℹ️ La regola corrispondente (100023) è già inclusa nel file `local_rules.xml` in sezione 9.2.

#### 8.4.5 Test workaround

```bash
# Sul MacBook — simula modifica a .zshrc
echo "# fim-test" >> ~/.zshrc
sudo /Library/Ossec/fim-snapshot.sh

# Su vm-103 — verifica alert
sudo tail -20 /var/ossec/logs/alerts/alerts.log | grep -A 5 "100023"
# Atteso: Rule 100023 (level 10) — modifica file critico: .zshrc

# Pulizia
sed -i '' '/# fim-test/d' ~/.zshrc
```

---

## 9. Detection rules custom — UC-01 · UC-02 · UC-03 · UC-04 · UC-06

Le custom rules vanno nel file `/var/ossec/etc/rules/local_rules.xml` sul Manager. Wazuh carica questo file dopo tutte le rule di default — i Rule ID custom devono essere ≥ 100000.

### 9.1 Backup del file rules esistente

```bash
# Su vm-103
sudo cp /var/ossec/etc/rules/local_rules.xml \
  /var/ossec/etc/rules/local_rules.xml.bak.$(date +%Y%m%d)
```

### 9.2 Scrittura regole custom

```bash
# Su vm-103
sudo tee /var/ossec/etc/rules/local_rules.xml << 'RULES_EOF'
<!--
  HomeSOC — Custom Detection Rules
  File: /var/ossec/etc/rules/local_rules.xml
  Versione: 1.2 — Aprile 2026
  Autore: Alessandro · LM Sicurezza Informatica · UniMI
  Threat model: docs/01-threat-model.md
-->


<group name="homesoc,">

  <!-- ============================================================
       UC-01 — Brute Force SSH su HomeSOC (T1110.001)
       Trigger: ≥5 login SSH falliti in 60s dallo stesso IP
       Asset: SOC-01 (R-10)
       Prerequisito: Rule 5720 è la built-in Wazuh per SSH failures
       ============================================================ -->

  <rule id="100001" level="10">
    <if_matched_sid>5720</if_matched_sid>
    <same_source_ip />
    <timeframe>60</timeframe>
    <frequency>5</frequency>
    <description>UC-01 HomeSOC: Brute force SSH rilevato da $(srcip) — attivare fail2ban</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,brute_force,homesoc_uc01,</group>
  </rule>

  <!-- Alert escalation: brute force persistente (≥15 tentativi in 120s) -->
  <rule id="100002" level="14">
    <if_matched_sid>100001</if_matched_sid>
    <same_source_ip />
    <timeframe>120</timeframe>
    <frequency>3</frequency>
    <description>UC-01 HomeSOC: Brute force SSH CRITICO da $(srcip) — ≥15 tentativi in 120s</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,brute_force,homesoc_uc01,critical,</group>
  </rule>


  <!-- ============================================================
       UC-02 — Beaconing IoT verso IP Sospetti (T1071.001)
       Trigger: log NextDNS con domini non in whitelist ad alta frequenza
       Asset: IOT-01 (Dreame), IOT-02 (Narwal) (R-01)
       Nota: richiede setup ingestion NextDNS (sezione 10)
       ============================================================ -->

  <!-- Alert su query DNS verso IP/domini in ASN cinesi (Baidu/Alibaba)
       dal log NextDNS — il decodificatore è configurato nella sezione 10 -->
  <!-- ⚠️ FIX v1.1: NextDNS API restituisce campo 'status' (stringa "ok"/"blocked"),
       non 'blocked' (boolean). Il decoder mappa questo valore su nextdns.blocked.
       "ok" = query non bloccata = traffico reale verso il dominio sospetto -->
  <rule id="100010" level="8">
    <decoded_as>nextdns-log</decoded_as>
    <field name="nextdns.blocked">^ok$</field>
    <field name="nextdns.domain" type="pcre2">
      (\.baidu\.com|\.alibaba\.com|\.aliyun\.com|\.qq\.com|\.taobao\.com|\.jd\.com)$
    </field>
    <description>UC-02 HomeSOC: Query DNS IoT verso dominio cloud cinese (non bloccata): $(nextdns.domain) da $(nextdns.device)</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
    <group>nextdns,iot_beaconing,homesoc_uc02,</group>
  </rule>

  <!-- Alert frequenza alta: beaconing regolare (>20 query/min dallo stesso device) -->
  <rule id="100011" level="10">
    <if_matched_sid>100010</if_matched_sid>
    <same_field>nextdns.device</same_field>
    <timeframe>60</timeframe>
    <frequency>20</frequency>
    <description>UC-02 HomeSOC: Beaconing IoT elevato da $(nextdns.device) — $(frequency) query/min verso cloud cinese</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
    <group>nextdns,iot_beaconing,homesoc_uc02,</group>
  </rule>


  <!-- ============================================================
       UC-03 — File Integrity Monitoring MacBook (T1565.001)
       Trigger: modifiche a file critici in percorsi sensibili
       Asset: END-05 MacBook Pro M1 (R-02, R-08)
       Prerequisito: FIM configurato (sezione 8)
       ============================================================ -->

  <!-- Modifica a LaunchAgents/LaunchDaemons — vettore persistence classico macOS -->
  <rule id="100020" level="12">
    <if_group>syscheck</if_group>
    <field name="file" type="pcre2">
      /Library/Launch(Agents|Daemons)/
    </field>
    <description>UC-03 HomeSOC: FIM — Modifica LaunchAgent/Daemon su MacBook: $(file) — possibile persistence malware</description>
    <mitre>
      <id>T1565.001</id>
      <id>T1543.001</id>
    </mitre>
    <group>syscheck,fim,homesoc_uc03,macos_persistence,</group>
  </rule>

  <!-- Modifica a ~/.ssh — possibile esfiltrazione o aggiunta chiavi non autorizzate -->
  <rule id="100021" level="12">
    <if_group>syscheck</if_group>
    <field name="file" type="pcre2">
      /Users/[^/]+/\.ssh/
    </field>
    <description>UC-03 HomeSOC: FIM — Modifica directory .ssh su MacBook: $(file)</description>
    <mitre>
      <id>T1565.001</id>
      <id>T1098.004</id>
    </mitre>
    <group>syscheck,fim,homesoc_uc03,ssh_keys,</group>
  </rule>

  <!-- File eliminato in home directory — possibile cover tracks -->
  <rule id="100022" level="8">
    <if_group>syscheck</if_group>
    <field name="file" type="pcre2">
      /Users/alessandrogaburro/
    </field>
    <match>deleted</match>
    <description>UC-03 HomeSOC: FIM — File eliminato in home directory MacBook: $(file)</description>
    <mitre>
      <id>T1565.001</id>
      <id>T1070.004</id>
    </mitre>
    <group>syscheck,fim,homesoc_uc03,</group>
  </rule>


  <!-- ============================================================
       UC-04 — Monitoraggio Porte NAS WD My Cloud Home (T1078 / T1571)
       Implementazione: script nmap polling ogni 30min (nas-monitor.sh)
       Il WD My Cloud Home non supporta syslog nativo — la detection
       avviene tramite confronto periodico delle porte esposte vs baseline.
       Baseline Aprile 2026: 80 139 445 4430 5357 8001 8010 8543 9999 33284
       Asset: NAS-01 192.168.68.90 (R-06)
       Decoder: nas-monitor-decoder.xml (sezione 12.3)
       Script: /opt/homesoc/scripts/nas-monitor.sh (sezione 12.1)

       Fix v1.3: guard baseline su NAS offline aggiunto allo script.
       Quando il NAS è irraggiungibile (es. spento di notte) lo script
       logga nas_offline e NON aggiorna la baseline, prevenendo il FP
       "tutte le porte appaiono nuove" al ritorno online (rilevato 2026-04-22).
       ============================================================ -->

  <!-- Porta inattesa sul NAS — possibile backdoor o misconfiguration post-compromise -->
  <rule id="100030" level="12">
    <decoded_as>nas-monitor-fields</decoded_as>
    <field name="nas.event">new_port</field>
    <description>UC-04 HomeSOC: NAS $(nas.ip) — porta inattesa rilevata: $(nas.port) — possibile backdoor post-compromise</description>
    <mitre>
      <id>T1078</id>
      <id>T1571</id>
    </mitre>
    <group>network,nas_monitor,homesoc_uc04,</group>
  </rule>

  <!-- SMB (445) non raggiungibile sul NAS — servizio down o manomesso -->
  <rule id="100031" level="10">
    <decoded_as>nas-monitor-fields</decoded_as>
    <field name="nas.event">smb_down</field>
    <description>UC-04 HomeSOC: NAS $(nas.ip) — SMB (445) non raggiungibile — servizio down o manomesso</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>network,nas_monitor,homesoc_uc04,</group>
  </rule>

  <!-- NAS non raggiungibile durante il polling — informativo, nessuna notifica Slack -->
  <!-- Logga quando il NAS è spento o irraggiungibile (es. spegnimento notturno) -->
  <!-- Level 3 = solo audit trail nella Dashboard, nessun alert attivo -->
  <rule id="100032" level="3">
    <decoded_as>nas-monitor-fields</decoded_as>
    <field name="nas.event">nas_offline</field>
    <description>UC-04 HomeSOC: NAS $(nas.ip) non raggiungibile — spento o rete down (informativo)</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>network,nas_monitor,homesoc_uc04,</group>
  </rule>


  <!-- ============================================================
       UC-06 — Rogue Device in Rete (T1200)
       Trigger: nuovo MAC address non in whitelist rilevato in rete
       Asset: rete LAN 192.168.68.0/24 (R-11)
       Prerequisito: script polling DHCP (sezione 11)
       ============================================================ -->

  <rule id="100040" level="10">
    <decoded_as>homesoc-rogue-device</decoded_as>
    <field name="event">new_device</field>
    <description>UC-06 HomeSOC: Device non identificato in rete — MAC: $(mac) IP: $(ip) — verificare fisicamente</description>
    <mitre>
      <id>T1200</id>
    </mitre>
    <group>network,rogue_device,homesoc_uc06,</group>
  </rule>

  <!-- Device rogue persiste dopo il primo alert (non è stato bloccato) -->
  <!-- ⚠️ FIX v1.1: frequency e timeframe vanno come ATTRIBUTI del tag <rule>, non come elementi figli -->
  <rule id="100041" level="14" timeframe="3600" frequency="3">
    <if_matched_sid>100040</if_matched_sid>
    <same_field>mac</same_field>
    <description>UC-06 HomeSOC: Device non identificato PERSISTENTE — MAC: $(mac) ancora in rete dopo 1 ora — isolamento urgente</description>
    <mitre>
      <id>T1200</id>
    </mitre>
    <group>network,rogue_device,homesoc_uc06,critical,</group>
  </rule>

</group>
RULES_EOF
```

### 9.3 Verifica sintassi e reload

```bash
# Su vm-103
# Verifica sintassi XML prima del reload
sudo /var/ossec/bin/wazuh-logtest -U "homesoc" 2>&1 | head -20

# Test formale sintassi regole
sudo /var/ossec/bin/ossec-analysisd -t
# Nessun errore = regole valide

# Reload regole (senza restart completo)
sudo systemctl reload wazuh-manager

# Verifica che le regole siano caricate
sudo grep -A 2 "100001\|100010\|100020\|100030\|100032\|100040" \
  /var/ossec/logs/ossec.log | tail -20
```

---

## 10. Ingestion log NextDNS — UC-02

NextDNS espone una **API REST** per esportare i log di query DNS. Lo script seguente fa polling periodico e scrive i log in un file che Wazuh logcollector monitora.

### 10.1 Recupero credenziali NextDNS API

1. Accedere a `https://my.nextdns.io` → `Settings` → `API`
2. Annotare: **Profile ID** e **API Key**

### 10.2 Script polling NextDNS

```bash
# Su vm-103
sudo mkdir -p /opt/homesoc/scripts
sudo mkdir -p /var/log/homesoc

sudo tee /opt/homesoc/scripts/nextdns-fetch.sh << 'SCRIPT_EOF'
#!/bin/bash
# ============================================================
# HomeSOC — NextDNS Log Fetcher per Wazuh
# File: /opt/homesoc/scripts/nextdns-fetch.sh
# Cron: ogni 5 minuti
# Output: /var/log/homesoc/nextdns.log (monitorato da Wazuh)
# v1.1 — Fix campi API: domain (non name), status (non blocked),
#         reasons[0].name (non reason), limit min=10, params senza profile=
# ============================================================

NEXTDNS_PROFILE="XXXXXX"    # Sostituire con il proprio Profile ID (es. 4831e7)
NEXTDNS_API_KEY="XXXXXXXX"  # Sostituire con la propria API Key
LOG_FILE="/var/log/homesoc/nextdns.log"
CURSOR_FILE="/var/lib/homesoc/nextdns_cursor"

mkdir -p "$(dirname $CURSOR_FILE)"

# Leggi cursor dell'ultima query (per evitare duplicati)
CURSOR=""
if [ -f "$CURSOR_FILE" ]; then
  CURSOR=$(cat "$CURSOR_FILE")
fi

# Costruisci parametri API
# NOTA: 'profile=' NON va nei params — è già nell'URL.
#       Il limite minimo dell'API NextDNS è 10.
PARAMS="limit=10"
if [ -n "$CURSOR" ]; then
  PARAMS="${PARAMS}&cursor=${CURSOR}"
fi

# Fetch log da NextDNS API
RESPONSE=$(curl -s -H "X-Api-Key: ${NEXTDNS_API_KEY}" \
  "https://api.nextdns.io/profiles/${NEXTDNS_PROFILE}/logs?${PARAMS}")

if [ $? -ne 0 ] || [ -z "$RESPONSE" ]; then
  echo "$(date -Iseconds) ERROR: Impossibile raggiungere NextDNS API" >> "$LOG_FILE"
  exit 1
fi

# Estrai e formatta i log per Wazuh
# NOTA sui campi API NextDNS (v1.1 fix):
#   - .domain      → dominio richiesto (non .name)
#   - .status      → "ok" o "blocked" (non .blocked boolean)
#   - .reasons[0].name → motivo del blocco (non .reason)
#   - .deviceName  → nome device, fallback su .clientIp
echo "$RESPONSE" | jq -c '.data[]' 2>/dev/null | while read -r entry; do
  TIMESTAMP=$(echo "$entry" | jq -r '.timestamp // "unknown"')
  DOMAIN=$(echo "$entry" | jq -r '.domain // "unknown"')
  DEVICE=$(echo "$entry" | jq -r '.deviceName // .clientIp // "unknown"')
  BLOCKED=$(echo "$entry" | jq -r '.status // "unknown"')
  REASON=$(echo "$entry" | jq -r '.reasons[0].name // ""')

  # Formato syslog-like per decodifica Wazuh
  echo "${TIMESTAMP} homesoc nextdns: domain=\"${DOMAIN}\" device=\"${DEVICE}\" blocked=\"${BLOCKED}\" reason=\"${REASON}\"" \
    >> "$LOG_FILE"
done

# Aggiorna cursor per la prossima esecuzione
NEW_CURSOR=$(echo "$RESPONSE" | jq -r '.meta.pagination.cursor // empty' 2>/dev/null)
if [ -n "$NEW_CURSOR" ]; then
  echo "$NEW_CURSOR" > "$CURSOR_FILE"
fi
SCRIPT_EOF

sudo chmod +x /opt/homesoc/scripts/nextdns-fetch.sh
```

> ⚠️ Sostituire `XXXXXX` e `XXXXXXXX` con le credenziali reali NextDNS. **Non committare questo file con le credenziali su Git** — usare un file di configurazione esterno o variabili d'ambiente.

### 10.3 Configurazione cron

```bash
# Su vm-103
sudo crontab -e
# Aggiungere:
# */5 * * * * /opt/homesoc/scripts/nextdns-fetch.sh >> /var/log/homesoc/nextdns-fetch.log 2>&1
```

### 10.4 Decoder Wazuh per NextDNS

> ⚠️ **Fix v1.1 — Struttura parent/child obbligatoria:** il decoder con solo `<program_name>` + `<regex>` in un unico blocco non triggera correttamente in Wazuh 4.x quando la regex deve estrarre campi. La struttura corretta prevede un **parent decoder** (filtra per program_name) e un **child decoder** (estrae i campi con regex PCRE2). Il child usa `type="pcre2"` per garantire supporto a `\S` e lookahead che il motore OSSEC regex non supporta nativamente.

```bash
# Su vm-103
sudo tee /var/ossec/etc/decoders/nextdns-decoder.xml << 'DECODER_EOF'
<!--
  HomeSOC — Decoder NextDNS log
  File: /var/ossec/etc/decoders/nextdns-decoder.xml
  v1.1 — Fix: struttura parent/child, regex pcre2
  Formato log atteso:
    <ISO-TS> homesoc nextdns: domain="<D>" device="<D>" blocked="<ok|blocked>" reason="<R>"
-->

<!-- Parent: seleziona i log con program_name=nextdns dal pre-decoder syslog -->
<decoder name="nextdns-log">
  <program_name>^nextdns$</program_name>
</decoder>

<!-- Child: estrae i campi dal corpo del messaggio -->
<decoder name="nextdns-log-fields">
  <parent>nextdns-log</parent>
  <regex type="pcre2">domain="(\S+)" device="(\S+)" blocked="(\S+)" reason="([^"]*)"</regex>
  <order>nextdns.domain,nextdns.device,nextdns.blocked,nextdns.reason</order>
</decoder>
DECODER_EOF
```

**Verifica decoder con wazuh-logtest:**

```bash
# Su vm-103 — test con una riga di log di esempio
echo '2026-04-20T14:45:16.710Z homesoc nextdns: domain="www.baidu.com" device="151.48.208.59" blocked="ok" reason=""' | \
  sudo /var/ossec/bin/wazuh-logtest

# Output atteso:
# **Phase 1: Completed pre-decoding.
#   full event: ...
#   hostname: 'homesoc'
#   program_name: 'nextdns'
# **Phase 2: Completed decoding.
#   decoder: 'nextdns-log-fields'
#   nextdns.domain: 'www.baidu.com'
#   nextdns.device: '151.48.208.59'
#   nextdns.blocked: 'ok'
#   nextdns.reason: ''
```

> ℹ️ Se wazuh-logtest mostra ancora "No decoder matched" dopo questo fix: verificare che non ci siano errori XML nel file (`xmllint --noout /var/ossec/etc/decoders/nextdns-decoder.xml`) e che il manager sia stato ricaricato (`sudo systemctl reload wazuh-manager`).
```

### 10.5 Logcollector — aggiungere sorgente NextDNS

```bash
# Su vm-103
# Prima di aggiungere: verifica che non sia già presente (evita duplicati)
grep -c "nextdns.log" /var/ossec/etc/ossec.conf
# Se output è 0: procedere. Se è ≥ 1: il blocco è già presente, non rieseguire.

sudo python3 - << 'PYTHON_EOF'
import re

CONF = '/var/ossec/etc/ossec.conf'
with open(CONF, 'r') as f:
    content = f.read()

# Guard: non inserire duplicati
if 'nextdns.log' in content:
    print("INFO: localfile NextDNS già presente in ossec.conf — nessuna modifica")
    exit(0)

LOCALFILE = """
  <!-- HomeSOC — NextDNS log ingestion (UC-02) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/homesoc/nextdns.log</location>
  </localfile>
"""

# Inserire prima del tag </ossec_config> finale
content = content.replace('</ossec_config>', LOCALFILE + '\n</ossec_config>')

with open(CONF, 'w') as f:
    f.write(content)

print("OK: localfile NextDNS aggiunto a ossec.conf")
PYTHON_EOF

sudo systemctl reload wazuh-manager
```

---

## 11. Script rogue device detection — UC-06

Il WD My Cloud Home e il Deco BE65 non espongono una DHCP lease table via API standard. Lo script usa `nmap` per fare un ARP scan della subnet e confronta i MAC trovati con la whitelist dell'asset inventory.

### 11.1 Installazione nmap

```bash
# Su vm-103
sudo apt install -y nmap
```

### 11.2 Whitelist MAC asset inventory

```bash
# Su vm-103
sudo mkdir -p /var/lib/homesoc

sudo tee /var/lib/homesoc/mac_whitelist.txt << 'WHITELIST_EOF'
# HomeSOC — MAC Whitelist per UC-06 rogue device detection
# Formato: MAC|ID|Hostname|Tipo
# Aggiornare questo file ad ogni nuovo device approvato
# Fonte: docs/01-threat-model.md + Inventario_IP_Pulito.csv
# Ultima modifica: Aprile 2026

# Infrastruttura di rete
50:c7:bf:XX:XX:XX|INF-01|deco-be65-salotto|Mesh Gateway
# (aggiungere MAC reali dal CSV)

# Endpoint utente
c6:a3:2a:a3:a8:0f|END-05|macbook-pro-m1|MacBook Pro M1
38:f9:d3:bf:fe:65|END-06|macbook-air-nicole|MacBook Air Nicole

# NAS
00:00:c0:44:a4:97|NAS-01|mycloud-nas|WD My Cloud Home

# SOC-01 (host Proxmox)
XX:XX:XX:XX:XX:XX|SOC-01|soc-01|GMKtec M5 Ultra HomeSOC

# IoT — Robot
70:c9:32:2f:90:05|IOT-01|robot-dreame|Dreame Robot Vacuum
80:9d:65:2c:d8:13|IOT-02|narwal-robot|Narwal Robot
b0:4a:39:1b:84:cd|IOT-03a|roborock-casa|Roborock A15 casa
b0:4a:39:0a:61:37|IOT-03b|roborock-negozio|Roborock negozio

# IoT — Telecamere
cc:ba:bd:79:e7:65|CAM-01|tapo-camera|TP-Link Tapo
0c:a6:4c:52:89:81|CAM-02|ezviz-1|Ezviz camera 1
54:d6:0d:f0:6f:eb|CAM-03|ezviz-2|Ezviz camera 2
14:a7:8b:ce:f0:63|CAM-04|dahua-1|Dahua OEM camera
08:02:8e:a3:dd:dc|CAM-05|arlo-base|Netgear Arlo base

# IoT — Automazione
e4:b3:23:2b:99:fc|AUTO-01|shelly-plus2pm|Shelly Plus 2PM Gen3
28:6d:97:d5:0e:c9|AUTO-02a|smartthings-1|Samsung SmartThings
28:6d:97:d5:42:09|AUTO-02b|smartthings-2|Samsung SmartThings
28:6d:97:d0:fb:fe|AUTO-02c|smartthings-3|Samsung SmartThings
70:2c:1f:49:15:72|AUTO-03|wisol-module|Wisol IoT module
40:f5:20:ef:18:67|AUTO-04|esp-ef1867|Luce smart sala (Espressif/Tuya)
WHITELIST_EOF
```

> ℹ️ Completare i MAC mancanti (XX:XX:XX) leggendoli dall'`Inventario_IP_Pulito.csv`. Sono stati omessi perché non riportati nel threat model.

### 11.3 Script di rilevazione

```bash
# Su vm-103
sudo tee /opt/homesoc/scripts/rogue-device-check.sh << 'SCRIPT_EOF'
#!/bin/bash
# ============================================================
# HomeSOC — Rogue Device Detection (UC-06 / T1200)
# File: /opt/homesoc/scripts/rogue-device-check.sh
# Cron: ogni 15 minuti
# Output: evento Wazuh se device non in whitelist
# ============================================================

SUBNET="192.168.68.0/24"
WHITELIST="/var/lib/homesoc/mac_whitelist.txt"
WAZUH_LOG="/var/log/homesoc/rogue-device.log"
ALERT_DEDUP="/var/lib/homesoc/rogue_seen.tmp"

# Leggi whitelist (solo MAC, lowercase, no commenti)
APPROVED_MACS=$(grep -v "^#" "$WHITELIST" | awk -F'|' '{print tolower($1)}' | grep -v "^$" | grep -v "^xx")

# ARP scan della subnet
# NOTA v1.1: output nmap standard (no -oG) + awk multi-pattern per IP e MAC
# Il parser -oG con grep/awk/sed non gestisce correttamente tutti i formati MAC
SCAN_RESULT=$(sudo nmap -sn -PR "$SUBNET" 2>/dev/null | \
  awk '/Nmap scan report/{ip=$NF; gsub(/[()]/,"",ip)} /MAC Address/{print ip, tolower($3)}')

# Confronta ogni MAC trovato con la whitelist
while IFS= read -r line; do
  IP=$(echo "$line" | awk '{print $1}')
  MAC=$(echo "$line" | awk '{print tolower($2)}')

  # Salta se MAC non presente (device che non risponde ad ARP)
  [ -z "$MAC" ] || [ "$MAC" = "" ] && continue

  # Salta IP del gateway e del SOC stesso
  [ "$IP" = "192.168.68.1" ] || [ "$IP" = "192.168.68.200" ] && continue

  # Controlla se MAC è in whitelist
  if ! echo "$APPROVED_MACS" | grep -qi "^${MAC}$"; then
    # Deduplicazione: non alertare più volte per lo stesso MAC nello stesso ciclo
    DEDUP_KEY="${MAC}"
    if grep -q "$DEDUP_KEY" "$ALERT_DEDUP" 2>/dev/null; then
      continue
    fi
    echo "$DEDUP_KEY" >> "$ALERT_DEDUP"

    # Scrivi evento nel log Wazuh
    echo "$(date -Iseconds) homesoc rogue-device: event=\"new_device\" mac=\"${MAC}\" ip=\"${IP}\" status=\"not_in_whitelist\"" \
      >> "$WAZUH_LOG"
  fi
done <<< "$SCAN_RESULT"

# Pulisci dedup ogni ora (gestito dal cron)
HOUR=$(date +%M)
if [ "$HOUR" = "00" ]; then
  > "$ALERT_DEDUP"
fi
SCRIPT_EOF

sudo chmod +x /opt/homesoc/scripts/rogue-device-check.sh
```

### 11.4 Decoder Wazuh per rogue device

> ℹ️ **Fix v1.1:** il decoder usa `<program_name>rogue-device</program_name>` (non `<prematch>`) per coerenza con il comportamento confermato in produzione. La struttura è single-decoder perché il parent/child è necessario solo quando il regex deve operare sul corpo del messaggio DOPO stripping del programname — qui il `<prematch>` implicito del parent basta.

```bash
# Su vm-103
sudo tee /var/ossec/etc/decoders/homesoc-rogue-decoder.xml << 'DECODER_EOF'
<!--
  HomeSOC — Decoder rogue device detection
  File: /var/ossec/etc/decoders/homesoc-rogue-decoder.xml
  v1.1 — Fix: program_name invece di prematch (confermato in prod)
-->

<!-- Parent: filtra per program_name=rogue-device -->
<decoder name="homesoc-rogue-device">
  <program_name>^rogue-device$</program_name>
</decoder>

<!-- Child: estrae i campi evento -->
<decoder name="homesoc-rogue-device-fields">
  <parent>homesoc-rogue-device</parent>
  <regex type="pcre2">event="(\S+)" mac="(\S+)" ip="(\S+)" status="(\S+)"</regex>
  <order>event,mac,ip,status</order>
</decoder>
DECODER_EOF
```

### 11.5 Configurazione cron e logcollector

> ⚠️ **Fix v1.1 — Evitare duplicati in ossec.conf:** il blocco `<localfile>` per rogue-device deve essere presente **una sola volta** in `ossec.conf`. Se lo script Python viene eseguito più volte (es. dopo un restart del manager), il replace su `</ossec_config>` potrebbe inserire il blocco due volte. Verificare sempre con `grep -c "rogue-device.log" /var/ossec/etc/ossec.conf` prima di eseguire — deve restituire `1`. In caso di duplicato: editare manualmente `ossec.conf` e rimuovere il blocco sovrannumerario.

```bash
# Su vm-103
sudo crontab -e
# Aggiungere:
# */15 * * * * /opt/homesoc/scripts/rogue-device-check.sh >> /var/log/homesoc/rogue-device-cron.log 2>&1

# Aggiungere localfile rogue-device in ossec.conf — con guard anti-duplicato
sudo python3 - << 'PYTHON_EOF'
CONF = '/var/ossec/etc/ossec.conf'
with open(CONF, 'r') as f:
    content = f.read()

# Guard: non inserire duplicati (causa di "No decoder matched" osservata in prod)
if 'rogue-device.log' in content:
    print("INFO: localfile rogue-device già presente in ossec.conf — nessuna modifica")
    exit(0)

LOCALFILE = """
  <!-- HomeSOC — Rogue device detection log (UC-06) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/homesoc/rogue-device.log</location>
  </localfile>
"""
content = content.replace('</ossec_config>', LOCALFILE + '\n</ossec_config>')
with open(CONF, 'w') as f:
    f.write(content)
print("OK: localfile rogue-device aggiunto a ossec.conf")
PYTHON_EOF

sudo systemctl reload wazuh-manager
```

---

## 12. Script NAS port monitor — UC-04

Il WD My Cloud Home non supporta syslog nativo. La detection di UC-04 (T1078 — accesso non autorizzato) è implementata tramite **monitoraggio periodico dei servizi esposti** dal NAS: se una porta nuova appare o SMB scompare, viene generato un alert. Baseline rilevata con nmap in Aprile 2026: porte `80 139 445 4430 5357 8001 8010 8543 9999 33284`.

### 12.1 Script nas-monitor.sh

```bash
# Su vm-103
sudo tee /opt/homesoc/scripts/nas-monitor.sh << 'SCRIPT_EOF'
#!/bin/bash
# ============================================================
# HomeSOC — NAS Port Monitor (UC-04 / T1078 / T1571)
# Monitora variazioni nei servizi esposti dal NAS WD My Cloud Home
# File: /opt/homesoc/scripts/nas-monitor.sh
# Cron: ogni 30 minuti
# Output: /var/log/homesoc/nas-monitor.log
#
# v1.1 — Fix FP post-reboot: guard NAS offline — se nmap non trova
#   porte aperte, logga nas_offline e termina SENZA aggiornare la
#   baseline (previene FP "tutte le porte nuove" al ritorno online)
# v1.0 — Prima stesura
# ============================================================

NAS_IP="192.168.68.90"
BASELINE="/var/lib/homesoc/nas-baseline.txt"
LOG="/var/log/homesoc/nas-monitor.log"

# Scan porte note sul NAS (baseline Aprile 2026)
CURRENT=$(nmap -p 80,139,445,4430,5357,8001,8010,8543,9999,33284 \
  --open -oG - "$NAS_IP" 2>/dev/null | \
  grep "Ports:" | grep -oP '\d+/open' | cut -d/ -f1 | sort -n | tr '\n' ' ' | sed 's/ $//')

# Guard: NAS irraggiungibile o spento
# Se nmap non trova nessuna porta aperta, il NAS è probabilmente offline.
# NON aggiornare la baseline — altrimenti al ritorno online tutte le porte
# appaiono "nuove" generando un false positive (rule 100030 L12).
# Rilevato in produzione: 2026-04-22, causa spegnimento notturno NAS.
if [ -z "$CURRENT" ]; then
  echo "$(date -Iseconds) homesoc nas-monitor: event=\"nas_offline\" port=\"N/A\" nas=\"${NAS_IP}\" status=\"unreachable\"" >> "$LOG"
  exit 0
fi

# Prima esecuzione: salva baseline
if [ ! -f "$BASELINE" ]; then
  echo "$CURRENT" > "$BASELINE"
  echo "$(date -Iseconds) homesoc nas-monitor: event=\"baseline_created\" ports=\"${CURRENT}\" nas=\"${NAS_IP}\"" >> "$LOG"
  exit 0
fi

PREVIOUS=$(cat "$BASELINE")

# Porte nuove — possibile backdoor post-compromise
NEW_PORTS=$(comm -13 \
  <(echo "$PREVIOUS" | tr ' ' '\n' | sort) \
  <(echo "$CURRENT"  | tr ' ' '\n' | sort) | tr '\n' ' ' | sed 's/ $//')

# Porte chiuse
CLOSED_PORTS=$(comm -23 \
  <(echo "$PREVIOUS" | tr ' ' '\n' | sort) \
  <(echo "$CURRENT"  | tr ' ' '\n' | sort) | tr '\n' ' ' | sed 's/ $//')

if [ -n "$NEW_PORTS" ]; then
  echo "$(date -Iseconds) homesoc nas-monitor: event=\"new_port\" port=\"${NEW_PORTS}\" nas=\"${NAS_IP}\" status=\"unexpected_service\"" >> "$LOG"
fi

# Alert specifico su SMB down — servizio critico
if echo "$CLOSED_PORTS" | grep -q "445"; then
  echo "$(date -Iseconds) homesoc nas-monitor: event=\"smb_down\" port=\"445\" nas=\"${NAS_IP}\" status=\"service_missing\"" >> "$LOG"
fi

# Aggiorna baseline (il guard sopra garantisce che CURRENT non sia vuoto)
echo "$CURRENT" > "$BASELINE"
SCRIPT_EOF

sudo chmod +x /opt/homesoc/scripts/nas-monitor.sh
```

### 12.2 Prima esecuzione — crea baseline

```bash
# Su vm-103
sudo /opt/homesoc/scripts/nas-monitor.sh
cat /var/log/homesoc/nas-monitor.log
# Atteso: event="baseline_created" ports="80 139 445 4430 5357 8001 8010 8543 9999 33284"
```

### 12.3 Decoder Wazuh per NAS monitor

```bash
# Su vm-103
sudo tee /var/ossec/etc/decoders/nas-monitor-decoder.xml << 'DECODER_EOF'
<!--
  HomeSOC — Decoder NAS port monitor
  File: /var/ossec/etc/decoders/nas-monitor-decoder.xml
-->
<decoder name="nas-monitor">
  <program_name>^nas-monitor$</program_name>
</decoder>

<decoder name="nas-monitor-fields">
  <parent>nas-monitor</parent>
  <regex type="pcre2">event="(\S+)" port="([^"]+)" nas="(\S+)" status="(\S+)"</regex>
  <order>nas.event,nas.port,nas.ip,nas.status</order>
</decoder>
DECODER_EOF
```

> ℹ️ Le regole corrispondenti (100030/100031) sono già nel file `local_rules.xml` (sezione 9.2).

### 12.4 Logcollector e cron

```bash
# Su vm-103 — aggiungere localfile in ossec.conf
sudo python3 << 'EOF'
CONF = '/var/ossec/etc/ossec.conf'
with open(CONF, 'r') as f:
    content = f.read()

if 'nas-monitor.log' in content:
    print("INFO: già presente")
    exit(0)

LOCALFILE = """
  <!-- HomeSOC — NAS monitor log (UC-04) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/homesoc/nas-monitor.log</location>
  </localfile>
"""
content = content.replace('</ossec_config>', LOCALFILE + '\n</ossec_config>')
with open(CONF, 'w') as f:
    f.write(content)
print("OK: localfile nas-monitor aggiunto")
EOF

sudo systemctl reload wazuh-manager

# Aggiungere cron ogni 30 minuti
sudo crontab -e
# Aggiungere:
# */30 * * * * /opt/homesoc/scripts/nas-monitor.sh >> /var/log/homesoc/nas-monitor-cron.log 2>&1
```

---

## 13. Verifica alert end-to-end

### 13.1 Test UC-01 — Brute Force SSH

```bash
# Da un device qualsiasi in LAN (es. MacBook) — genera 6 login SSH falliti
for i in {1..6}; do
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
    fakeuser@192.168.68.204 2>/dev/null || true
  sleep 2
done

# Su vm-103 — verifica alert
sudo tail -30 /var/ossec/logs/alerts/alerts.log | grep -A 5 "100001"
# Atteso: alert level 10 con srcip del MacBook
```

### 13.2 Test UC-03 — FIM

```bash
# Test FIM nativo — LaunchAgents system-level (rule 100020)
# Sul MacBook Pro M1
echo "test" | sudo tee /Library/LaunchAgents/com.homesoc.test.plist

# Su vm-103 — attendi 30 secondi e verifica
sudo tail -30 /var/ossec/logs/alerts/alerts.log | grep -A 5 "100020"
# Atteso: alert FIM level 12

# Pulizia test
sudo rm /Library/LaunchAgents/com.homesoc.test.plist

# Test FIM workaround — home directory (rule 100023)
# Sul MacBook Pro M1
echo "# fim-test" >> ~/.zshrc
sudo /Library/Ossec/fim-snapshot.sh

# Su vm-103
sudo tail -20 /var/ossec/logs/alerts/alerts.log | grep -A 5 "100023"
# Atteso: Rule 100023 (level 10) — modifica file critico: .zshrc

# Pulizia
sed -i '' '/# fim-test/d' ~/.zshrc
```

### 13.3 Test UC-06 — Rogue Device

```bash
# Su vm-103 — simula MAC non in whitelist
echo "$(date -Iseconds) homesoc rogue-device: event=\"new_device\" mac=\"aa:bb:cc:dd:ee:ff\" ip=\"192.168.68.200\" status=\"not_in_whitelist\"" \
  >> /var/log/homesoc/rogue-device.log

sleep 15
sudo tail -20 /var/ossec/logs/alerts/alerts.log | grep -A 5 "100040"
# Atteso: alert level 10
```

### 13.4 Test UC-02 — NextDNS

```bash
# Su vm-103 — inserisci riga simulata nel log
echo "$(date -Iseconds) homesoc nextdns: domain=\"www.baidu.com\" device=\"151.48.208.59\" blocked=\"ok\" reason=\"\"" \
  >> /var/log/homesoc/nextdns.log

sleep 15
sudo tail -20 /var/ossec/logs/alerts/alerts.log | grep -A 5 "100010"
# Atteso: Rule 100010 (level 8) — query DNS verso dominio cloud cinese
```

### 13.5 Test UC-04 — NAS Port Monitor

```bash
# Su vm-103 — simula porta inattesa sul NAS
echo "$(date -Iseconds) homesoc nas-monitor: event=\"new_port\" port=\"4444\" nas=\"192.168.68.90\" status=\"unexpected_service\"" \
  >> /var/log/homesoc/nas-monitor.log

sleep 15
sudo tail -20 /var/ossec/logs/alerts/alerts.log | grep -A 5 "100030"
# Atteso: Rule 100030 (level 12) — porta inattesa rilevata: 4444
```

### 13.6 Verifica Dashboard

1. **Dashboard** → `☰` → **Threat Hunting** → **Events** → filtrare per:
   `rule.id:(100001 OR 100010 OR 100020 OR 100023 OR 100030 OR 100040)`
2. Verificare che tutti gli alert di test compaiano con i livelli corretti
3. **Dashboard** → **Security Events** → verificare timeline attiva

---

## 14. Backup snapshot

### 14.1 Snapshot post-configurazione

```bash
# Su SOC-01
qm snapshot 103 "wazuh-phase3-complete" \
  --description "Wazuh 4.x single-node — tutti UC operativi: UC-01/02/03/04/06 — FIM workaround macOS — NAS port monitor — Aprile 2026"

qm listsnapshot 103
```

### 14.2 Inclusione nel job vzdump

```bash
# Su SOC-01
cat /etc/pve/jobs.cfg | grep -A 20 "vzdump"
```

Se vm-103 non è inclusa: **Web UI Proxmox** → `Datacenter` → `Backup` → job esistente → **Edit** → aggiungere vm-103.

---

## 15. Verifica finale e checklist

### 15.1 Checklist di completamento

**VM Proxmox:**
- [ ] VM `vm-103-wazuh` creata con ID 103
- [ ] 4 vCPU, 6144 MB RAM, 64 GB disco — `qm config 103 | grep -E "cores|memory|scsi0"`
- [ ] VM nel pool `phase2`, `onboot: 1`
- [ ] qemu-guest-agent attivo

**Rete:**
- [ ] MAC address vm-103 annotato in `Inventario_IP_Pulito.csv`
- [ ] DHCP reservation `192.168.68.204` creata su Deco BE65
- [ ] `ping 192.168.68.204` → OK da MacBook
- [ ] UFW attivo con regole corrette — `sudo ufw status numbered`

**Wazuh Stack:**
- [ ] `wazuh-manager` — `systemctl is-active wazuh-manager` → `active`
- [ ] `wazuh-indexer` — `systemctl is-active wazuh-indexer` → `active`
- [ ] `wazuh-dashboard` — `systemctl is-active wazuh-dashboard` → `active`
- [ ] Dashboard raggiungibile su `https://192.168.68.204`
- [ ] Password admin cambiata

**Agent macOS:**
- [ ] Wazuh Agent installato su MacBook Pro M1 (ARM64)
- [ ] Agent in stato `Active` in Dashboard → Agents
- [ ] `agent_control -l` su vm-103 mostra `macbook-pro-m1-ale · Active`

**FIM (UC-03):**
- [ ] `ossec.conf` macOS contiene sezione `<syscheck>` con percorsi configurati
- [ ] Test FIM `/Library/LaunchAgents` (system-level) → alert 100020 generato ✅
- [ ] Script `/Library/Ossec/fim-snapshot.sh` presente e baseline creata — `sudo cat /Library/Ossec/logs/fim-changes.log`
- [ ] Cron MacBook attivo — `sudo crontab -l | grep fim-snapshot`
- [ ] Test FIM workaround (.zshrc) → alert 100023 generato ✅
- [ ] ⚠️ **Limite noto FDA:** home dir non monitorata dal FIM nativo (sez. 8.3) — workaround operativo (rule 100023)

**Custom Rules:**
- [ ] `wazuh-analysisd -t` → nessun errore di sintassi
- [ ] Tutte le rule IDs presenti — `grep "rule id" /var/ossec/etc/rules/local_rules.xml | wc -l` → deve essere 12
- [ ] Test UC-01 (brute force) → alert 100001 generato ✅
- [ ] Test UC-02 (nextdns) → alert 100010 generato ✅
- [ ] Test UC-03 FIM nativo → alert 100020 generato ✅
- [ ] Test UC-03 FIM workaround → alert 100023 generato ✅
- [ ] Test UC-04 (NAS port monitor) → alert 100030 generato ✅
- [ ] Test UC-06 (rogue device) → alert 100040 generato ✅

**Ingestion esterna:**
- [ ] Script `nextdns-fetch.sh` con cron ogni 5 min — `sudo crontab -l | grep nextdns`
- [ ] Script `rogue-device-check.sh` con cron ogni 15 min
- [ ] Script `nas-monitor.sh` con cron ogni 30 min
- [ ] Script `fim-snapshot.sh` (MacBook) con cron ogni 5 min
- [ ] Decoder presenti: `nextdns-decoder.xml`, `homesoc-rogue-decoder.xml`, `fim-macos-decoder.xml`, `nas-monitor-decoder.xml`
- [ ] Logcollector vm-103 aggiornato per: `nextdns.log`, `rogue-device.log`, `nas-monitor.log`
- [ ] Logcollector MacBook aggiornato per: `fim-changes.log`

**Backup:**
- [ ] Snapshot `wazuh-configured` creato
- [ ] vm-103 inclusa nel job vzdump schedulato

### 15.2 Comandi diagnostici di riepilogo

```bash
# Su SOC-01
echo "=== VM Status ===" && qm status 103
echo "=== VM Config ===" && qm config 103 | grep -E "cores|memory|scsi0|net0"
echo "=== Ping ===" && ping -c 2 192.168.68.204 | tail -1
echo "=== Port 443 ===" && nc -zv 192.168.68.204 443 2>&1 | grep -o "succeeded\|refused"
echo "=== Port 55000 ===" && nc -zv 192.168.68.204 55000 2>&1 | grep -o "succeeded\|refused"
echo "=== Snapshots ===" && qm listsnapshot 103

# Su vm-103
echo "=== Wazuh Services ===" && for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
  echo "  ${svc}: $(systemctl is-active $svc)"
done
echo "=== Agents ===" && sudo /var/ossec/bin/agent_control -l
echo "=== Rules loaded ===" && grep -c "rule id" /var/ossec/etc/rules/local_rules.xml
echo "=== UFW ===" && sudo ufw status | grep Status
echo "=== Disk ===" && df -h / | tail -1
```

---

## 16. Troubleshooting

### Dashboard non raggiungibile — Connection refused su porta 443

```bash
# Su vm-103
sudo systemctl status wazuh-dashboard
sudo journalctl -u wazuh-dashboard -n 50

# Problema comune: Indexer non ancora pronto al boot del dashboard
sudo systemctl restart wazuh-indexer
sleep 30
sudo systemctl restart wazuh-dashboard
```

### Wazuh Indexer in crash — OOM killer

**Causa:** 6 GB RAM è al limite. OpenSearch richiede almeno 2 GB heap.

```bash
# Su vm-103
dmesg | grep -i "oom\|killed"

# Verifica heap JVM Indexer
grep "^-Xmx\|^-Xms" /etc/wazuh-indexer/jvm.options
# Default: -Xms512m -Xmx512m — se OOM, aumentare con cautela

# Alternativa: da SOC-01, aumentare RAM della VM a 8 GB
# (richiede riavvio VM)
# qm set 103 --memory 8192
# qm reset 103
```

### Agent macOS non si connette al Manager

```bash
# Sul MacBook Pro M1
sudo /Library/Ossec/bin/wazuh-control status
sudo tail -30 /Library/Ossec/logs/ossec.log | grep -E "error|ERROR|connect"

# Verifica connettività verso Manager
nc -zv 192.168.68.204 1514
nc -zv 192.168.68.204 1515

# Re-enrollment manuale se il certificato è scaduto o corrotto
sudo /Library/Ossec/bin/ossec-authd -m 192.168.68.204 -A macbook-pro-m1-ale
```

### Regole custom non triggerano

```bash
# Su vm-103
# Verifica sintassi
sudo /var/ossec/bin/ossec-analysisd -t
# Deve terminare senza errori

# Testa una regola manualmente con wazuh-logtest
echo '{"timestamp":"2026-04-16T10:00:00","srcip":"192.168.68.50","id":"5720"}' | \
  sudo /var/ossec/bin/wazuh-logtest
# Deve mostrare: Rule: 100001 (level 10) fired

# Verifica che il reload sia andato a buon fine
sudo grep "Reloaded" /var/ossec/logs/ossec.log | tail -5
```

### Scan FIM non parte sul macOS agent

```bash
# Sul MacBook Pro M1
# Verifica permessi — Wazuh ha bisogno di Full Disk Access su macOS
# Impostazioni di Sistema → Privacy e sicurezza → Accesso completo al disco
# Aggiungere: /Library/Ossec/bin/wazuh-agentd

sudo /Library/Ossec/bin/wazuh-control restart
sudo tail -30 /Library/Ossec/logs/ossec.log | grep syscheck
```

> ⚠️ **Limite noto FDA:** anche con FDA assegnato via GUI, la home directory potrebbe non essere accessibile se assegnata al binary `wazuh-agentd` anziché al bundle `.app`. Vedi sez. 8.3 per l'analisi completa e le soluzioni future.

### Decoder NextDNS non matcha — "No decoder matched"

**Causa più comune:** struttura decoder non corretta (single-decoder con `<program_name>` + `<regex>` senza parent/child) o regex engine OSSEC che non supporta `\S` senza `type="pcre2"`.

```bash
# Su vm-103

# 1. Verifica sintassi XML del decoder
xmllint --noout /var/ossec/etc/decoders/nextdns-decoder.xml
# Nessun output = XML valido

# 2. Verifica che il decoder sia strutturato correttamente (parent + child)
grep -A5 "decoder name=" /var/ossec/etc/decoders/nextdns-decoder.xml
# Deve mostrare due decoder: nextdns-log (parent) e nextdns-log-fields (child con <parent>)

# 3. Reload e retest
sudo systemctl reload wazuh-manager
echo "$(date -Iseconds) homesoc nextdns: domain=\"www.baidu.com\" device=\"151.48.208.59\" blocked=\"ok\" reason=\"\"" | \
  sudo /var/ossec/bin/wazuh-logtest

# 4. Se ancora "No decoder matched": verifica che il pre-decoder estragga program_name
# wazuh-logtest mostra "Phase 1: Completed pre-decoding" con program_name — deve essere 'nextdns'
# Se program_name è vuoto o diverso, il problema è nel formato del log (timestamp ISO non parsato)
# Soluzione alternativa: usare prematch nel parent invece di program_name
# <decoder name="nextdns-log">
#   <prematch>homesoc nextdns: domain=</prematch>
# </decoder>
```

### Dashboard mostra "No results" in Security Events

```bash
# Su vm-103
# Verifica che gli indici Wazuh esistano nell'Indexer
curl -k -u admin:<PASSWORD> \
  "https://192.168.68.204:9200/_cat/indices/wazuh-alerts-*?v"
# Deve listare indici con doc.count > 0

# Se vuoti, verifica che il Manager invii al Indexer
sudo grep "output" /var/ossec/etc/ossec.conf | grep indexer
```

### Script nextdns-fetch.sh restituisce errore 403

**Causa:** API Key errata o scaduta, oppure il Profile ID non corrisponde alla chiave.

```bash
# Test manuale API NextDNS
curl -v -H "X-Api-Key: <LA-TUA-API-KEY>" \
  "https://api.nextdns.io/profiles/<PROFILE-ID>/logs?limit=5"
# Risposta attesa: 200 OK con JSON
# Se 403: credenziali errate
# Se 404: Profile ID errato
```

---

## Prossimi passi

Dopo aver completato e verificato questa checklist:

1. Commit su Git:
   ```bash
   git add runbooks/wazuh-deploy.md
   git commit -m "runbooks(wazuh): v1.2 — Fase 3 completa, tutti UC operativi (UC-01/02/03/04/06)"
   ```

2. Aggiornare `docs/Inventario_IP_Pulito.csv`:
   - IP: `192.168.68.204`
   - MAC: *(letto con `ip link show ens18 | grep link/ether` dentro vm-103)*
   - Hostname: `vm-103-wazuh`
   - Servizi: `Wazuh Dashboard 443/tcp, API 55000/tcp, Agent 1514-1515/tcp`

3. Aggiornare `docs/01-threat-model.md`:
   - Sez. 6.1: tutti gli UC → `Implementato`
     - UC-01: `Implementato` — rule 100001
     - UC-02: `Implementato` — rule 100010, decoder nextdns-log
     - UC-03: `Implementato (parziale — FDA limit, workaround operativo)` — rule 100020/100023
     - UC-04: `Implementato (port monitor)` — rule 100030/100031, alternativa a syslog nativo
     - UC-06: `Implementato` — rule 100040
   - Sez. 3.2: aggiornare stato rischi R-02, R-06, R-08, R-10, R-11

4. Commit threat model aggiornato:
   ```bash
   git add docs/01-threat-model.md
   git commit -m "docs(threat-model): v1.3 — tutti UC Fase 3 implementati"
   ```

5. Procedere con il runbook successivo: **`runbooks/crowdsec-deploy.md`** (Fase 3 — su SOC-01 direttamente)
   - Installazione su SOC-01 (non VM dedicata)
   - Copertura: SSH protection, integrazione Wazuh, Hub threat intelligence
   - Preparazione per future esposizioni internet
---

*File: `runbooks/wazuh-deploy.md` · v1.2 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
