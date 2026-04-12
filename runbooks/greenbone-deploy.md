# Runbook — Greenbone Community Edition Deploy (ct-102)
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `runbooks/greenbone-deploy.md`  
**Versione:** 1.0 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 2 — Deploy  
**Prerequisito:** `runbooks/proxmox-setup.md` completato — SOC-01 operativo, pool `phase2` creato

> **Scopo:** Creare e configurare `ct-102` su Proxmox VE come container LXC Debian 12, installare Greenbone Community Edition (GCE) via Docker Compose, eseguire la prima scan di vulnerabilità sulla rete LAN e sui target del negozio (UC-05). Al termine di questo runbook Greenbone deve essere operativo, raggiungibile via browser, con almeno una scan schedulata settimanale e il primo report generato.

---

## Indice

1. [Prerequisiti](#1-prerequisiti)
2. [Creazione CT su Proxmox](#2-creazione-ct-su-proxmox)
3. [Configurazione base del container](#3-configurazione-base-del-container)
4. [Installazione Docker Engine](#4-installazione-docker-engine)
5. [Deploy Greenbone Community Edition](#5-deploy-greenbone-community-edition)
6. [Configurazione iniziale GSA](#6-configurazione-iniziale-gsa)
7. [Configurazione target e scan policy](#7-configurazione-target-e-scan-policy)
8. [Prima scan — UC-05 Negozio e LAN completa](#8-prima-scan--uc-05-negozio-e-lan-completa)
9. [Schedulazione scansioni settimanali](#9-schedulazione-scansioni-settimanali)
10. [Esportazione report e integrazione SOC](#10-esportazione-report-e-integrazione-soc)
11. [Backup snapshot](#11-backup-snapshot)
12. [Verifica finale e checklist](#12-verifica-finale-e-checklist)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Prerequisiti

### 1.1 Requisiti infrastrutturali

Prima di procedere verificare che il runbook `proxmox-setup.md` sia completato al 100%:

```bash
# Su SOC-01 — verifica Proxmox operativo
pveversion
# Output atteso: pve-manager/8.x.x

# Verifica storage disponibile (ct-102 richiede 32 GB)
pvesm status
# local-lvm deve avere ≥ 32 GB liberi

# Verifica RAM disponibile (ct-102 richiede 4 GB)
free -h
# Deve essere disponibile almeno 4 GB oltre al consumo corrente

# Verifica che il template Debian 12 sia scaricato
pveam list local | grep debian-12
# Se non presente, scaricarlo (vedi passo 1.4)

# Verifica che il pool phase2 esista
pvesh get /pools/phase2
```

> ✅ **Checkpoint:** Se uno di questi comandi fallisce, tornare al runbook `proxmox-setup.md` e completare le verifiche mancanti prima di continuare.

### 1.2 Specifiche ct-102

| Parametro | Valore |
|---|---|
| CT ID | `102` |
| Nome | `ct-102-greenbone` |
| OS | Debian 12 (bookworm) — template LXC |
| vCPU | 4 |
| RAM | 4 GB (4096 MB) — **no balloon** (Greenbone è memory-intensive) |
| Swap | 512 MB |
| Storage | 32 GB su `local-lvm` |
| Network | `vmbr0` (LAN — 192.168.68.0/24) |
| IP target | `192.168.68.203` (DHCP reservation da impostare) |
| Container type | **Privilegiato** (richiesto per Docker inside LXC) |
| Features | `nesting=1`, `keyctl=1` (richiesti per Docker) |

> ⚠️ **IMPORTANTE:** Il container **deve** essere creato come **privilegiato** (`Unprivileged: No`) con le features `nesting=1` e `keyctl=1` abilitate. Senza queste impostazioni Docker non funzionerà all'interno dell'LXC.

### 1.3 Informazioni di rete

| Parametro | Valore |
|---|---|
| IP ct-102 | `192.168.68.203` (DHCP reservation) |
| Gateway | `192.168.68.1` (Deco BE65) |
| DNS | `192.168.68.1` |
| Porta GSA (Web UI) | `9392/tcp` |
| Accesso Web UI | `http://192.168.68.203:9392` |

### 1.4 Download template Debian 12 (se non presente)

```bash
# Su SOC-01
# Aggiorna lista template disponibili
pveam update

# Cerca template Debian 12
pveam available | grep debian-12

# Scarica il template (scegliere la versione più recente)
pveam download local debian-12-standard_12.x-1_amd64.tar.zst

# Verifica download
pveam list local | grep debian-12
```

### 1.5 Target di scan — asset inventario

I target principali per la prima scan sono:

| Asset | ID | IP | Priorità | Use Case |
|---|---|---|---|---|
| POS Negozio 1 | NEG-01 | `192.168.68.64` | Critica | UC-05 |
| POS Negozio 2 | NEG-02 | `192.168.68.67` | Critica | UC-05 |
| NAS WD My Cloud | NAS-01 | `192.168.68.90` | Alta | UC-04 |
| MacBook Pro | END-05 | `192.168.68.108` | Alta | UC-03 |
| LAN completa | — | `192.168.68.0/24` | Media | Baseline |

> 📌 I POS (NEG-01, NEG-02) sono stati identificati come dispositivi **PAX Computer** dall'inventario IP. Sono i target prioritari dell'UC-05: qualsiasi CVE con CVSS ≥ 7.0 su questi host genera un ticket TheHive (configurazione Fase 4).

---

## 2. Creazione CT su Proxmox

La creazione avviene dalla **Web UI Proxmox** (`https://192.168.68.200:8006`) tramite procedura guidata, oppure interamente via CLI (sezione 2.7).

### 2.1 Avvia la creazione guidata

**Web UI:** `soc-01` → **Create CT** (pulsante in alto a destra)

### 2.2 Tab "General"

| Campo | Valore |
|---|---|
| Node | `soc-01` |
| CT ID | `102` |
| Hostname | `ct-102-greenbone` |
| Pool | `phase2` |
| Password | *(password root complessa, ≥16 caratteri)* |
| SSH public key | *(incollare la chiave pubblica ED25519 del MacBook — opzionale ma consigliato)* |
| **Unprivileged container** | ❌ **DESELEZIONARE** — il container deve essere **PRIVILEGIATO** |

> ⚠️ **CRITICO:** La checkbox "Unprivileged container" deve essere **deselezionata**. Un container unprivileged non supporta Docker in modo affidabile e causerà errori durante il deploy di Greenbone.

### 2.3 Tab "Template"

| Campo | Valore |
|---|---|
| Storage | `local` |
| Template | `debian-12-standard_12.x-1_amd64.tar.zst` |

### 2.4 Tab "Disks"

| Campo | Valore |
|---|---|
| Storage | `local-lvm` |
| Disk size (GiB) | `32` |

### 2.5 Tab "CPU"

| Campo | Valore |
|---|---|
| Cores | `4` |
| CPU limit | *(lasciare vuoto — no limit)* |

### 2.6 Tab "Memory"

| Campo | Valore |
|---|---|
| Memory (MiB) | `4096` |
| Swap (MiB) | `512` |

> ℹ️ Il **ballooning è disabilitato** intenzionalmente per Greenbone. GCE utilizza intensivamente la RAM per i feed NVT e per il motore OpenVAS — un limite dinamico causerebbe degradazione delle performance durante le scan.

### 2.7 Tab "Network"

| Campo | Valore |
|---|---|
| Name | `eth0` |
| Bridge | `vmbr0` |
| VLAN Tag | *(lasciare vuoto)* |
| Firewall | ✅ Abilitare |
| IPv4 | `DHCP` *(la reservation viene impostata nel passo 6)* |
| IPv6 | `SLAAC` oppure `None` |

### 2.8 Tab "DNS"

| Campo | Valore |
|---|---|
| DNS domain | `homesoc.lan` |
| DNS servers | `192.168.68.1` |

### 2.9 Tab "Confirm"

Rivedere il riepilogo. Verificare:
- Unprivileged: **No** (privilegiato)
- Cores: 4
- RAM: 4096 MB
- Disk: 32 GB su local-lvm
- Bridge: vmbr0

**Deselezionare** "Start after created" — il container deve essere configurato prima dell'avvio.

Click **Finish**.

### 2.10 Abilita features Docker (obbligatorio — CLI)

Dopo la creazione del CT, dalla shell di SOC-01:

```bash
# Abilita nesting e keyctl — OBBLIGATORIO per Docker
pct set 102 --features nesting=1,keyctl=1

# Verifica configurazione
pct config 102 | grep features
# Output atteso: features: keyctl=1,nesting=1
```

### 2.11 Avvio container

```bash
# Avvia ct-102
pct start 102

# Verifica stato
pct status 102
# Output atteso: status: running

# Verifica IP assegnato via DHCP
pct exec 102 -- ip addr show eth0 | grep inet
# Annotare l'IP assegnato — sarà usato fino alla DHCP reservation (passo 6)
```

### 2.12 Alternativa — Creazione via CLI (metodo completo)

```bash
# Crea il container con un solo comando
pct create 102 local:vztmpl/debian-12-standard_12.x-1_amd64.tar.zst \
  --hostname ct-102-greenbone \
  --cores 4 \
  --memory 4096 \
  --swap 512 \
  --rootfs local-lvm:32 \
  --net0 name=eth0,bridge=vmbr0,firewall=1,ip=dhcp \
  --nameserver 192.168.68.1 \
  --searchdomain homesoc.lan \
  --pool phase2 \
  --unprivileged 0 \
  --features nesting=1,keyctl=1 \
  --onboot 1 \
  --password  # Il sistema chiederà la password root interattivamente

# Avvia
pct start 102
```

---

## 3. Configurazione base del container

Accedere alla shell del container da SOC-01:

```bash
# Metodo 1: via pct exec (da SOC-01)
pct exec 102 -- bash

# Metodo 2: via console Web UI
# Proxmox Web UI: ct-102 → Console

# Metodo 3: SSH (se configurata la chiave pubblica)
ssh root@<IP-ct-102>
```

### 3.1 Aggiornamento sistema

```bash
# Aggiorna lista pacchetti e sistema
apt update && apt full-upgrade -y

# Installa utility essenziali
apt install -y \
  curl \
  wget \
  gnupg \
  ca-certificates \
  lsb-release \
  apt-transport-https \
  software-properties-common \
  htop \
  net-tools \
  iputils-ping \
  ncat \
  jq \
  unzip \
  git \
  cron \
  rsync
```

### 3.2 Configurazione hostname e /etc/hosts

```bash
# Verifica hostname
hostname
# Output atteso: ct-102-greenbone

# Aggiorna /etc/hosts
cat > /etc/hosts << 'EOF'
127.0.0.1       localhost
127.0.1.1       ct-102-greenbone.homesoc.lan ct-102-greenbone
192.168.68.203  ct-102-greenbone.homesoc.lan ct-102-greenbone
EOF
```

### 3.3 Configurazione timezone

```bash
timedatectl set-timezone Europe/Rome

# Verifica
timedatectl status
# "Time zone: Europe/Rome (CET, +0100)"
# "System clock synchronized: yes"
```

### 3.4 Hardening SSH del container

```bash
# Cambia porta SSH per sicurezza
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config

# Disabilita login root via password (se è stata aggiunta la chiave pubblica)
# SOLO SE si è aggiunta la chiave pubblica al passo 2.2
# sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Disabilita autenticazione password (se chiave configurata)
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config

systemctl restart ssh

# Verifica porta 2222
ss -tlnp | grep 2222
```

> ⚠️ Se non è stata aggiunta la chiave pubblica al passo 2.2, non disabilitare PasswordAuthentication — si perderebbe l'accesso SSH. In alternativa aggiungere la chiave ora con `ssh-copy-id -p 2222 root@<IP-ct-102>` prima di disabilitare la password.

### 3.5 Crea struttura directory per i report

```bash
# Directory per i report Greenbone esportati
mkdir -p /opt/homesoc/lab-reports/greenbone/{pdf,xml,csv}

# Directory per gli script di automazione
mkdir -p /opt/homesoc/scripts

# Permessi
chmod 750 /opt/homesoc
chmod 750 /opt/homesoc/lab-reports
chmod 750 /opt/homesoc/lab-reports/greenbone
```

---

## 4. Installazione Docker Engine

Greenbone Community Edition utilizza Docker Compose come metodo di deploy ufficiale. Prima di installare GCE è necessario installare Docker Engine.

### 4.1 Rimozione versioni precedenti

```bash
# Rimuovi versioni vecchie se presenti
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
  apt remove -y $pkg 2>/dev/null || true
done
```

### 4.2 Aggiunta repository Docker ufficiale

```bash
# Aggiungi chiave GPG Docker
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg \
  -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Aggiungi repository Docker
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

# Aggiorna e installa Docker
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### 4.3 Verifica e abilitazione Docker

```bash
# Avvia e abilita Docker all'avvio
systemctl enable docker
systemctl start docker

# Verifica stato
systemctl is-active docker
# Output atteso: active

# Test installazione
docker run --rm hello-world
# Output atteso: "Hello from Docker!"
```

> ✅ **Checkpoint:** Se il comando `docker run hello-world` riesce, Docker è correttamente installato. Se fallisce con errori di permessi o namespace, verificare che il container sia **privilegiato** e abbia le features `nesting=1,keyctl=1` (passo 2.10).

### 4.4 Configurazione Docker daemon

```bash
# Configura log rotation per evitare saturazione disco
cat > /etc/docker/daemon.json << 'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
EOF

systemctl restart docker
```

---

## 5. Deploy Greenbone Community Edition

### 5.1 Scarica il file docker-compose ufficiale

Greenbone distribuisce la Community Edition tramite un file `docker-compose.yml` ufficiale mantenuto nel repository `greenbone/greenbone-community-container`.

```bash
# Crea directory di lavoro per GCE
mkdir -p /opt/greenbone && cd /opt/greenbone

# Scarica il docker-compose.yml ufficiale
curl -fO https://greenbone.github.io/docs/latest/_static/docker-compose-22.4.yml
mv docker-compose-22.4.yml docker-compose.yml

# Verifica contenuto
cat docker-compose.yml | grep "image:" | head -10
```

> 📌 **Verifica versione:** La versione consigliata è la 22.4 (GVM 22.4 — stabile). Controllare eventuali versioni più recenti su https://greenbone.github.io/docs/latest/ prima di procedere.

### 5.2 Configurazione variabili d'ambiente

```bash
# Crea file .env con configurazione base
cat > /opt/greenbone/.env << 'EOF'
# Greenbone Community Edition — HomeSOC ct-102
# Configurazione variabili ambiente

# Porta GSA (web interface) — esposta sulla LAN
GVMD_ADMIN_PASSWORD=CHANGEME_STRONGPASSWORD

# Porta esterna GSA
GSA_PORT=9392

# Timezone
TZ=Europe/Rome
EOF

# ⚠️ SOSTITUIRE CHANGEME_STRONGPASSWORD con una password sicura (≥16 caratteri)
# Editare il file con nano:
nano /opt/greenbone/.env
```

> 🔒 **Sicurezza:** La password admin GCE deve essere robusta. Usare un gestore password per generarla e salvarla. Questa è la chiave di accesso all'intero sistema di vulnerability scanning.

### 5.3 Pull immagini Docker

```bash
cd /opt/greenbone

# Pull di tutte le immagini (operazione lunga — ~3-5 GB totali)
docker compose -f docker-compose.yml pull

# Verifica immagini scaricate
docker images | grep greenbone
```

> ℹ️ Il pull delle immagini richiede **10-20 minuti** a seconda della velocità della connessione. Le immagini principali sono:
> - `greenbone/gvm-libs` — librerie condivise
> - `greenbone/openvas-scanner` — scanner OpenVAS
> - `greenbone/ospd-openvas` — Open Scanner Protocol daemon
> - `greenbone/gvmd` — GVM Manager daemon
> - `greenbone/gsad` — Greenbone Security Assistant daemon (web UI)
> - `greenbone/notus-scanner` — scanner per Notus (pacchetti locali)

### 5.4 Avvio stack Greenbone

```bash
cd /opt/greenbone

# Avvia tutti i servizi in background
docker compose -f docker-compose.yml up -d

# Verifica stato container (attendere che tutti siano "Up")
docker compose -f docker-compose.yml ps
```

Output atteso (dopo ~2 minuti dall'avvio):

```
NAME                    IMAGE                          STATUS
greenbone-gvmd-1        greenbone/gvmd:stable          Up X minutes
greenbone-gsad-1        greenbone/gsad:stable          Up X minutes
greenbone-ospd-1        greenbone/ospd-openvas:stable  Up X minutes
greenbone-openvas-1     greenbone/openvas-scanner:...  Up X minutes
greenbone-notus-1       greenbone/notus-scanner:...    Up X minutes
greenbone-redis-1       greenbone/redis-server:...     Up X minutes
greenbone-pg-gvm-1      greenbone/pg-gvm:stable        Up X minutes
```

> ✅ **Checkpoint:** Tutti i container devono avere status `Up`. Se qualcuno è in `Exit` o `Restarting`, controllare i log con `docker compose logs <service-name>`.

### 5.5 Attesa feed NVT — fase di sincronizzazione iniziale

Al primo avvio, Greenbone deve scaricare e sincronizzare i **feed NVT (Network Vulnerability Tests)**. Questo processo richiede **30-90 minuti** al primo avvio.

```bash
# Monitora il progresso della sincronizzazione feed
docker compose -f docker-compose.yml logs -f greenbone-gvmd-1 | grep -i "feed\|sync\|loading"

# In alternativa, controlla il log di openvas-scanner
docker compose -f docker-compose.yml logs -f greenbone-openvas-1 | grep -i "NVT\|sync\|finish"

# Verifica se il feed è stato sincronizzato (cerca il count NVT)
docker exec -it greenbone-gvmd-1 gvmd --get-feeds
```

> ⚠️ **Non eseguire scan durante la sincronizzazione feed.** Attendere che il feed NVT sia completamente caricato prima di configurare i target. Una scan avviata con feed incompleto produrrà risultati inaffidabili.

Indicatori che la sincronizzazione è completa:
- I log di `gvmd` mostrano "Feed import: done" o simile
- Il conteggio NVT in `gvmd --get-feeds` è stabile (tipicamente 50.000–80.000 NVT)

### 5.6 Verifica porta GSA

```bash
# Verifica che la porta 9392 sia in ascolto
ss -tlnp | grep 9392
# Output atteso: LISTEN 0 ... *:9392 ...

# Test connettività dalla shell del container
curl -sk https://localhost:9392 -o /dev/null -w "%{http_code}"
# Output atteso: 200 oppure 302
```

### 5.7 Configura avvio automatico all'avvio del container

```bash
# Crea systemd service per avviare Greenbone all'avvio del container
cat > /etc/systemd/system/greenbone-community.service << 'EOF'
[Unit]
Description=Greenbone Community Edition (Docker Compose)
Requires=docker.service
After=docker.service network.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/greenbone
ExecStart=/usr/bin/docker compose -f docker-compose.yml up -d
ExecStop=/usr/bin/docker compose -f docker-compose.yml down
StandardOutput=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable greenbone-community.service

# Test: verifica che il servizio sia abilitato
systemctl is-enabled greenbone-community.service
# Output: enabled
```

---

## 6. Configurazione iniziale GSA

### 6.1 Cambio password admin (se non impostata via .env)

```bash
# Imposta o resetta la password dell'utente admin via CLI
docker exec -it greenbone-gvmd-1 \
  gvmd --user=admin --new-password="TuaPasswordSicura16+"

# Verifica: deve restituire 0 (successo)
echo "Exit code: $?"
```

### 6.2 Primo accesso Web UI

Da browser sul MacBook:
```
http://192.168.68.203:9392
```

> ⚠️ Se il container ha ancora un IP DHCP diverso da .203, usare l'IP corrente (letto con `pct exec 102 -- ip addr show eth0 | grep inet`). La DHCP reservation viene impostata nel passo successivo.

Credenziali di primo accesso:
- **Username:** `admin`
- **Password:** quella impostata nel `.env` o con `gvmd --new-password`

### 6.3 Impostazioni base interfaccia

Dopo il primo login, navigare in **Administration → Settings** e verificare/configurare:

| Impostazione | Valore |
|---|---|
| Timezone | `Europe/Rome` |
| Rows per page | `50` |
| Default scanner | `OpenVAS` |
| Auto-refresh interval | `30 seconds` |

### 6.4 Verifica stato feed e scanner

**Web UI:** `Administration` → `Feed Status`

I feed devono essere in stato `Current` (verde):
- **NVT** — Network Vulnerability Tests
- **CERT-Bund Advisories**
- **DFN-CERT Advisories**
- **SCAP Data** (CVE, CPE)

Se uno dei feed è in stato `Outdated` o `Update in progress`, attendere il completamento prima di procedere con le scan.

---

## 7. Configurazione target e scan policy

### 7.1 Crea credenziali per scan autenticata (opzionale)

Le scan autenticate permettono di rilevare vulnerabilità che richiedono accesso al sistema (es. patch mancanti). Per la scan LAN è opzionale; per i POS del negozio è consigliata se si hanno credenziali di accesso.

**Web UI:** `Configuration` → `Credentials` → `+ New Credential`

| Campo | Valore |
|---|---|
| Name | `homesoc-scan-creds` |
| Type | `Username + Password` |
| Username | *(credenziale di accesso al dispositivo, se disponibile)* |
| Password | *(password)* |

> ℹ️ Per la prima scan si procede **senza credenziali** (scan non autenticata). Questo è il metodo standard per un assessment esterno e produce risultati comparabili a quelli che vedrebbe un attaccante non autenticato.

### 7.2 Crea target — POS Negozio (UC-05)

**Web UI:** `Configuration` → `Targets` → `+ New Target`

**Target 1 — Negozio POS:**

| Campo | Valore |
|---|---|
| Name | `UC-05 — POS Negozio (NEG-01, NEG-02)` |
| Hosts | `192.168.68.64,192.168.68.67` |
| Port list | `All IANA assigned TCP and UDP` |
| Alive test | `ICMP, TCP-ACK Service & ARP Ping` |
| Credentials for SSH | *(lasciare vuoto — scan non autenticata)* |
| Comment | `PAX Computer POS — target UC-05 CVSS ≥ 7.0` |

Click **Save**.

### 7.3 Crea target — LAN completa (baseline)

**Target 2 — LAN HomeSOC:**

| Campo | Valore |
|---|---|
| Name | `HomeSOC LAN — Baseline Scan` |
| Hosts | `192.168.68.0/24` |
| Exclude hosts | `192.168.68.203` *(escludere se stessa — ct-102)* |
| Port list | `All IANA assigned TCP` |
| Alive test | `ICMP, TCP-ACK Service & ARP Ping` |
| Comment | `Scan LAN completa — baseline mensile` |

Click **Save**.

### 7.4 Crea target — Asset critici

**Target 3 — Asset critici HomeSOC:**

| Campo | Valore |
|---|---|
| Name | `HomeSOC Asset Critici` |
| Hosts | `192.168.68.90,192.168.68.108,192.168.68.200` |
| Port list | `All IANA assigned TCP and UDP` |
| Alive test | `ICMP, TCP-ACK Service & ARP Ping` |
| Comment | `NAS-01, MacBook END-05, SOC-01 — scan settimanale` |

### 7.5 Crea scan configuration (policy)

**Web UI:** `Configuration` → `Scan Configs` → `+ New Scan Config`

Per la scan UC-05 usare la configurazione **Full and fast** (già presente come built-in):
- Cerca "Full and fast" nella lista
- È la policy bilanciata tra completezza e velocità — adatta per scan periodiche su rete domestica

Per la scan di baseline LAN usare **Discovery** (built-in):
- Meno invasiva, ideale per mappare l'inventario

---

## 8. Prima scan — UC-05 Negozio e LAN completa

### 8.1 Crea task UC-05 — POS Negozio

**Web UI:** `Scans` → `Tasks` → `+ New Task`

| Campo | Valore |
|---|---|
| Name | `UC-05 — Vulnerability Scan POS Negozio` |
| Scan Targets | `UC-05 — POS Negozio (NEG-01, NEG-02)` |
| Scanner | `OpenVAS Default` |
| Scan Config | `Full and fast` |
| Order for target hosts | `Sequential` |
| Network Source Interface | *(lasciare default)* |
| Auto Delete Reports | `Keep all reports` |
| Comment | `ATT&CK T1190 — Initial Access — CVSS ≥ 7.0 → TheHive (Fase 4)` |

Click **Save**.

### 8.2 Crea task LAN Baseline

**Web UI:** `Scans` → `Tasks` → `+ New Task`

| Campo | Valore |
|---|---|
| Name | `HomeSOC LAN Baseline Scan` |
| Scan Targets | `HomeSOC LAN — Baseline Scan` |
| Scanner | `OpenVAS Default` |
| Scan Config | `Full and fast` |
| Comment | `Scan di baseline mensile — 192.168.68.0/24` |

Click **Save**.

### 8.3 Avvio manuale prima scan UC-05

**Web UI:** `Scans` → `Tasks` → selezionare `UC-05 — Vulnerability Scan POS Negozio` → click **▶ Start** (icona play verde).

La scan avanza attraverso le seguenti fasi:
1. **Queued** — in attesa di esecuzione
2. **Running: Host discovery** — ping sweep per verificare host attivi
3. **Running: Port scan** — scansione porte aperte
4. **Running: NVT tests** — esecuzione dei Network Vulnerability Tests
5. **Done** — scan completata, report disponibile

```bash
# Monitoraggio progressione da CLI (alternativa)
docker exec -it greenbone-gvmd-1 \
  gvmd --get-tasks 2>/dev/null | head -20
```

> ℹ️ La durata della prima scan "Full and fast" su 2 host (NEG-01, NEG-02) è tipicamente **15-45 minuti** a seconda dei servizi esposti. La scan LAN completa (254 host) richiede invece **2-6 ore**.

### 8.4 Monitoraggio scan in corso

**Web UI:** `Scans` → `Tasks` — la colonna **Status** mostra la percentuale di avanzamento.

Oppure via log Docker:

```bash
# Log del processo di scan
docker compose -f /opt/greenbone/docker-compose.yml \
  logs -f greenbone-openvas-1 | grep -i "host\|progress\|finish"
```

### 8.5 Verifica risultati

Al completamento della scan:

**Web UI:** `Scans` → `Reports` → click sul report più recente

Navigare in **Results** — verificare:
- **High** (CVSS 7.0–8.9) e **Critical** (CVSS 9.0–10.0): richiedono attenzione immediata (UC-05)
- **Medium** (CVSS 4.0–6.9): da pianificare nel backlog
- **Low / Log**: informativi

```bash
# Verifica risultati da CLI — conteggio per severità
docker exec -it greenbone-gvmd-1 \
  gvmd --get-results | grep -c "severity"
```

---

## 9. Schedulazione scansioni settimanali

### 9.1 Crea schedule in GSA

**Web UI:** `Configuration` → `Schedules` → `+ New Schedule`

**Schedule 1 — UC-05 Settimanale:**

| Campo | Valore |
|---|---|
| Name | `UC-05 Weekly Sunday 02:00` |
| Timezone | `Europe/Rome` |
| First Time | `Prossima domenica, 02:00` |
| Period | `1 week` |
| Duration | `4 hours` *(scan si interrompe se dura più di 4h)* |

**Schedule 2 — Baseline Mensile:**

| Campo | Valore |
|---|---|
| Name | `LAN Baseline Monthly 03:00` |
| Timezone | `Europe/Rome` |
| First Time | `Primo giorno del mese prossimo, 03:00` |
| Period | `1 month` |
| Duration | `8 hours` |

### 9.2 Associa schedule ai task

**Web UI:** `Scans` → `Tasks` → selezionare `UC-05 — Vulnerability Scan POS Negozio` → **Edit**:

| Campo | Valore |
|---|---|
| Schedule | `UC-05 Weekly Sunday 02:00` |
| Schedule Once | ❌ (scan ricorrente) |

Ripetere per il task **HomeSOC LAN Baseline Scan** con la schedule mensile.

### 9.3 Verifica schedule da CLI

```bash
# Lista schedule configurati
docker exec -it greenbone-gvmd-1 gvmd --get-schedules

# Lista task con schedule associato
docker exec -it greenbone-gvmd-1 gvmd --get-tasks
```

---

## 10. Esportazione report e integrazione SOC

### 10.1 Export report manuale via Web UI

**Web UI:** `Scans` → `Reports` → selezionare il report → **Download** (icona ↓)

Formati disponibili:
- **PDF** — per documentazione portfolio e comunicazione
- **XML** — per import in strumenti SIEM/SOAR (Fase 4: TheHive + Cortex)
- **CSV** — per analisi in spreadsheet

Salvare i report nella struttura:
```
/opt/homesoc/lab-reports/greenbone/
├── pdf/
│   └── UC-05_negozio_YYYYMMDD.pdf
├── xml/
│   └── UC-05_negozio_YYYYMMDD.xml
└── csv/
    └── UC-05_negozio_YYYYMMDD.csv
```

### 10.2 Script di export automatico post-scan

```bash
cat > /opt/homesoc/scripts/greenbone-export-report.sh << 'SCRIPT'
#!/bin/bash
# greenbone-export-report.sh
# Esporta l'ultimo report Greenbone in PDF e XML
# Uso: ./greenbone-export-report.sh [nome-prefisso]
#
# Prerequisito: gvm-cli installato
# pip3 install gvm-tools

set -euo pipefail

PREFIX="${1:-report}"
DATE=$(date +%Y%m%d_%H%M)
OUTDIR="/opt/homesoc/lab-reports/greenbone"
GVM_HOST="localhost"
GVM_PORT="9390"
ADMIN_PASSWORD="$(grep GVMD_ADMIN_PASSWORD /opt/greenbone/.env | cut -d= -f2)"

echo "[*] Connecting to GVM daemon..."

# Recupera l'ID dell'ultimo report
LAST_REPORT_ID=$(docker exec greenbone-gvmd-1 \
  gvmd --get-reports --sort-field=date --sort-reverse 2>/dev/null | \
  awk 'NR==1 {print $1}')

if [ -z "$LAST_REPORT_ID" ]; then
  echo "[!] Nessun report trovato"
  exit 1
fi

echo "[*] Last report ID: $LAST_REPORT_ID"

# Export PDF
echo "[*] Exporting PDF..."
docker exec greenbone-gvmd-1 \
  gvmd --get-report "$LAST_REPORT_ID" --format PDF \
  > "${OUTDIR}/pdf/${PREFIX}_${DATE}.pdf" 2>/dev/null

# Export XML
echo "[*] Exporting XML..."
docker exec greenbone-gvmd-1 \
  gvmd --get-report "$LAST_REPORT_ID" --format XML \
  > "${OUTDIR}/xml/${PREFIX}_${DATE}.xml" 2>/dev/null

echo "[+] Report esportato:"
echo "    PDF: ${OUTDIR}/pdf/${PREFIX}_${DATE}.pdf"
echo "    XML: ${OUTDIR}/xml/${PREFIX}_${DATE}.xml"

# Log per audit trail
echo "$(date -Iseconds) | EXPORT | $LAST_REPORT_ID | $PREFIX" \
  >> /opt/homesoc/lab-reports/greenbone/export-audit.log
SCRIPT

chmod +x /opt/homesoc/scripts/greenbone-export-report.sh
```

### 10.3 Cron job per export automatico post-scan domenicale

```bash
# Aggiunge cron job: ogni domenica alle 06:00 (dopo la scan delle 02:00)
# L'ora tiene conto della durata massima della scan (4h) + buffer 30min
(crontab -l 2>/dev/null; echo "0 6 * * 0 /opt/homesoc/scripts/greenbone-export-report.sh UC-05-negozio >> /var/log/greenbone-export.log 2>&1") | crontab -

# Verifica cron
crontab -l
```

### 10.4 Struttura report nel repository Git

Per il portfolio, i report vanno versionati nella cartella `lab-reports/`:

```
homesoc-project/
└── lab-reports/
    └── greenbone/
        ├── UC-05_negozio_20260413.pdf    ← prima scan
        ├── UC-05_negozio_20260413.xml    ← per import Fase 4
        └── baseline_LAN_20260501.pdf     ← baseline mensile
```

```bash
# Dal MacBook — copia i report via rsync (dopo aver completato la scan)
rsync -avz -e "ssh -p 2222" \
  root@192.168.68.203:/opt/homesoc/lab-reports/greenbone/ \
  ~/homesoc-project/lab-reports/greenbone/

# Commit nel repository
cd ~/homesoc-project
git add lab-reports/greenbone/
git commit -m "lab-reports(greenbone): UC-05 first scan $(date +%Y%m%d)"
```

### 10.5 Integrazione futura con Wazuh (Fase 3) e TheHive (Fase 4)

> ℹ️ Queste integrazioni saranno completate nelle fasi successive. I passi seguenti documentano il design per riferimento.

**Fase 3 — Import report Greenbone in Wazuh:**
- Script Python che legge il report XML e genera alert Wazuh per ogni finding CVSS ≥ 7.0
- Alert mappato su regola Wazuh custom (Rule ID 100050+)
- Configurazione: `configs/wazuh/greenbone-integration.py`

**Fase 4 — Ticket automatico TheHive:**
- Cortex analyzer `GreenBone_Vuln` legge il report XML
- Ogni finding CVSS ≥ 7.0 su NEG-01/NEG-02 crea un caso TheHive
- Playbook: `playbooks/UC-05-vuln-critica-negozio.md`

---

## 11. Backup snapshot

### 11.1 Snapshot Proxmox pre-scan (stato baseline)

```bash
# Da SOC-01 — prima di avviare qualsiasi scan significativa
pct snapshot 102 "greenbone-configured" \
  --description "GCE v22.4 configurato — feed sincronizzato — target UC-05 pronti — Aprile 2026"

# Verifica snapshot creato
pct listsnapshot 102
```

Output atteso:
```
             PARENT             SNAPNAME             TIME      DESCRIPTION
                                    current
                               greenbone-configured  XXXXXX  GCE v22.4 configurato ...
```

### 11.2 Backup dati Greenbone (volumi Docker)

I dati di Greenbone (report, configurazioni, feed NVT) sono salvati in volumi Docker. Prima di qualsiasi manutenzione:

```bash
# Lista volumi Docker GCE
docker volume ls | grep greenbone

# Backup volumi su storage locale
cd /opt/greenbone
docker compose -f docker-compose.yml stop

# Esegui backup dei volumi
mkdir -p /opt/homesoc/backups/greenbone-volumes
for vol in $(docker volume ls -q | grep greenbone); do
  echo "Backing up volume: $vol"
  docker run --rm \
    -v "${vol}:/source:ro" \
    -v "/opt/homesoc/backups/greenbone-volumes:/backup" \
    debian:12 \
    tar czf "/backup/${vol}_$(date +%Y%m%d).tar.gz" -C /source .
done

# Riavvia Greenbone
docker compose -f docker-compose.yml up -d

echo "[+] Backup volumi completato in /opt/homesoc/backups/greenbone-volumes/"
ls -lh /opt/homesoc/backups/greenbone-volumes/
```

### 11.3 Verifica inclusione ct-102 nel backup vzdump

```bash
# Da SOC-01 — verifica che ct-102 sia nel job di backup schedulato
cat /etc/pve/jobs.cfg | grep -A 20 "vzdump"
```

Se ct-102 non è inclusa, aggiungere manualmente:

**Web UI Proxmox:** `Datacenter` → `Backup` → selezionare il job esistente → **Edit** → selezionare `ct-102` nella lista VM/CT.

---

## 12. Verifica finale e checklist

### 12.1 Checklist di completamento

**Container Proxmox:**
- [ ] CT `ct-102-greenbone` creata con ID 102
- [ ] Container **privilegiato** (`Unprivileged: No`) — verificare in `pct config 102`
- [ ] Features `nesting=1,keyctl=1` abilitate — verificare in `pct config 102 | grep features`
- [ ] 4 vCPU, 4096 MB RAM, 32 GB disco su `local-lvm` — verificare in `pct config 102`
- [ ] CT nel pool `phase2`
- [ ] `onboot: 1` nella configurazione CT

**Rete:**
- [ ] MAC address ct-102 annotato in `Inventario_IP_Pulito.csv`
- [ ] DHCP reservation `192.168.68.203` creata su Deco BE65
- [ ] IP `192.168.68.203` assegnato e stabile — verificare con `ping 192.168.68.203`
- [ ] Web UI GSA raggiungibile su `http://192.168.68.203:9392`

**Docker e Greenbone:**
- [ ] Docker Engine installato e attivo (`systemctl is-active docker`)
- [ ] `docker compose up -d` completato senza errori
- [ ] Tutti i container GCE in stato `Up` (`docker compose ps`)
- [ ] Feed NVT sincronizzati (`Administration` → `Feed Status` → tutti `Current`)
- [ ] Login GSA funzionante con utente `admin`
- [ ] Servizio `greenbone-community.service` abilitato all'avvio

**Target e scan:**
- [ ] Target `UC-05 — POS Negozio (NEG-01, NEG-02)` configurato
- [ ] Target `HomeSOC LAN — Baseline Scan` configurato
- [ ] Task `UC-05 — Vulnerability Scan POS Negozio` creata
- [ ] Task `HomeSOC LAN Baseline Scan` creata
- [ ] Prima scan UC-05 completata con successo
- [ ] Report disponibile in `Scans` → `Reports`
- [ ] Report PDF esportato in `/opt/homesoc/lab-reports/greenbone/pdf/`

**Schedulazione:**
- [ ] Schedule `UC-05 Weekly Sunday 02:00` creata
- [ ] Schedule `LAN Baseline Monthly 03:00` creata
- [ ] Schedule associata al task UC-05
- [ ] Cron export domenicale configurato

**Backup:**
- [ ] Snapshot Proxmox `greenbone-configured` creato
- [ ] ct-102 inclusa nel job backup vzdump schedulato

### 12.2 Comandi diagnostici di riepilogo

```bash
# Da SOC-01
echo "=== CT Status ===" && pct status 102
echo "=== CT Config (features) ===" && pct config 102 | grep -E "features|cores|memory|rootfs"
echo "=== Network Ping Greenbone ===" && ping -c 3 192.168.68.203
echo "=== Port 9392 Check ===" && nc -zv 192.168.68.203 9392 && echo "OPEN" || echo "CLOSED"
echo "=== CT Snapshots ===" && pct listsnapshot 102
echo "=== Storage ===" && pvesm status

# Da ct-102
echo "=== Docker Status ===" && docker info --format '{{.ServerVersion}}'
echo "=== GCE Containers ===" && docker compose -f /opt/greenbone/docker-compose.yml ps
echo "=== Disk Usage ===" && df -h /opt
echo "=== Feed Status ===" && docker exec greenbone-gvmd-1 gvmd --get-feeds 2>/dev/null | head -20
echo "=== Report Count ===" && docker exec greenbone-gvmd-1 gvmd --get-reports 2>/dev/null | wc -l
```

Output atteso:
```
=== CT Status ===
status: running
=== Port 9392 Check ===
Connection to 192.168.68.203 9392 port [tcp/*] succeeded!
OPEN
=== GCE Containers ===
NAME                    STATUS
greenbone-gvmd-1        Up X hours
greenbone-gsad-1        Up X hours
[...]
```

---

## 13. Troubleshooting

### Docker non si avvia nel container LXC — errori namespace

**Sintomi:** `docker run hello-world` fallisce con errori tipo `failed to create new user namespace` o `operation not permitted`.

**Causa:** Container LXC non privilegiato, o features `nesting`/`keyctl` mancanti.

```bash
# Da SOC-01 — verifica configurazione
pct config 102 | grep -E "unprivileged|features"

# Se "unprivileged: 1" → il container è non privilegiato → impossibile da correggere senza ricreare
# Se features mancanti → aggiungere a container spento
pct stop 102
pct set 102 --features nesting=1,keyctl=1
pct start 102

# Se il container è non privilegiato, deve essere ricreato con la flag corretta
# (vedi passo 2.2 — deselezionare "Unprivileged container")
```

### Container GCE in stato "Restarting" o "Exit"

```bash
# Visualizza log del container problematico
docker compose -f /opt/greenbone/docker-compose.yml logs greenbone-gvmd-1

# Causa comune 1: RAM insufficiente
free -h
# Se RAM < 4 GB → aumentare la RAM del CT dal Proxmox (pct set 102 --memory 4096)

# Causa comune 2: disco pieno
df -h /opt
# Se >90% → liberare spazio o aumentare il disco del CT

# Causa comune 3: volume Docker corrotto → ricreare
docker compose -f /opt/greenbone/docker-compose.yml down -v
docker compose -f /opt/greenbone/docker-compose.yml up -d
# ⚠️ ATTENZIONE: "down -v" cancella i volumi inclusi i report → fare backup prima
```

### GSA non raggiungibile sulla porta 9392

```bash
# Verifica che il container gsad sia in running
docker compose -f /opt/greenbone/docker-compose.yml ps | grep gsad

# Verifica porta in ascolto nel container
docker exec greenbone-gsad-1 ss -tlnp | grep 9392

# Verifica porta nel CT
ss -tlnp | grep 9392

# Se la porta non è esposta — verifica il docker-compose.yml
grep "9392" /opt/greenbone/docker-compose.yml

# Ricrea il servizio gsad
docker compose -f /opt/greenbone/docker-compose.yml restart greenbone-gsad-1
```

### Feed NVT non aggiornati — Feed Status "Outdated"

```bash
# Forza aggiornamento feed manuale
docker compose -f /opt/greenbone/docker-compose.yml \
  exec greenbone-gvmd-1 greenbone-feed-sync

# Monitora aggiornamento
docker compose -f /opt/greenbone/docker-compose.yml \
  logs -f greenbone-openvas-1 | grep -i "sync\|NVT\|feed"

# Il processo può richiedere 20-60 minuti
# Verificare completamento con:
docker exec greenbone-gvmd-1 gvmd --get-feeds
```

### Scan bloccata — status "Running" per ore senza progresso

```bash
# Verifica che OpenVAS scanner sia attivo
docker compose -f /opt/greenbone/docker-compose.yml ps greenbone-openvas-1

# Verifica log scanner per errori
docker compose -f /opt/greenbone/docker-compose.yml \
  logs --tail=100 greenbone-openvas-1

# Se necessario, cancella il task dalla Web UI e riavvia
# Oppure via CLI:
docker exec greenbone-gvmd-1 \
  gvmd --get-tasks | head -5
# Annotare il TASK_ID e:
docker exec greenbone-gvmd-1 \
  gvmd --stop-task="<TASK_ID>"
```

### Errore "Login failed" sulla Web UI GSA

```bash
# Reset password admin
docker exec -it greenbone-gvmd-1 \
  gvmd --user=admin --new-password="NuovaPasswordSicura"

# Se l'utente admin non esiste, crearlo
docker exec -it greenbone-gvmd-1 \
  gvmd --create-user=admin --password="NuovaPasswordSicura"

# Verifica utenti esistenti
docker exec -it greenbone-gvmd-1 \
  gvmd --get-users
```

### Scan non raggiunge i target — host risultano "down"

```bash
# Verifica connettività da ct-102 ai target
ping -c 3 192.168.68.64    # NEG-01
ping -c 3 192.168.68.67    # NEG-02

# Verifica routing
ip route show

# Verifica che il container Docker abbia accesso alla LAN
docker exec greenbone-openvas-1 ping -c 3 192.168.68.1

# Se i device IoT/POS hanno firewall che bloccano il ping
# provare "Alive Test: Consider Alive" nel target — NON usa ICMP
```

### Disco pieno — volumi Docker crescono troppo

```bash
# Verifica spazio usato dai volumi Docker
docker system df

# Rimuovi immagini e container non usati (NON rimuove i volumi dati)
docker system prune -f

# Se i volumi dati dei report crescono troppo
# Esporta i report vecchi e rimuovili dalla UI Greenbone
# Web UI: Scans → Reports → seleziona report vecchi → Delete

# Verifica spazio disco CT
df -h
```

---

## Prossimi passi

Dopo aver completato e verificato questa checklist:

1. Commit su Git:
   ```bash
   git add runbooks/greenbone-deploy.md
   git commit -m "runbooks(greenbone): add Phase 2 deploy runbook v1.0"
   ```

2. Aggiornare `docs/Inventario_IP_Pulito.csv` con:
   - IP: `192.168.68.203`
   - MAC: *(valore letto da `pct exec 102 -- ip link show eth0 | grep link/ether`)*
   - Hostname: `ct-102-greenbone`
   - Servizio: `Greenbone GCE 9392/tcp`

3. Aggiungere il primo report PDF al repository:
   ```bash
   git add lab-reports/greenbone/
   git commit -m "lab-reports(greenbone): UC-05 first scan results $(date +%Y%m%d)"
   ```

4. Procedere con il runbook successivo: **`runbooks/uptimekuma-deploy.md`**
   - Crea ct-101 su Proxmox (2 vCPU, 1 GB RAM, 16 GB, vmbr0)
   - Installa Uptime Kuma + Portainer in container LXC Debian 12
   - Configura probe ICMP/HTTP su tutti gli asset della rete (`192.168.68.0/24`)
   - Include probe su ct-102 Greenbone (`http://192.168.68.203:9392`)
   - Configura webhook verso HAOS (`192.168.68.201:8123/api/webhook/uptimekuma-homesoc-alert`)

---

*File: `runbooks/greenbone-deploy.md` · v1.0 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
