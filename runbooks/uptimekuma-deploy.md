# Runbook — Uptime Kuma + Portainer Deploy (ct-101)
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `runbooks/uptimekuma-deploy.md`  
**Versione:** 1.0 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 2 — Deploy  
**Prerequisito:** `runbooks/proxmox-setup.md` completato — SOC-01 operativo, pool `phase2` creato

> **Scopo:** Creare e configurare `ct-101` su Proxmox VE come container LXC Debian 12, installare **Uptime Kuma** (monitoring/alerting) e **Portainer CE** (gestione container) via Docker Compose. Al termine di questo runbook ct-101 deve monitorare proattivamente tutti gli asset della rete con probe ICMP e HTTP, inviare alert a Home Assistant tramite webhook, e Portainer deve essere operativo come pannello di gestione Docker per tutta la Fase 2.

---

## Indice

1. [Prerequisiti](#1-prerequisiti)
2. [Creazione CT su Proxmox](#2-creazione-ct-su-proxmox)
3. [Configurazione base del container](#3-configurazione-base-del-container)
4. [Installazione Docker Engine](#4-installazione-docker-engine)
5. [Deploy Portainer CE](#5-deploy-portainer-ce)
6. [Deploy Uptime Kuma](#6-deploy-uptime-kuma)
7. [Configurazione monitor — asset inventory](#7-configurazione-monitor--asset-inventory)
8. [Webhook verso Home Assistant](#8-webhook-verso-home-assistant)
9. [Notifiche aggiuntive — opzionali](#9-notifiche-aggiuntive--opzionali)
10. [Backup snapshot](#10-backup-snapshot)
11. [Verifica finale e checklist](#11-verifica-finale-e-checklist)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Prerequisiti

### 1.1 Requisiti infrastrutturali

Prima di procedere verificare che il runbook `proxmox-setup.md` sia completato al 100%:

```bash
# Su SOC-01 — verifica Proxmox operativo
pveversion
# Output atteso: pve-manager/8.x.x

# Verifica storage disponibile (ct-101 richiede 16 GB)
pvesm status
# local-lvm deve avere ≥ 16 GB liberi

# Verifica RAM disponibile (ct-101 richiede 1 GB)
free -h
# Deve essere disponibile almeno 1 GB oltre al consumo corrente

# Verifica che il template Debian 12 sia scaricato
pveam list local | grep debian-12
# Se non presente, vedi passo 1.4

# Verifica che il pool phase2 esista
pvesh get /pools/phase2
```

> ✅ **Checkpoint:** Se uno di questi comandi fallisce, tornare al runbook `proxmox-setup.md` e completare le verifiche mancanti prima di continuare.

### 1.2 Specifiche ct-101

| Parametro | Valore |
|---|---|
| CT ID | `101` |
| Nome | `ct-101-monitoring` |
| OS | Debian 12 (bookworm) — template LXC |
| vCPU | 2 |
| RAM | 1 GB (1024 MB) — balloon abilitato, min 512 MB |
| Swap | 512 MB |
| Storage | 16 GB su `local-lvm` |
| Network | `vmbr0` (LAN — 192.168.68.0/24) |
| IP target | `192.168.68.202` (DHCP reservation da impostare) |
| Container type | **Privilegiato** (richiesto per Docker inside LXC) |
| Features | `nesting=1`, `keyctl=1` (richiesti per Docker) |

> ⚠️ **IMPORTANTE:** Anche per ct-101, esattamente come per ct-102, il container **deve** essere **privilegiato** con features `nesting=1` e `keyctl=1`. Docker non funziona in LXC unprivileged senza configurazioni aggiuntive complesse.

### 1.3 Informazioni di rete

| Parametro | Valore |
|---|---|
| IP ct-101 | `192.168.68.202` (DHCP reservation) |
| Gateway | `192.168.68.1` (Deco BE65) |
| DNS | `192.168.68.1` |
| Porta Uptime Kuma | `3001/tcp` |
| Porta Portainer | `9000/tcp` (HTTP) · `9443/tcp` (HTTPS) |
| Accesso Uptime Kuma | `http://192.168.68.202:3001` |
| Accesso Portainer | `https://192.168.68.202:9443` |

### 1.4 Download template Debian 12 (se non presente)

```bash
# Su SOC-01
pveam update

# Cerca template disponibili
pveam available | grep debian-12

# Scarica la versione più recente
pveam download local debian-12-standard_12.x-1_amd64.tar.zst

# Verifica
pveam list local | grep debian-12
```

### 1.5 Dipendenze — stato atteso della Fase 2

Uptime Kuma deve monitorare tutti i servizi già deployati in Fase 2. Prima di configurare i monitor verificare lo stato atteso:

| Asset | IP | Servizio | Monitor type |
|---|---|---|---|
| SOC-01 Proxmox | `192.168.68.200` | TCP 8006 | TCP Port |
| vm-100 HAOS | `192.168.68.201` | HTTP 8123 | HTTP(s) |
| ct-102 Greenbone | `192.168.68.203` | HTTP 9392 | HTTP(s) |
| ct-101 self | `192.168.68.202` | ICMP | Ping |
| Gateway Deco BE65 | `192.168.68.1` | ICMP | Ping |
| NAS WD My Cloud | `192.168.68.90` | ICMP | Ping |
| MacBook Pro | `192.168.68.108` | ICMP | Ping |
| POS NEG-01 | `192.168.68.64` | ICMP | Ping |
| POS NEG-02 | `192.168.68.67` | ICMP | Ping |

> 📌 I monitor su vm-100 e ct-102 possono essere configurati solo se quei runbook sono stati completati. Se non ancora completati, configurare prima i monitor ICMP/Ping e aggiungere HTTP in seguito.

---

## 2. Creazione CT su Proxmox

La creazione avviene dalla **Web UI Proxmox** (`https://192.168.68.200:8006`) oppure via CLI (sezione 2.12).

### 2.1 Avvia la creazione guidata

**Web UI:** `soc-01` → **Create CT** (pulsante in alto a destra)

### 2.2 Tab "General"

| Campo | Valore |
|---|---|
| Node | `soc-01` |
| CT ID | `101` |
| Hostname | `ct-101-monitoring` |
| Pool | `phase2` |
| Password | *(password root complessa, ≥16 caratteri)* |
| SSH public key | *(incollare la chiave pubblica ED25519 del MacBook — consigliato)* |
| **Unprivileged container** | ❌ **DESELEZIONARE** — il container deve essere **PRIVILEGIATO** |

> ⚠️ **CRITICO:** La checkbox "Unprivileged container" deve essere **deselezionata**. Stessa motivazione di ct-102: Docker richiede container privilegiato in LXC.

### 2.3 Tab "Template"

| Campo | Valore |
|---|---|
| Storage | `local` |
| Template | `debian-12-standard_12.x-1_amd64.tar.zst` |

### 2.4 Tab "Disks"

| Campo | Valore |
|---|---|
| Storage | `local-lvm` |
| Disk size (GiB) | `16` |

### 2.5 Tab "CPU"

| Campo | Valore |
|---|---|
| Cores | `2` |
| CPU limit | *(lasciare vuoto)* |

### 2.6 Tab "Memory"

| Campo | Valore |
|---|---|
| Memory (MiB) | `1024` |
| Swap (MiB) | `512` |

> ℹ️ Il **ballooning è abilitato** per ct-101: Uptime Kuma e Portainer sono leggeri e tollerano variazioni dinamiche di memoria, a differenza di Greenbone. Il balloon permette a Proxmox di recuperare RAM inutilizzata per le altre VM/CT.

### 2.7 Tab "Network"

| Campo | Valore |
|---|---|
| Name | `eth0` |
| Bridge | `vmbr0` |
| VLAN Tag | *(lasciare vuoto)* |
| Firewall | ✅ Abilitare |
| IPv4 | `DHCP` *(la reservation viene impostata al passo 2.9)* |
| IPv6 | `None` |

### 2.8 Tab "DNS"

| Campo | Valore |
|---|---|
| DNS domain | `homesoc.lan` |
| DNS servers | `192.168.68.1` |

### 2.9 Tab "Confirm"

Rivedere il riepilogo e verificare:
- Unprivileged: **No**
- Cores: 2
- RAM: 1024 MB, balloon abilitato
- Disk: 16 GB su local-lvm
- Bridge: vmbr0

**Deselezionare** "Start after created". Click **Finish**.

### 2.10 Abilita features Docker (obbligatorio — CLI)

```bash
# Da SOC-01 — dopo la creazione del CT, prima dell'avvio
pct set 101 --features nesting=1,keyctl=1

# Verifica
pct config 101 | grep features
# Output atteso: features: keyctl=1,nesting=1
```

### 2.11 Avvio container e annotazione MAC

```bash
# Avvia ct-101
pct start 101

# Verifica stato
pct status 101
# Output atteso: status: running

# Annota il MAC address — serve per la DHCP reservation
pct exec 101 -- ip link show eth0 | grep link/ether
# es. link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
# ANNOTARE questo MAC → andrà inserito su Deco BE65 come reservation per 192.168.68.202

# Verifica IP assegnato via DHCP
pct exec 101 -- ip addr show eth0 | grep inet
```

> 📌 **DHCP Reservation su Deco BE65:** Admin → LAN → DHCP Reservation → Add
> - MAC: `<valore letto sopra>`
> - IP: `192.168.68.202`
> - Nome: `ct-101-monitoring`
>
> Dopo la reservation, riavviare il networking del CT oppure attendere il rinnovo DHCP:
> ```bash
> pct exec 101 -- dhclient -r eth0 && pct exec 101 -- dhclient eth0
> ```

### 2.12 Alternativa — Creazione via CLI (metodo completo)

```bash
pct create 101 local:vztmpl/debian-12-standard_12.x-1_amd64.tar.zst \
  --hostname ct-101-monitoring \
  --cores 2 \
  --memory 1024 \
  --swap 512 \
  --balloon 512 \
  --rootfs local-lvm:16 \
  --net0 name=eth0,bridge=vmbr0,firewall=1,ip=dhcp \
  --nameserver 192.168.68.1 \
  --searchdomain homesoc.lan \
  --pool phase2 \
  --unprivileged 0 \
  --features nesting=1,keyctl=1 \
  --onboot 1 \
  --password  # Il sistema chiederà la password root interattivamente

# Avvia
pct start 101
pct status 101
```

---

## 3. Configurazione base del container

### 3.1 Accesso al container

```bash
# Da SOC-01 — shell diretta nel container
pct enter 101

# Oppure via SSH (dopo configurazione chiave)
ssh root@192.168.68.202 -p 22
```

> Tutti i comandi nelle sezioni 3–9 vengono eseguiti **dentro ct-101** (come root), salvo indicazione esplicita contraria.

### 3.2 Aggiornamento sistema

```bash
apt update && apt full-upgrade -y

# Installa tool di base
apt install -y \
  curl \
  wget \
  ca-certificates \
  gnupg \
  lsb-release \
  apt-transport-https \
  software-properties-common \
  nano \
  htop \
  net-tools \
  iputils-ping \
  sudo \
  git \
  unattended-upgrades
```

### 3.3 Hostname e timezone

```bash
# Verifica hostname
hostname
# Output atteso: ct-101-monitoring

# Imposta timezone
timedatectl set-timezone Europe/Rome

# Verifica
timedatectl status
# Output atteso: Time zone: Europe/Rome (CET/CEST)
```

### 3.4 Configurazione unattended-upgrades

```bash
dpkg-reconfigure --priority=low unattended-upgrades
# Selezionare "Yes" quando richiesto

# Verifica
systemctl is-active unattended-upgrades
```

### 3.5 Verifica connettività

```bash
# Ping gateway
ping -c 4 192.168.68.1

# Ping DNS esterno
ping -c 4 1.1.1.1

# Verifica DNS resolution
nslookup google.com 192.168.68.1
```

> ✅ **Checkpoint:** Tutti e tre i test devono rispondere prima di procedere all'installazione di Docker.

---

## 4. Installazione Docker Engine

### 4.1 Rimozione versioni vecchie (se presenti)

```bash
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
  apt remove -y $pkg 2>/dev/null || true
done
```

### 4.2 Aggiungi repo ufficiale Docker

```bash
# Crea directory per le chiavi GPG
install -m 0755 -d /etc/apt/keyrings

# Scarica chiave GPG Docker
curl -fsSL https://download.docker.com/linux/debian/gpg \
  -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Aggiungi repo Docker
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

apt update
```

### 4.3 Installa Docker Engine e Docker Compose

```bash
apt install -y \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin
```

### 4.4 Abilita e avvia Docker

```bash
systemctl enable docker
systemctl start docker

# Verifica
systemctl is-active docker
# Output atteso: active

docker --version
# Output atteso: Docker version 27.x.x, build xxxxxxx

docker compose version
# Output atteso: Docker Compose version v2.x.x
```

### 4.5 Test installazione

```bash
docker run --rm hello-world
# Output atteso: "Hello from Docker!" — poi il container viene rimosso automaticamente
```

> ✅ **Checkpoint:** Se `hello-world` funziona, Docker è operativo nel container LXC privilegiato.

### 4.6 Crea struttura directory progetto

```bash
mkdir -p /opt/homesoc/{portainer,uptimekuma}/data
mkdir -p /opt/homesoc/compose

# Verifica struttura
tree /opt/homesoc/ 2>/dev/null || find /opt/homesoc -type d
```

---

## 5. Deploy Portainer CE

Portainer CE viene deployato **prima** di Uptime Kuma: fornisce la Web UI per gestire tutti i container Docker di ct-101 (e, con Portainer Agent, anche quelli di ct-102 in futuro).

### 5.1 Crea Docker Compose stack

```bash
cat > /opt/homesoc/compose/docker-compose.yml << 'EOF'
# HomeSOC ct-101 — Portainer CE + Uptime Kuma
# File: /opt/homesoc/compose/docker-compose.yml
# Versione: 1.0 — Aprile 2026

services:

  portainer:
    image: portainer/portainer-ce:latest
    container_name: portainer
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /opt/homesoc/portainer/data:/data
    ports:
      - "9000:9000"   # HTTP (redirect a HTTPS)
      - "9443:9443"   # HTTPS — Web UI principale
    networks:
      - homesoc-monitoring

  uptime-kuma:
    image: louislam/uptime-kuma:latest
    container_name: uptime-kuma
    restart: unless-stopped
    volumes:
      - /opt/homesoc/uptimekuma/data:/app/data
    ports:
      - "3001:3001"
    networks:
      - homesoc-monitoring
    depends_on:
      - portainer

networks:
  homesoc-monitoring:
    driver: bridge
    name: homesoc-monitoring
EOF
```

### 5.2 Avvia lo stack

```bash
cd /opt/homesoc/compose
docker compose up -d

# Verifica che entrambi i container siano in running
docker compose ps
```

Output atteso:
```
NAME           IMAGE                        COMMAND    SERVICE        STATUS    PORTS
portainer      portainer/portainer-ce:...   /portainer portainer      Up X s    0.0.0.0:9000->9000/tcp, 0.0.0.0:9443->9443/tcp
uptime-kuma    louislam/uptime-kuma:...     ...        uptime-kuma    Up X s    0.0.0.0:3001->3001/tcp
```

> ✅ **Checkpoint:** Entrambi i container in stato `Up`. Se uno dei due è `Restarting` o `Exit`, vedere la sezione [Troubleshooting](#12-troubleshooting).

### 5.3 Configurazione iniziale Portainer

Da browser sul MacBook, aprire: `https://192.168.68.202:9443`

> ⚠️ Il browser mostrerà un avviso certificato self-signed — accettare l'eccezione (normale per Portainer fresh install).

**Schermata "Create initial administrator":**

| Campo | Valore |
|---|---|
| Username | `admin` |
| Password | *(≥12 caratteri, complessa — annotare nel password manager)* |
| Confirm password | *(ripetere)* |

> ⚠️ Portainer mostra la schermata di registrazione solo nei **primi 5 minuti** dall'avvio. Se il timer scade, il container si blocca per sicurezza. In quel caso: `docker compose restart portainer` e procedere immediatamente.

**Schermata "Quick Setup":**
- Selezionare **"Get Started"** → poi **"local"** per gestire l'ambiente Docker locale

A questo punto Portainer è operativo e mostra i container del Docker locale di ct-101.

### 5.4 Crea servizio systemd per lo stack

```bash
cat > /etc/systemd/system/homesoc-monitoring.service << 'EOF'
[Unit]
Description=HomeSOC Monitoring Stack (Portainer + Uptime Kuma)
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/homesoc/compose
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable homesoc-monitoring.service

# Test (lo stack è già in running, quindi questo è un no-op sicuro)
systemctl start homesoc-monitoring.service
systemctl status homesoc-monitoring.service
```

---

## 6. Deploy Uptime Kuma

Uptime Kuma è già stato avviato al passo 5.2 come parte dello stack Docker Compose. Questo capitolo descrive la configurazione iniziale via Web UI.

### 6.1 Accesso Web UI

Da browser sul MacBook: `http://192.168.68.202:3001`

**Schermata "Create your admin account":**

| Campo | Valore |
|---|---|
| Username | `admin` |
| Password | *(≥12 caratteri — può coincidere con quella di Portainer o essere diversa)* |
| Confirm password | *(ripetere)* |

Click **"Create"** → si apre la dashboard principale di Uptime Kuma.

### 6.2 Panoramica interfaccia

La dashboard mostra tre aree principali:
- **Barra laterale sinistra:** lista monitor con indicatore up/down in tempo reale
- **Area centrale:** grafico uptime, latenza, storico eventi
- **Pulsante "+ Add New Monitor" (in alto):** per aggiungere nuovi monitor

---

## 7. Configurazione monitor — asset inventory

Per ogni monitor: click **"+ Add New Monitor"** → compilare i campi → **"Save"**.

Il capitolo è strutturato per gruppi di asset, nell'ordine prioritario raccomandato.

### 7.1 Gruppo "HomeSOC Infrastructure"

#### Monitor 1 — Gateway LAN (Deco BE65)

| Campo | Valore |
|---|---|
| Monitor Type | `Ping` |
| Friendly Name | `Gateway — Deco BE65` |
| Hostname | `192.168.68.1` |
| Heartbeat Interval | `60` secondi |
| Retries | `3` |
| Retry Interval | `20` secondi |
| Tags | `infrastructure`, `critical` |
| Description | `Gateway NAT principale — se down tutta la LAN è offline` |

> ⚠️ Questo è il monitor più critico: se il gateway va down, tutti gli altri monitor appariranno down per motivi di connettività, non per un problema reale sui singoli host. Usarlo come riferimento per il triage degli alert.

#### Monitor 2 — SOC-01 Proxmox (Web UI)

| Campo | Valore |
|---|---|
| Monitor Type | `TCP Port` |
| Friendly Name | `SOC-01 — Proxmox Web UI` |
| Hostname | `192.168.68.200` |
| Port | `8006` |
| Heartbeat Interval | `60` secondi |
| Retries | `3` |
| Tags | `infrastructure`, `soc` |

> ℹ️ Si usa `TCP Port` e non `HTTP(s)` perché il certificato di Proxmox è self-signed e causerebbe false positive SSL. Il TCP check sulla 8006 è sufficiente a verificare che il servizio sia in ascolto.

#### Monitor 3 — vm-100 Home Assistant

| Campo | Valore |
|---|---|
| Monitor Type | `HTTP(s)` |
| Friendly Name | `vm-100 — Home Assistant` |
| URL | `http://192.168.68.201:8123` |
| Heartbeat Interval | `60` secondi |
| Accepted Status Codes | `200-299`, `302`, `401` *(HAOS restituisce 200 o redirect al login)* |
| Retries | `3` |
| Tags | `infrastructure`, `soc`, `haos` |

#### Monitor 4 — ct-101 self (Uptime Kuma stesso)

| Campo | Valore |
|---|---|
| Monitor Type | `Ping` |
| Friendly Name | `ct-101 — Self (monitoring node)` |
| Hostname | `192.168.68.202` |
| Heartbeat Interval | `60` secondi |
| Tags | `infrastructure`, `soc` |

#### Monitor 5 — ct-102 Greenbone GSA

| Campo | Valore |
|---|---|
| Monitor Type | `HTTP(s)` |
| Friendly Name | `ct-102 — Greenbone GSA` |
| URL | `http://192.168.68.203:9392` |
| Heartbeat Interval | `120` secondi *(scan attive rallentano il GSA — intervallo più generoso)* |
| Accepted Status Codes | `200-299`, `302`, `401` |
| Retries | `3` |
| Tags | `infrastructure`, `soc`, `scanner` |

---

### 7.2 Gruppo "Negozio — POS Critici (UC-05)"

> 📌 I POS del negozio sono asset **critici** per UC-05. Un'interruzione prolungata impatta l'operatività commerciale. Gli alert su questi host devono avere priorità massima.

#### Monitor 6 — POS Negozio 1 (NEG-01)

| Campo | Valore |
|---|---|
| Monitor Type | `Ping` |
| Friendly Name | `NEG-01 — POS Negozio 1 (PAX)` |
| Hostname | `192.168.68.64` |
| Heartbeat Interval | `60` secondi |
| Retries | `3` |
| Retry Interval | `20` secondi |
| Tags | `negozio`, `pos`, `critical`, `uc-05` |
| Description | `POS PAX — Negozio Sesto San Giovanni` |

#### Monitor 7 — POS Negozio 2 (NEG-02)

| Campo | Valore |
|---|---|
| Monitor Type | `Ping` |
| Friendly Name | `NEG-02 — POS Negozio 2 (PAX)` |
| Hostname | `192.168.68.67` |
| Heartbeat Interval | `60` secondi |
| Retries | `3` |
| Retry Interval | `20` secondi |
| Tags | `negozio`, `pos`, `critical`, `uc-05` |
| Description | `POS PAX — Negozio Sesto San Giovanni` |

---

### 7.3 Gruppo "Home LAN — Asset chiave"

#### Monitor 8 — NAS WD My Cloud (NAS-01)

| Campo | Valore |
|---|---|
| Monitor Type | `Ping` |
| Friendly Name | `NAS-01 — WD My Cloud Home` |
| Hostname | `192.168.68.90` |
| Heartbeat Interval | `120` secondi |
| Retries | `3` |
| Tags | `home`, `storage`, `uc-04` |

#### Monitor 9 — MacBook Pro (END-05)

| Campo | Valore |
|---|---|
| Monitor Type | `Ping` |
| Friendly Name | `END-05 — MacBook Pro (admin)` |
| Hostname | `192.168.68.108` |
| Heartbeat Interval | `120` secondi |
| Retries | `2` |
| Tags | `home`, `endpoint` |

> ℹ️ Il MacBook può rispondere in modo intermittente al ping quando in sleep. I 2 retry e l'intervallo 120 s riducono i falsi positivi.

---

### 7.4 Configurazione Tag groups (raggruppamento visivo)

Uptime Kuma permette di raggruppare i monitor per tag nella dashboard. Per creare un raggruppamento visivo ordinato:

**Settings → Tags → Add Tag:**

| Tag | Colore | Uso |
|---|---|---|
| `critical` | Rosso (`#e74c3c`) | Asset con impatto operativo immediato se down |
| `infrastructure` | Blu (`#3498db`) | Componenti SOC e rete base |
| `soc` | Verde scuro (`#27ae60`) | Servizi SOC interni |
| `negozio` | Arancione (`#e67e22`) | Asset negozio (UC-05) |
| `home` | Grigio (`#95a5a6`) | Asset domestici |

---

## 8. Webhook verso Home Assistant

Il webhook permette a Uptime Kuma di inviare notifiche push a Home Assistant ogni volta che un monitor cambia stato (UP → DOWN o DOWN → UP). HAOS le riceve e può a sua volta generare notifiche su smartphone, creare automazioni, accendere indicatori visivi.

### 8.1 Configura il webhook in HAOS

Prima di configurare Uptime Kuma, creare l'endpoint webhook su Home Assistant:

**Su vm-100 — HAOS Web UI (`http://192.168.68.201:8123`):**

1. Vai in **Settings** → **Automations & Scenes** → **Create Automation**
2. Click **"Create new automation"** → **"Start with an empty automation"**
3. Configura:

**Trigger:**
- Trigger type: **Webhook**
- Webhook ID: `uptimekuma-homesoc-alert`
  - *(L'URL generato sarà: `http://192.168.68.201:8123/api/webhook/uptimekuma-homesoc-alert`)*

**Action:**
- Action type: **Send notification**
- Target: il tuo dispositivo mobile (o `notify.mobile_app_<device>`)
- Message: `{{ trigger.json.msg }}` *(usa il payload JSON di Uptime Kuma)*
- Title: `HomeSOC Alert — {{ trigger.json.monitor.name }}`

4. Salva l'automazione con nome: `HomeSOC — Uptime Kuma Alert`

> ✅ **Checkpoint:** Dopo il salvataggio, l'URL webhook sarà accessibile su `http://192.168.68.201:8123/api/webhook/uptimekuma-homesoc-alert`. Annotarlo — verrà usato al passo 8.2.

### 8.2 Configura la notifica in Uptime Kuma

**Su Uptime Kuma (`http://192.168.68.202:3001`):**

1. **Settings** (icona ingranaggio, in basso a sinistra) → **Notifications**
2. Click **"Setup Notification"**

| Campo | Valore |
|---|---|
| Notification Type | `Home Assistant` |
| Friendly Name | `HomeSOC — HAOS Alert` |
| Home Assistant URL | `http://192.168.68.201:8123` |
| Notification Service | `persistent_notification.create` *(o `notify.mobile_app_<device>` se preferito)* |
| Long-lived Access Token | *(vedi passo 8.3)* |

### 8.3 Generare Long-Lived Access Token in HAOS

**Su HAOS:**
1. Click sul tuo profilo (in basso a sinistra) → **Security**
2. Scroll fino a **"Long-lived access tokens"** → **"Create Token"**
3. Nome: `uptimekuma-homesoc`
4. **Copiare immediatamente il token** — viene mostrato una sola volta

> ⚠️ Conservare il token nel password manager. Se viene perso, deve essere revocato e ricreato.

Inserire il token nel campo **"Long-lived Access Token"** di Uptime Kuma (passo 8.2).

### 8.4 Test notifica

In Uptime Kuma, dopo aver salvato la notifica:
1. Click **"Test"** accanto alla notifica appena creata
2. Verificare che arrivi un messaggio di test in Home Assistant (**Notifications** → campanella in alto a destra in HAOS)

> ✅ **Checkpoint:** Il test deve generare una notifica visibile in HAOS. Se non appare, verificare il Long-Lived Token e l'URL di HAOS.

### 8.5 Associa la notifica ai monitor critici

Per ogni monitor in Uptime Kuma, aprire le impostazioni del monitor (click sul nome → Edit) e nella sezione **Notifications** abilitare `HomeSOC — HAOS Alert`.

Priorità di configurazione:
1. Monitor 1 (Gateway), Monitor 6 (NEG-01), Monitor 7 (NEG-02) → notifica **obbligatoria**
2. Monitor 2 (SOC-01), Monitor 3 (HAOS), Monitor 5 (Greenbone) → notifica **consigliata**
3. Monitor 8 (NAS), Monitor 9 (MacBook) → notifica **opzionale**

---

## 9. Notifiche aggiuntive — opzionali

Uptime Kuma supporta numerosi canali di notifica aggiuntivi. Queste configurazioni sono opzionali ma aumentano la copertura di alerting del SOC.

### 9.1 Webhook generico (alternativa a HAOS)

Se HAOS non è ancora configurato, è possibile usare un webhook generico verso qualsiasi servizio:

```
Notification Type: Webhook
URL: http://192.168.68.201:8123/api/webhook/uptimekuma-homesoc-alert
Request Method: POST
Content Type: application/json
Additional Headers: (vuoto)
Custom Body: {
  "monitor": "{{monitorName}}",
  "status": "{{status}}",
  "msg": "{{msg}}"
}
```

### 9.2 Notifica email (opzionale)

| Campo | Valore |
|---|---|
| Notification Type | `Email (SMTP)` |
| Friendly Name | `HomeSOC — Email Alert` |
| SMTP Host | *(il tuo provider SMTP — es. smtp.gmail.com)* |
| SMTP Port | `587` |
| TLS | StartTLS |
| Username | *(la tua email)* |
| Password | *(App Password generata dal provider)* |
| From | `homesoc-alerts@<tuo-dominio>` |
| To | *(la tua email di destinazione)* |

> ℹ️ Se si usa Gmail, generare una **App Password** specifica (non la password dell'account) tramite **Google Account** → **Security** → **2-Step Verification** → **App Passwords**.

### 9.3 Telegram (opzionale — consigliato per mobilità)

Telegram è particolarmente utile per alert in mobilità:

1. Creare un bot Telegram: `@BotFather` → `/newbot` → annotare il **Bot Token**
2. Ottenere il proprio **Chat ID**: inviare un messaggio al bot, poi interrogare `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. In Uptime Kuma: **Notification Type: Telegram** → inserire Bot Token e Chat ID

---

## 10. Backup snapshot

### 10.1 Snapshot Proxmox post-configurazione

Dopo aver completato e verificato tutta la configurazione, creare uno snapshot Proxmox come baseline:

```bash
# Da SOC-01
# Ferma il container per snapshot consistente (opzionale — lo snapshot funziona anche live)
# pct stop 101

# Crea snapshot
pct snapshot 101 monitoring-configured \
  --description "ct-101 monitoring — Portainer CE + Uptime Kuma configurati — Aprile 2026"

# Verifica snapshot creato
pct listsnapshot 101
```

> ✅ Lo snapshot `monitoring-configured` permette di ripristinare la configurazione completa in caso di problemi futuri senza ripartire dall'installazione.

### 10.2 Verifica inclusione nel job vzdump

Verificare che ct-101 sia incluso nel job di backup schedulato configurato nel runbook Proxmox:

```bash
# Da SOC-01 — verifica la configurazione del job vzdump
cat /etc/pve/jobs.cfg
# Verificare che CT 101 sia incluso (o che la policy sia "all")
```

Se ct-101 non è incluso, aggiungerlo dalla **Web UI Proxmox:** Datacenter → Backup → selezionare il job esistente → Edit → aggiungere CT 101 alla selezione.

### 10.3 Backup dati Uptime Kuma (manuale)

I dati di Uptime Kuma (database SQLite con tutti i monitor e la storia) sono nel volume Docker:

```bash
# Da ct-101
# Backup manuale del database
docker exec uptime-kuma tar czf /tmp/uptime-kuma-backup-$(date +%Y%m%d).tar.gz \
  -C /app/data .

# Copia backup fuori dal container
docker cp uptime-kuma:/tmp/uptime-kuma-backup-$(date +%Y%m%d).tar.gz \
  /opt/homesoc/uptimekuma/

# Verifica
ls -lh /opt/homesoc/uptimekuma/*.tar.gz
```

> ℹ️ In alternativa, Uptime Kuma dispone di una funzione di export nativa dalla Web UI: **Settings** → **Backup** → **Export** → scarica un JSON con tutti i monitor configurati.

---

## 11. Verifica finale e checklist

### 11.1 Checklist di completamento

Completare tutte le voci prima di dichiarare ct-101 operativo e procedere al prossimo step.

**Container Proxmox:**
- [ ] ct-101 creato con ID `101`, hostname `ct-101-monitoring`
- [ ] Container tipo: **Privilegiato** (unprivileged: no)
- [ ] Features `nesting=1,keyctl=1` verificate (`pct config 101 | grep features`)
- [ ] Pool `phase2` assegnato
- [ ] ct-101 in stato `running` (`pct status 101`)

**Rete:**
- [ ] MAC address ct-101 annotato in `docs/Inventario_IP_Pulito.csv`
- [ ] DHCP reservation `192.168.68.202` creata su Deco BE65
- [ ] IP `192.168.68.202` assegnato e stabile — verificare con `ping 192.168.68.202`
- [ ] Portainer Web UI raggiungibile su `https://192.168.68.202:9443`
- [ ] Uptime Kuma Web UI raggiungibile su `http://192.168.68.202:3001`

**Docker e stack:**
- [ ] Docker Engine installato e attivo (`systemctl is-active docker`)
- [ ] `docker compose up -d` completato senza errori
- [ ] `portainer` container in stato `Up` (`docker compose ps`)
- [ ] `uptime-kuma` container in stato `Up` (`docker compose ps`)
- [ ] Servizio `homesoc-monitoring.service` abilitato all'avvio

**Portainer:**
- [ ] Account admin Portainer creato
- [ ] Ambiente `local` configurato e visibile
- [ ] Entrambi i container (portainer, uptime-kuma) visibili in Portainer

**Uptime Kuma — monitor configurati:**
- [ ] Monitor 1: Gateway `192.168.68.1` — Ping
- [ ] Monitor 2: SOC-01 Proxmox `192.168.68.200:8006` — TCP Port
- [ ] Monitor 3: vm-100 HAOS `http://192.168.68.201:8123` — HTTP
- [ ] Monitor 4: ct-101 self `192.168.68.202` — Ping
- [ ] Monitor 5: ct-102 Greenbone `http://192.168.68.203:9392` — HTTP
- [ ] Monitor 6: NEG-01 POS `192.168.68.64` — Ping
- [ ] Monitor 7: NEG-02 POS `192.168.68.67` — Ping
- [ ] Monitor 8: NAS-01 `192.168.68.90` — Ping
- [ ] Monitor 9: MacBook `192.168.68.108` — Ping

**Alerting:**
- [ ] Notifica `HomeSOC — HAOS Alert` configurata in Uptime Kuma
- [ ] Long-Lived Token HAOS generato e inserito
- [ ] Test notifica superato (messaggio ricevuto in HAOS)
- [ ] Notifica associata ai monitor critici (Gateway, NEG-01, NEG-02)

**Backup:**
- [ ] Snapshot Proxmox `monitoring-configured` creato (`pct listsnapshot 101`)
- [ ] ct-101 incluso nel job vzdump schedulato

### 11.2 Comandi diagnostici di riepilogo

```bash
# Da SOC-01
echo "=== CT Status ===" && pct status 101
echo "=== CT Config ===" && pct config 101 | grep -E "features|cores|memory|rootfs"
echo "=== Network Ping ===" && ping -c 3 192.168.68.202
echo "=== Port 3001 (Uptime Kuma) ===" && nc -zv 192.168.68.202 3001 && echo "OPEN" || echo "CLOSED"
echo "=== Port 9443 (Portainer) ===" && nc -zv 192.168.68.202 9443 && echo "OPEN" || echo "CLOSED"
echo "=== CT Snapshots ===" && pct listsnapshot 101
echo "=== Storage ===" && pvesm status

# Da ct-101
echo "=== Docker Status ===" && docker info --format '{{.ServerVersion}}'
echo "=== Stack Containers ===" && docker compose -f /opt/homesoc/compose/docker-compose.yml ps
echo "=== Disk Usage ===" && df -h /opt
echo "=== Memory ===" && free -h
echo "=== Service ===" && systemctl is-active homesoc-monitoring.service
```

Output atteso:
```
=== CT Status ===
status: running
=== Port 3001 (Uptime Kuma) ===
Connection to 192.168.68.202 3001 port [tcp/*] succeeded!
OPEN
=== Port 9443 (Portainer) ===
Connection to 192.168.68.202 9443 port [tcp/*] succeeded!
OPEN
=== Stack Containers ===
NAME           STATUS
portainer      Up X hours
uptime-kuma    Up X hours
=== Service ===
active
```

---

## 12. Troubleshooting

### Docker non si avvia nel container LXC — errori namespace

**Sintomi:** `docker run hello-world` fallisce con `failed to create new user namespace` o `operation not permitted`.

**Causa:** Container non privilegiato o features mancanti.

```bash
# Da SOC-01
pct config 101 | grep -E "unprivileged|features"

# Se features mancanti → aggiungere a container spento
pct stop 101
pct set 101 --features nesting=1,keyctl=1
pct start 101

# Se il container è unprivileged → deve essere ricreato
# (vedi sezione 2.2 — deselezionare "Unprivileged container")
```

### Uptime Kuma non si avvia — porta 3001 già in uso

```bash
# Da ct-101 — verifica porte in uso
ss -tlnp | grep 3001

# Se la porta è occupata da un altro processo
# Identificare e fermare il processo
fuser -k 3001/tcp

# Riavvia il container
docker compose -f /opt/homesoc/compose/docker-compose.yml restart uptime-kuma
```

### Portainer: timer registrazione scaduto

Se si accede alla Web UI di Portainer oltre i 5 minuti dal primo avvio, compare il messaggio "This Portainer instance timed out for security purposes".

```bash
# Da ct-101 — riavvia il container Portainer
docker compose -f /opt/homesoc/compose/docker-compose.yml restart portainer
```

Aprire immediatamente `https://192.168.68.202:9443` e completare la registrazione.

### Monitor Uptime Kuma: falsi positivi su MacBook (Ping intermittente)

Il MacBook può entrare in sleep e non rispondere al ping. Soluzioni:

1. **Aumentare i retry:** Settings del monitor → Retries = `5`, Retry Interval = `30 s`
2. **Aumentare l'intervallo:** Heartbeat Interval = `300 s` (5 minuti) — rilevazione più lenta ma meno noise
3. **Disabilitare la notifica** per questo monitor specifico se i falsi positivi sono troppo frequenti

### Webhook HAOS non riceve le notifiche

```bash
# Verifica connettività da ct-101 verso HAOS
curl -v http://192.168.68.201:8123/api/webhook/uptimekuma-homesoc-alert \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"msg": "Test connettività da ct-101"}'
# Output atteso: HTTP 200

# Se la porta non è raggiungibile
ping -c 3 192.168.68.201
# Se il ping fallisce → vm-100 è down → risolvere prima il problema su vm-100
```

Se il curl restituisce `401 Unauthorized`, il webhook ID non corrisponde. Verificare il webhook ID configurato in HAOS (deve essere esattamente `uptimekuma-homesoc-alert`).

### Stack Docker non si avvia al reboot

```bash
# Verifica che il servizio systemd sia abilitato
systemctl is-enabled homesoc-monitoring.service

# Se disabled:
systemctl enable homesoc-monitoring.service

# Verifica che Docker si avvii prima del servizio
systemctl is-enabled docker
# Deve essere enabled

# Avvio manuale dello stack
cd /opt/homesoc/compose && docker compose up -d
```

### Disco pieno — volumi Docker

```bash
# Da ct-101 — verifica spazio disco
df -h /opt

# Verifica spazio usato dai volumi Docker
docker system df

# Pulizia immagini non usate (NON rimuove i volumi dati)
docker system prune -f

# Se il database di Uptime Kuma cresce troppo
# Backup + cancellazione dalla Web UI: Settings → Data Management
```

### Monitor in stato "Pending" per lungo tempo dopo la creazione

Uptime Kuma esegue il primo check entro il primo intervallo configurato. Se `Heartbeat Interval = 60 s`, il primo stato apparirà entro 60 secondi dalla creazione del monitor. Non è un errore.

```bash
# Verifica log Uptime Kuma per errori
docker logs uptime-kuma --tail=50
```

---

## Prossimi passi

Dopo aver completato e verificato questa checklist:

1. Commit su Git:
   ```bash
   git add runbooks/uptimekuma-deploy.md
   git commit -m "runbooks(uptimekuma): add Phase 2 deploy runbook v1.0"
   ```

2. Aggiornare `docs/Inventario_IP_Pulito.csv` con:
   - IP: `192.168.68.202`
   - MAC: *(valore letto da `pct exec 101 -- ip link show eth0 | grep link/ether`)*
   - Hostname: `ct-101-monitoring`
   - Servizi: `Uptime Kuma 3001/tcp`, `Portainer CE 9443/tcp`

3. **Fase 2 completata.** Tutti i runbook della Fase 2 sono stati eseguiti:
   - ✅ `runbooks/proxmox-setup.md` — SOC-01 operativo
   - ✅ `runbooks/homeassistant-deploy.md` — vm-100 HAOS
   - ✅ `runbooks/greenbone-deploy.md` — ct-102 scanner
   - ✅ `runbooks/uptimekuma-deploy.md` — ct-101 monitoring

4. **Commit di chiusura Fase 2:**
   ```bash
   git add -A
   git commit -m "phase2: complete — all 4 runbooks deployed and verified"
   git tag -a phase2-complete -m "HomeSOC Phase 2 — Deploy complete — Aprile 2026"
   git push origin main --tags
   ```

5. Procedere con la pianificazione della **Fase 3** → vedi `docs/02-architecture.md` sezione 5 per le VM/CT previste (Wazuh SIEM, TheHive, Cortex).

---

*File: `runbooks/uptimekuma-deploy.md` · v1.0 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
