# Runbook — Greenbone Community Edition Deploy (ct-102)
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `runbooks/greenbone-deploy.md`  
**Versione:** 1.1 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 2 — Deploy  
**Prerequisito:** `runbooks/proxmox-setup.md` completato — SOC-01 operativo, pool `phase2` creato

> **Scopo:** Creare e configurare `ct-102` su Proxmox VE come container LXC Debian 12, installare Greenbone Community Edition (GCE) via Docker Compose, eseguire la prima scan di vulnerabilità sulla rete LAN e sui target del negozio (UC-05). Al termine di questo runbook Greenbone deve essere operativo, raggiungibile via browser, con almeno una scan schedulata settimanale e il primo report generato.

**Changelog:**
- v1.0 — Aprile 2026 — Prima stesura
- v1.1 — Aprile 2026 — Fix post-deployment reale: template versioning dinamico, pool pre-creazione, disco 50 GB, nuovo nome file compose, patch GSA slim + localhost binding, rimozione comandi gvmd CLI deprecati, fix scan 0% (cap_add + redis socket volume)

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

# Verifica storage disponibile (ct-102 richiede 50 GB)
pvesm status
# local-lvm deve avere ≥ 50 GB liberi

# Verifica RAM disponibile (ct-102 richiede 4 GB)
free -h
# Deve essere disponibile almeno 4 GB oltre al consumo corrente

# Verifica che il pool phase2 esista
pvesh get /pools/phase2
# Se restituisce errore 404 → crearlo (vedi passo 1.4)
```

> ✅ **Checkpoint:** Se `pvesm status` mostra meno di 50 GB liberi su `local-lvm`, non procedere. I feed SCAP/CPE di Greenbone occupano molto più spazio rispetto alle versioni precedenti — con 32 GB il database crasha durante la sincronizzazione iniziale.

### 1.2 Specifiche ct-102

| Parametro | Valore |
|---|---|
| CT ID | `102` |
| Nome | `ct-102-greenbone` |
| OS | Debian 12 (bookworm) — template LXC |
| vCPU | 4 |
| RAM | 4 GB (4096 MB) — **no balloon** |
| Swap | 512 MB |
| Storage | **50 GB** su `local-lvm` |
| Network | `vmbr0` (LAN — 192.168.68.0/24) |
| IP target | `192.168.68.203` (DHCP reservation) |
| Container type | **Privilegiato** (richiesto per Docker inside LXC) |
| Features | `nesting=1`, `keyctl=1` (richiesti per Docker) |

> ⚠️ **IMPORTANTE — due requisiti critici:**
> 1. Il container **deve** essere **privilegiato** (`Unprivileged: No`). Senza questa impostazione Docker non funzionerà.
> 2. Il disco deve essere **50 GB** (non 32 GB). I dizionari CPE/SCAP scaricati durante la sync dei feed occupano oltre 35 GB.

### 1.3 Informazioni di rete

| Parametro | Valore |
|---|---|
| IP ct-102 | `192.168.68.203` (DHCP reservation) |
| Gateway | `192.168.68.1` (Deco BE65) |
| DNS | `192.168.68.1` |
| Porta GSA (Web UI) | `9392/tcp` |
| Accesso Web UI | `http://192.168.68.203:9392` |

### 1.4 Creazione pool phase2 (se non presente)

```bash
# Su SOC-01 — eseguire PRIMA di creare il container
pvesh create /pools -poolid phase2

# Verifica (se il pool esiste già restituisce errore ignorabile)
pvesh get /pools/phase2
```

### 1.5 Download template Debian 12

Il team Proxmox aggiorna frequentemente i template rimuovendo le versioni precedenti. Non hardcodare il numero di versione — cercare sempre quello disponibile al momento.

```bash
# Su SOC-01
pveam update

# Cerca la versione attualmente disponibile
pveam available | grep debian-12-standard
# Output esempio: system  debian-12-standard_12.12-1_amd64.tar.zst
# ← il numero di versione cambia nel tempo — usare quello che compare

# Scarica il template trovato (sostituire il numero di versione)
pveam download local debian-12-standard_12.12-1_amd64.tar.zst

# Verifica download
pveam list local | grep debian-12
```

### 1.6 Target di scan — asset inventario

| Asset | ID | IP | Priorità | Use Case |
|---|---|---|---|---|
| POS Negozio 1 | NEG-01 | `192.168.68.64` | Critica | UC-05 |
| POS Negozio 2 | NEG-02 | `192.168.68.67` | Critica | UC-05 |
| NAS WD My Cloud | NAS-01 | `192.168.68.90` | Alta | UC-04 |
| MacBook Pro | END-05 | `192.168.68.108` | Alta | UC-03 |
| LAN completa | — | `192.168.68.0/24` | Media | Baseline |

> 📌 I POS (NEG-01, NEG-02) sono stati identificati come dispositivi **PAX Computer** dall'inventario IP. Sono i target prioritari dell'UC-05.

---

## 2. Creazione CT su Proxmox

### 2.1 Creazione via CLI (metodo consigliato)

La CLI garantisce che tutti i parametri critici siano impostati correttamente.

```bash
# Su SOC-01
# Recupera il nome esatto del template scaricato
TEMPLATE=$(pveam list local | grep debian-12-standard | awk '{print $1}')
echo "Template: $TEMPLATE"

pct create 102 ${TEMPLATE} \
  --hostname ct-102-greenbone \
  --cores 4 \
  --memory 4096 \
  --swap 512 \
  --rootfs local-lvm:50 \
  --net0 name=eth0,bridge=vmbr0,firewall=1,ip=dhcp \
  --nameserver 192.168.68.1 \
  --searchdomain homesoc.lan \
  --pool phase2 \
  --unprivileged 0 \
  --features nesting=1,keyctl=1 \
  --onboot 1 \
  --password
# Il sistema chiede la password root del container interattivamente
```

> ⚠️ **CRITICO:** `--unprivileged 0` = container **privilegiato**. Se si omette o si usa `1`, Docker non funzionerà e sarà necessario ricreare il container da zero.

### 2.2 Verifica features e avvio

```bash
# Su SOC-01
pct config 102 | grep -E "features|unprivileged|cores|memory|rootfs"
# Output atteso:
# features: keyctl=1,nesting=1
# unprivileged: 0
# cores: 4
# memory: 4096
# rootfs: local-lvm:50

pct start 102
pct status 102

# Annota l'IP DHCP temporaneo assegnato
sleep 5
pct exec 102 -- ip addr show eth0 | grep inet
```

### 2.3 Alternativa — Creazione via Web UI

**Web UI Proxmox** → `soc-01` → **Create CT**

| Tab | Campo | Valore |
|---|---|---|
| General | CT ID | `102` |
| General | Hostname | `ct-102-greenbone` |
| General | Pool | `phase2` |
| General | **Unprivileged container** | ❌ **DESELEZIONARE** |
| Template | Template | `debian-12-standard_12.XX-1_amd64.tar.zst` |
| Disks | Disk size | **`50`** GiB |
| CPU | Cores | `4` |
| Memory | Memory | `4096` MiB / Swap `512` MiB |
| Network | Bridge | `vmbr0` / IPv4 `DHCP` |
| DNS | DNS servers | `192.168.68.1` |

Dopo la creazione, **non avviare** — aggiungere prima le features:

```bash
# Su SOC-01
pct set 102 --features nesting=1,keyctl=1
pct start 102
```

---

## 3. Configurazione base del container

Accedere al container:

```bash
# Su SOC-01 — metodo diretto
pct exec 102 -- bash

# Oppure SSH all'IP DHCP temporaneo letto al passo 2.2
ssh root@<IP-DHCP-ct-102>
```

> ℹ️ **Contesto terminale:** i comandi `pct exec`, `pct config`, `pct status` vanno eseguiti su **SOC-01**. I comandi seguenti vanno eseguiti **dentro ct-102**. Per leggere il MAC address dall'interno del container usare `ip link show eth0 | grep "link/ether"` — i comandi `pct` non esistono dentro l'LXC.

### 3.1 Aggiornamento sistema

```bash
# Dentro ct-102
apt update && apt full-upgrade -y

apt install -y \
  curl wget gnupg ca-certificates lsb-release \
  apt-transport-https software-properties-common \
  htop net-tools iputils-ping ncat jq unzip git cron rsync
```

### 3.2 Hostname e timezone

```bash
# Dentro ct-102
timedatectl set-timezone Europe/Rome

cat > /etc/hosts << 'EOF'
127.0.0.1       localhost
127.0.1.1       ct-102-greenbone.homesoc.lan ct-102-greenbone
192.168.68.203  ct-102-greenbone.homesoc.lan ct-102-greenbone
EOF

timedatectl status | grep "Time zone"
# Output atteso: Time zone: Europe/Rome (CET, +0100)
```

### 3.3 Struttura directory report

```bash
# Dentro ct-102
mkdir -p /opt/homesoc/lab-reports/greenbone/{pdf,xml,csv}
mkdir -p /opt/homesoc/scripts
mkdir -p /opt/homesoc/backups/greenbone-volumes
chmod 750 /opt/homesoc /opt/homesoc/lab-reports /opt/homesoc/lab-reports/greenbone
```

---

## 4. Installazione Docker Engine

### 4.1 Rimozione versioni precedenti

```bash
# Dentro ct-102
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
  apt remove -y $pkg 2>/dev/null || true
done
```

### 4.2 Repository ufficiale Docker

```bash
# Dentro ct-102
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg \
  -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### 4.3 Avvio e test

```bash
# Dentro ct-102
systemctl enable docker
systemctl start docker

docker run --rm hello-world
```

Output atteso: `Hello from Docker!`

> ⚠️ Se fallisce con errori namespace: il container non è privilegiato. Verificare su SOC-01 con `pct config 102 | grep unprivileged` — deve essere `0`.

### 4.4 Log rotation

```bash
# Dentro ct-102
cat > /etc/docker/daemon.json << 'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "storage-driver": "overlay2"
}
EOF
systemctl restart docker
```

---

## 5. Deploy Greenbone Community Edition

### 5.1 Download file docker-compose

```bash
# Dentro ct-102
mkdir -p /opt/greenbone && cd /opt/greenbone

# Il file ha cambiato nome rispetto alle versioni precedenti
curl -fO -L https://greenbone.github.io/docs/latest/_static/compose.yaml
mv compose.yaml docker-compose.yml

ls -lh docker-compose.yml
```

### 5.2 Patch obbligatorie — applicare prima del pull

Applicare le tre patch seguenti nell'ordine. Correggono problemi noti nella versione corrente del file ufficiale.

```bash
# Dentro ct-102
cd /opt/greenbone

# Patch 1: sostituisce gsa:stable-slim (immagine non pubblicata) con gsa:stable
sed -i 's/gsa:stable-slim/gsa:stable/g' docker-compose.yml

# Patch 2: rimuove il binding 127.0.0.1 che blocca l'accesso dalla LAN
sed -i 's/127.0.0.1://g' docker-compose.yml

# Patch 3: fix scan bloccata a 0%
# Rimuove network_mode: host (incompatibile con la comunicazione Redis via bridge)
sed -i '/network_mode: "host"/d' docker-compose.yml

# Aggiunge cap_add per raw packet al servizio openvas
sed -i '/^  openvas:/{n; /image:/a\    cap_add:\n      - NET_RAW\n      - NET_ADMIN
}' docker-compose.yml

# Monta il socket Redis nel servizio openvas
sed -i '/^  openvas:/,/^  [a-z]/{
  /openvas_log_data_vol:\/var\/log\/openvas/a\      - redis_socket_vol:/run/redis
}' docker-compose.yml

# Verifica patch 1 e 2
grep -E "slim|127\.0\.0\.1" docker-compose.yml
# Output atteso: nessuna riga (patch applicate)

# Verifica patch 3 — blocco openvas risultante
grep -A 10 "^  openvas:" docker-compose.yml | grep -E "cap_add|NET_RAW|redis_socket"
# Output atteso:
#     cap_add:
#       - NET_RAW
#       - NET_ADMIN
#       - redis_socket_vol:/run/redis
```

> ℹ️ **Perché la patch 3:** il container `openvas` comunica con Redis tramite socket Unix. Senza il volume `redis_socket_vol:/run/redis` montato, lo scanner non riesce a passare la lista degli host alla coda di scan, producendo l'errore `attack_network: got NULL host` e la scan rimane bloccata allo 0% nonostante gli host vengano trovati correttamente.

### 5.3 Configurazione variabili d'ambiente

```bash
# Dentro ct-102
cat > /opt/greenbone/.env << 'EOF'
GVMD_ADMIN_PASSWORD=CAMBIA_QUESTA_PASSWORD
GSA_PORT=9392
TZ=Europe/Rome
EOF

# Modificare la password con una robusta (≥16 caratteri)
nano /opt/greenbone/.env
```

> 🔒 Usare un gestore password per generare e salvare questa credenziale.

### 5.4 Pull immagini Docker

```bash
# Dentro ct-102
cd /opt/greenbone
docker compose -f docker-compose.yml pull
```

> ⏱️ Il pull richiede **10-20 minuti** (~3-5 GB totali). Lasciare completare senza interrompere.

### 5.5 Avvio stack

```bash
# Dentro ct-102
cd /opt/greenbone
docker compose -f docker-compose.yml up -d
sleep 30
docker compose -f docker-compose.yml ps
```

I container principali devono essere `Up`. Alcuni (es. `configure-openvas`, `gpg-data`, `gvm-config`, `pg-gvm-migrator`) mostrano `Exited (0)` — è normale: sono container one-shot di inizializzazione.

> ℹ️ I nomi dei container seguono il formato `greenbone-community-edition-<servizio>-1`. Il servizio Redis si chiama `redis-server` (non `redis`).

### 5.6 Attesa sincronizzazione feed NVT

Al primo avvio Greenbone scarica e processa i feed NVT. Questo richiede **45-90 minuti**.

```bash
# Dentro ct-102 — monitora (Ctrl+C per uscire)
docker compose -f /opt/greenbone/docker-compose.yml logs -f openvas ospd-openvas
```

> ⚠️ **Importante:** I comandi CLI `gvmd --get-feeds`, `--rebuild-scap`, `--rebuild-cert` sono stati **rimossi** nelle versioni recenti di GCE e restituiscono `Unknown option`. L'unico modo affidabile per verificare lo stato dei feed è la **Web UI → Administration → Feed Status**. Non avviare scan finché tutti i feed non mostrano il badge verde **Current**.

### 5.7 Servizio systemd per avvio automatico

```bash
# Dentro ct-102
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
systemctl is-enabled greenbone-community.service
# Output atteso: enabled
```

---

## 6. Configurazione iniziale GSA

### 6.1 DHCP reservation e IP fisso

```bash
# Dentro ct-102 — leggi il MAC address
ip link show eth0 | grep "link/ether"
# Output: link/ether AA:BB:CC:DD:EE:FF brd ff:ff:ff:ff:ff:ff
# ← annotare il MAC
```

Creare la DHCP reservation sul Deco BE65 (app TP-Link Deco → Avanzate → LAN → Prenotazione DHCP):
- MAC: `AA:BB:CC:DD:EE:FF`
- IP: `192.168.68.203`

```bash
# Dentro ct-102 — applica il nuovo IP
systemctl restart networking
ip addr show eth0 | grep inet
# Deve mostrare 192.168.68.203
```

### 6.2 Verifica porta e primo accesso

```bash
# Su SOC-01
nc -zv 192.168.68.203 9392 && echo "PORTA APERTA" || echo "PORTA CHIUSA"
```

Da browser sul MacBook: `http://192.168.68.203:9392`

Credenziali: username `admin`, password impostata nel `.env`.

### 6.3 Verifica stato feed

**Web UI:** `Administration` → `Feed Status`

Tutti i feed devono essere **Current** (verde) prima di procedere con le scan:
- NVT, CERT-Bund, DFN-CERT, SCAP Data

---

## 7. Configurazione target e scan policy

### 7.1 Target — UC-05 POS Negozio

**Web UI:** `Configuration` → `Targets` → `+ New Target`

| Campo | Valore |
|---|---|
| Name | `UC-05 — POS Negozio (NEG-01, NEG-02)` |
| Hosts | `192.168.68.64,192.168.68.67` |
| Port list | `All IANA assigned TCP and UDP` |
| **Alive test** | **`Consider Alive`** |
| Credentials | *(lasciare vuoto — scan non autenticata)* |
| Comment | `PAX Computer POS — UC-05 CVSS ≥ 7.0` |

> ⚠️ **`Consider Alive` è obbligatorio per target con host espliciti.** Con altri metodi (ICMP, TCP-ACK, ARP) il container Docker non riesce ad eseguire i test di raggiungibilità a basso livello e la scan rimane bloccata allo 0%. Per le scan su subnet `/24` (LAN Baseline) il metodo ICMP funziona correttamente — il problema si manifesta solo con liste di host espliciti.

### 7.2 Target — LAN completa

| Campo | Valore |
|---|---|
| Name | `HomeSOC LAN — Baseline Scan` |
| Hosts | `192.168.68.0/24` |
| Exclude hosts | `192.168.68.203` |
| Port list | `All IANA assigned TCP` |
| Alive test | `ICMP, TCP-ACK Service & ARP Ping` |

### 7.3 Target — Asset critici

| Campo | Valore |
|---|---|
| Name | `HomeSOC Asset Critici` |
| Hosts | `192.168.68.90,192.168.68.108,192.168.68.200` |
| Port list | `All IANA assigned TCP and UDP` |
| Alive test | `Consider Alive` |

---

## 8. Prima scan — UC-05 Negozio e LAN completa

### 8.1 Crea task UC-05

**Web UI:** `Scans` → `Tasks` → `+ New Task`

| Campo | Valore |
|---|---|
| Name | `UC-05 — Vulnerability Scan POS Negozio` |
| Scan Targets | `UC-05 — POS Negozio (NEG-01, NEG-02)` |
| Scanner | `OpenVAS Default` |
| Scan Config | `Full and fast` |
| Comment | `ATT&CK T1190 — CVSS ≥ 7.0 → TheHive (Fase 4)` |

### 8.2 Crea task LAN Baseline

| Campo | Valore |
|---|---|
| Name | `HomeSOC LAN Baseline Scan` |
| Scan Targets | `HomeSOC LAN — Baseline Scan` |
| Scanner | `OpenVAS Default` |
| Scan Config | `Full and fast` |

### 8.3 Avvio e monitoraggio

**Web UI:** `Scans` → `Tasks` → task desiderato → click **▶ Start**

```bash
# Dentro ct-102 — monitora la scan in corso
docker compose -f /opt/greenbone/docker-compose.yml logs -f openvas ospd-openvas 2>&1 | grep -v DEBUG
```

Indicatori che la scan sta girando correttamente:
```
Vulnerability scan ... started: Target has 2 hosts: 192.168.68.64, 192.168.68.67
Vulnerability scan ... started for host: 192.168.68.67
Vulnerability scan ... started for host: 192.168.68.64
```

> ℹ️ La percentuale nella Web UI può rimanere a 0% per diversi minuti anche con la scan in corso — OpenVAS aggiorna il progresso solo quando arrivano i primi risultati dai NVT, non durante il port scan iniziale. Verificare i log per confermare che lo scanner stia lavorando.

> ⏱️ Durata attesa: **15-45 minuti** per 2 host (Full and fast). La LAN Baseline su /24 richiede **2-4 ore**.

### 8.4 Download report

Al completamento (status **Done**):

**Web UI:** `Scans` → `Reports` → click sul report → icona **↓** → scegliere formato

Il file si scarica direttamente sul MacBook tramite il browser — nessun `rsync` necessario.

Salvare:
- `lab-reports/greenbone/UC-05_negozio_YYYYMMDD.pdf`
- `lab-reports/greenbone/UC-05_negozio_YYYYMMDD.xml` (per import TheHive Fase 4)
- `lab-reports/greenbone/baseline_LAN_YYYYMMDD.pdf`

---

## 9. Schedulazione scansioni settimanali

### 9.1 Schedule UC-05 domenicale

**Web UI:** `Configuration` → `Schedules` → `+ New Schedule`

| Campo | Valore |
|---|---|
| Name | `UC-05 Weekly Sunday 02:00` |
| Timezone | `Europe/Rome` |
| First Time | Prossima domenica, 02:00 |
| Period | `1 week` |
| Duration | `4 hours` |

Associare: `Scans` → `Tasks` → `UC-05` → **Edit** → Schedule: `UC-05 Weekly Sunday 02:00`

### 9.2 Schedule baseline mensile

| Campo | Valore |
|---|---|
| Name | `LAN Baseline Monthly 03:00` |
| Timezone | `Europe/Rome` |
| First Time | Primo del mese prossimo, 03:00 |
| Period | `1 month` |
| Duration | `8 hours` |

---

## 10. Esportazione report e integrazione SOC

### 10.1 Struttura report nel repository

```
homesoc-project/
└── lab-reports/
    └── greenbone/
        ├── UC-05_negozio_YYYYMMDD.pdf
        ├── UC-05_negozio_YYYYMMDD.xml
        └── baseline_LAN_YYYYMMDD.pdf
```

```bash
# Dal MacBook
cd ~/homesoc-project
git add lab-reports/greenbone/
git commit -m "lab-reports(greenbone): baseline LAN e UC-05 first scan $(date +%Y%m%d)"
```

### 10.2 Integrazione futura (Fase 3-4)

**Fase 3 — Wazuh:** script Python che legge il report XML e genera alert per ogni finding CVSS ≥ 7.0 → regola Wazuh custom (Rule ID 100050+).

**Fase 4 — TheHive:** ogni finding CVSS ≥ 7.0 su NEG-01/NEG-02 crea automaticamente un caso TheHive tramite Cortex analyzer `GreenBone_Vuln`.

---

## 11. Backup snapshot

### 11.1 Snapshot Proxmox

```bash
# Su SOC-01
pct snapshot 102 "greenbone-configured" \
  --description "GCE configurato — feed sync — target UC-05 pronti — Aprile 2026"

pct listsnapshot 102
```

### 11.2 Verifica inclusione backup vzdump

```bash
# Su SOC-01
cat /etc/pve/jobs.cfg | grep -A 20 "vzdump"
```

Se ct-102 non è inclusa: **Web UI Proxmox** → `Datacenter` → `Backup` → job esistente → **Edit** → aggiungere ct-102.

---

## 12. Verifica finale e checklist

### 12.1 Checklist di completamento

**Container Proxmox:**
- [ ] CT `ct-102-greenbone` creata con ID 102
- [ ] Container **privilegiato** — `pct config 102 | grep unprivileged` → `0`
- [ ] Features `nesting=1,keyctl=1` — `pct config 102 | grep features`
- [ ] 4 vCPU, 4096 MB RAM, **50 GB** disco — `pct config 102 | grep rootfs`
- [ ] CT nel pool `phase2`, `onboot: 1`

**Rete:**
- [ ] MAC address ct-102 annotato in `Inventario_IP_Pulito.csv`
- [ ] DHCP reservation `192.168.68.203` creata su Deco BE65
- [ ] `ping 192.168.68.203` → OK da SOC-01
- [ ] Web UI GSA raggiungibile su `http://192.168.68.203:9392`

**Docker e Greenbone:**
- [ ] `docker run hello-world` → OK
- [ ] Patch compose applicate (GSA slim, localhost, cap_add, redis socket)
- [ ] Tutti i container principali GCE in stato `Up`
- [ ] Feed tutti **Current** (Web UI → Administration → Feed Status)
- [ ] Servizio `greenbone-community.service` abilitato all'avvio

**Target e scan:**
- [ ] Target UC-05 con `Alive Test: Consider Alive`
- [ ] Target LAN Baseline configurato
- [ ] Prima scan UC-05 completata — report disponibile
- [ ] Prima scan LAN Baseline completata — report disponibile
- [ ] Report PDF e XML scaricati e committati su Git

**Schedulazione:**
- [ ] Schedule domenicale 02:00 associata al task UC-05
- [ ] Schedule mensile 03:00 associata al task LAN Baseline

**Backup:**
- [ ] Snapshot `greenbone-configured` creato
- [ ] ct-102 inclusa nel job vzdump schedulato

### 12.2 Comandi diagnostici di riepilogo

```bash
# Su SOC-01
echo "=== CT Status ===" && pct status 102
echo "=== CT Config ===" && pct config 102 | grep -E "features|unprivileged|cores|memory|rootfs"
echo "=== Ping ===" && ping -c 2 192.168.68.203 | tail -1
echo "=== Port 9392 ===" && nc -zv 192.168.68.203 9392 2>&1 | grep -o "succeeded\|refused"
echo "=== Snapshots ===" && pct listsnapshot 102

# Dentro ct-102
echo "=== Docker ===" && docker info --format '{{.ServerVersion}}'
echo "=== GCE Up ===" && docker compose -f /opt/greenbone/docker-compose.yml ps \
  --format "table {{.Name}}\t{{.Status}}" | grep "Up"
echo "=== Patch check ===" && grep -c "NET_RAW\|redis_socket" /opt/greenbone/docker-compose.yml
echo "=== Disk ===" && df -h / | tail -1
```

---

## 13. Troubleshooting

### Docker non si avvia — errori namespace o permission denied

**Causa:** container non privilegiato o features mancanti.

```bash
# Su SOC-01
pct config 102 | grep -E "unprivileged|features"
# unprivileged deve essere 0, features deve contenere nesting=1,keyctl=1

# Features mancanti (correggibile a container spento)
pct stop 102
pct set 102 --features nesting=1,keyctl=1
pct start 102

# Se unprivileged è 1 → ricreare il container (non correggibile a caldo)
```

### Errore 400 "no such template" durante pct create

**Causa:** la versione del template è stata rimossa da Proxmox.

```bash
# Su SOC-01
pveam update
pveam available | grep debian-12-standard
# Usare il nome esatto che compare nell'output
```

### Errore 403 "pool does not exist" durante pct create

```bash
# Su SOC-01
pvesh create /pools -poolid phase2
# poi ripetere pct create
```

### Errore 404 durante il download del docker-compose

**Causa:** il file ha cambiato nome nelle versioni recenti.

```bash
# Dentro ct-102
curl -fO -L https://greenbone.github.io/docs/latest/_static/compose.yaml
mv compose.yaml docker-compose.yml
```

### Disco pieno durante la sincronizzazione feed (crash gvmd)

**Causa:** 32 GB non sono sufficienti per i feed SCAP/CPE attuali.

```bash
# Su SOC-01
pct stop 102
pct resize 102 rootfs +18G
pct start 102

# Dentro ct-102 — verifica nuovo spazio
df -h /
```

### Web UI non raggiungibile — Connection refused su porta 9392

**Causa probabile:** patch del binding `127.0.0.1` non applicata.

```bash
# Dentro ct-102
grep "127.0.0.1" /opt/greenbone/docker-compose.yml
# Se trova righe → applicare la patch:
sed -i 's/127.0.0.1://g' /opt/greenbone/docker-compose.yml
docker compose -f /opt/greenbone/docker-compose.yml up -d --force-recreate
```

### Scan bloccata a 0% — errore "got NULL host" nei log

**Causa:** patch al blocco `openvas` non applicate.

```bash
# Dentro ct-102 — verifica che le patch siano presenti
grep -E "NET_RAW|redis_socket_vol" /opt/greenbone/docker-compose.yml
# Deve trovare almeno 2 righe

# Se mancano → applicare le patch del passo 5.2 e ricreare il container openvas
docker compose -f /opt/greenbone/docker-compose.yml up -d --force-recreate openvas
```

Se le patch sono presenti ma la scan è ancora bloccata, il task ha probabilmente uno stato corrotto da tentativi precedenti falliti. Soluzione: dalla Web UI eliminare il task e ricrearlo da zero con gli stessi parametri — il problema non si ripresenta su task nuovi.

### Feed Status mostra "Outdated" o "Update in progress"

```bash
# Dentro ct-102 — monitora i log e attendi
docker compose -f /opt/greenbone/docker-compose.yml logs -f openvas ospd-openvas

# Attendere 45-90 minuti al primo avvio
# NON usare gvmd --get-feeds o --rebuild-scap: rimossi nelle versioni recenti
# Unico indicatore affidabile: Web UI → Administration → Feed Status
```

### Comandi pct / pveam "command not found" dentro ct-102

**Causa:** questi comandi esistono solo su SOC-01, non dentro il container LXC.

```bash
# Per leggere il MAC dall'interno del container:
ip link show eth0 | grep "link/ether"

# Per riavviare la rete dall'interno del container:
systemctl restart networking
```

### Container GCE in Restarting o Exit (codice non zero)

```bash
# Dentro ct-102
docker compose -f /opt/greenbone/docker-compose.yml logs <nome-servizio>

# RAM insufficiente → aumentare da SOC-01
pct set 102 --memory 6144

# Disco pieno → vedi sezione dedicata sopra

# ⚠️ Solo in caso estremo — ricrea volumi (perde i report esistenti)
docker compose -f /opt/greenbone/docker-compose.yml down -v
docker compose -f /opt/greenbone/docker-compose.yml up -d
```

---

## Prossimi passi

Dopo aver completato e verificato questa checklist:

1. Commit su Git:
   ```bash
   git add runbooks/greenbone-deploy.md
   git commit -m "runbooks(greenbone): Phase 2 deploy runbook v1.1 — post-deployment fixes"
   ```

2. Aggiornare `docs/Inventario_IP_Pulito.csv`:
   - IP: `192.168.68.203`
   - MAC: *(letto con `ip link show eth0 | grep link/ether` dentro ct-102)*
   - Hostname: `ct-102-greenbone`
   - Servizio: `Greenbone GCE 9392/tcp`

3. Committare i report della prima scan:
   ```bash
   git add lab-reports/greenbone/
   git commit -m "lab-reports(greenbone): baseline LAN e UC-05 first scan $(date +%Y%m%d)"
   ```

4. Procedere con il runbook successivo: **`runbooks/uptimekuma-deploy.md`**
   - Crea ct-101 (2 vCPU, 1 GB RAM, 16 GB, vmbr0)
   - Installa Uptime Kuma + Portainer
   - Configura probe su tutti gli asset incluso ct-102 (`http://192.168.68.203:9392`)
   - Configura webhook verso HAOS (`192.168.68.201:8123/api/webhook/uptimekuma-homesoc-alert`)

---

*File: `runbooks/greenbone-deploy.md` · v1.1 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
