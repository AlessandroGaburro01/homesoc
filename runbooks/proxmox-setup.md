# Runbook — Proxmox VE Setup
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `runbooks/proxmox-setup.md`  
**Versione:** 1.0 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** 2 — Deploy  
**Prerequisito:** Fase 1 completata — `docs/02-architecture.md` approvata

> **Scopo:** Installare e configurare Proxmox VE sul nodo SOC-01 (GMKtec M5 Ultra), configurare rete, storage e hardening base. Al termine di questo runbook il nodo deve essere pronto ad ospitare le VM/CT di Fase 2 (`vm-100`, `ct-101`, `ct-102`).

---

## Indice

1. [Prerequisiti](#1-prerequisiti)
2. [Creazione USB di installazione](#2-creazione-usb-di-installazione)
3. [Installazione Proxmox VE](#3-installazione-proxmox-ve)
4. [Configurazione di rete post-install](#4-configurazione-di-rete-post-install)
5. [Configurazione storage](#5-configurazione-storage)
6. [Aggiornamento sistema e repo](#6-aggiornamento-sistema-e-repo)
7. [Hardening SSH](#7-hardening-ssh)
8. [Creazione pool risorse e tag VM](#8-creazione-pool-risorse-e-tag-vm)
9. [Snapshot automatici (Proxmox Backup tramite vzdump)](#9-snapshot-automatici-proxmox-backup-tramite-vzdump)
10. [Tailscale — accesso remoto sicuro](#10-tailscale--accesso-remoto-sicuro)
11. [Verifica finale e checklist](#11-verifica-finale-e-checklist)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Prerequisiti

### 1.1 Hardware richiesto

| Componente | Spec | Note |
|---|---|---|
| Device | GMKtec M5 Ultra | SOC-01 |
| CPU | AMD Ryzen 7 7730U (8C/16T) | VT-x/AMD-V abilitato nel BIOS |
| RAM | 16 GB DDR4 (→ 32 GB upgrade pianificato) | |
| Storage | NVMe interno (≥256 GB) | Target per Proxmox OS + LVM |
| NIC | 2× NIC 2.5GbE | NIC1 → LAN, NIC2 → lab isolato (vmbr1) |
| USB | Chiavetta ≥4 GB | Per USB bootable installer |
| Rete | Switch Nighthawk S8000, porta Ethernet disponibile | |

### 1.2 Informazioni di rete da avere prima di iniziare

| Parametro | Valore |
|---|---|
| IP SOC-01 | `192.168.68.200` (DHCP reservation) |
| Gateway | `192.168.68.1` (Deco BE65) |
| Subnet mask | `255.255.255.0` (/24) |
| DNS | `192.168.68.1` (o NextDNS DoH) |
| MAC NIC1 (da annotare dopo accensione) | `TBD — leggere da BIOS / ip link` |

> ⚠️ Prima di procedere: collegare NIC1 allo switch Nighthawk S8000, creare la DHCP reservation su Deco BE65 (Admin > LAN > DHCP Reservation) con il MAC address letto al passo 3.3.

### 1.3 Software richiesto (sulla macchina admin — MacBook)

- `balenaEtcher` o `dd` — per creare la USB
- Browser moderno — per accedere alla Web UI di Proxmox
- Client SSH — `ssh` (preinstallato su macOS)

---

## 2. Creazione USB di installazione

### 2.1 Download ISO Proxmox VE

```bash
# Sul MacBook — scarica l'ISO ufficiale
# Verifica la versione più recente su https://www.proxmox.com/en/downloads
curl -O https://enterprise.proxmox.com/iso/proxmox-ve_8.x-1.iso

# Verifica SHA256 (confronta con il valore pubblicato sul sito Proxmox)
shasum -a 256 proxmox-ve_8.x-1.iso
```

> ✅ **Checkpoint:** l'hash SHA256 deve corrispondere a quello indicato sulla pagina di download ufficiale. Non procedere se non corrisponde.

### 2.2 Flash USB con balenaEtcher

1. Aprire **balenaEtcher**
2. Selezionare l'ISO scaricata
3. Selezionare la chiavetta USB (verificare bene il device — l'operazione è distruttiva)
4. Click **Flash!** — attendere completamento

Alternativa via terminale (`dd`):
```bash
# ATTENZIONE: sostituire /dev/diskN con il device corretto
# Verificare con: diskutil list
diskutil unmountDisk /dev/diskN
sudo dd if=proxmox-ve_8.x-1.iso of=/dev/rdiskN bs=4m status=progress
```

---

## 3. Installazione Proxmox VE

### 3.1 Boot da USB

1. Collegare la chiavetta USB al GMKtec M5 Ultra
2. Accendere il device e premere **F7** (o Del/F2 a seconda del BIOS) per entrare nel boot menu
3. Selezionare la chiavetta USB come primo dispositivo di boot
4. Alla schermata di boot Proxmox selezionare: **Install Proxmox VE (Graphical)**

### 3.2 BIOS — verifiche preliminari

Prima dell'installazione, entrare nel BIOS (Del o F2) e verificare:

| Setting | Valore richiesto |
|---|---|
| Virtualization Technology (AMD-V / SVM) | **Enabled** |
| IOMMU | **Enabled** (per PCIe passthrough futuro) |
| Secure Boot | **Disabled** |
| Fast Boot | **Disabled** |
| Boot Mode | **UEFI** |

### 3.3 Procedura di installazione guidata

**Schermata "Target Harddisk":**
- Selezionare il disco NVMe interno
- File system: **ext4** (opzione base stabile; ZFS opzionale — vedi sezione 5.3)
- Lasciare le dimensioni di default (Proxmox gestirà LVM automaticamente)

**Schermata "Location and Time Zone":**
- Country: `Italy`
- Timezone: `Europe/Rome`
- Keyboard Layout: `Italian`

**Schermata "Administration Password":**
- Impostare una password root complessa (≥16 caratteri, alfanumerica + simboli)
- Email: inserire un indirizzo valido per le notifiche di sistema

**Schermata "Network Configuration":**

| Campo | Valore |
|---|---|
| Management Interface | Selezionare NIC1 (2.5GbE — quella collegata allo switch) |
| Hostname (FQDN) | `soc-01.homesoc.lan` |
| IP Address | `192.168.68.200/24` |
| Gateway | `192.168.68.1` |
| DNS Server | `192.168.68.1` |

> 📌 **Annotare il MAC address di NIC1** che appare in questa schermata — servirà per la DHCP reservation sul Deco BE65.

**Schermata di riepilogo:** rivedere tutte le impostazioni, poi click **Install**.

L'installazione richiede circa 5–10 minuti. Al termine il sistema si riavvia automaticamente — rimuovere la chiavetta USB quando richiesto.

### 3.4 Primo accesso Web UI

Da browser sul MacBook:
```
https://192.168.68.200:8006
```

> ⚠️ Il browser mostrerà un avviso certificato self-signed — accettare l'eccezione (è normale per installazione fresh).

Credenziali login:
- Username: `root`
- Realm: `Linux PAM standard authentication`
- Password: quella impostata durante l'installazione

---

## 4. Configurazione di rete post-install

### 4.1 Verifica interfacce fisiche

Da terminale SSH (o dalla console Web UI: node → Shell):

```bash
# Visualizza le interfacce disponibili
ip link show

# Output atteso: due interfacce oltre a lo
# es. enp2s0 (NIC1 — collegata LAN) e enp3s0 (NIC2 — libera)
# I nomi esatti dipendono dall'hardware — annotarli
```

### 4.2 Configurazione bridge vmbr0 (LAN — produzione)

Editare `/etc/network/interfaces`:

```bash
nano /etc/network/interfaces
```

Configurazione completa:

```
auto lo
iface lo inet loopback

# NIC fisica 1 — 2.5GbE — uplink vmbr0
auto enp2s0
iface enp2s0 inet manual

# Bridge LAN — produzione (tutte le VM Fase 2-5)
auto vmbr0
iface vmbr0 inet static
    address 192.168.68.200/24
    gateway 192.168.68.1
    bridge-ports enp2s0
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware no
# vmbr0 — LAN principale — vm-100, ct-101, ct-102, vm-103, vm-104, vm-105

# NIC fisica 2 — 2.5GbE — uplink vmbr1 (NON collegata fisicamente alla LAN)
auto enp3s0
iface enp3s0 inet manual

# Bridge Lab offensivo — isolato (Fase 6 — Caldera, Infection Monkey)
auto vmbr1
iface vmbr1 inet static
    address 10.99.0.1/24
    bridge-ports enp3s0
    bridge-stp off
    bridge-fd 0
# vmbr1 — LAB ISOLATO — NESSUN UPLINK FISICO ALLA LAN
# enp3s0 fisicamente NON collegata allo switch Nighthawk
```

> ⚠️ **IMPORTANTE:** `vmbr1` deve rimanere fisicamente isolata dalla LAN di casa. La NIC2 (enp3s0) non va mai collegata allo switch. Questo garantisce che le VM del lab offensivo (Fase 6) non possano raggiungere dispositivi reali.

Applicare le modifiche:
```bash
systemctl restart networking
# oppure (più sicuro da remoto):
ifreload -a
```

> ✅ **Checkpoint:** Verificare che la connessione SSH non cada dopo `ifreload -a`. Se si perde la connessione, accedere fisicamente alla macchina.

### 4.3 Verifica connettività

```bash
# Ping gateway
ping -c 4 192.168.68.1

# Ping DNS esterno
ping -c 4 1.1.1.1

# Verifica routing
ip route show
```

Output atteso `ip route show`:
```
default via 192.168.68.1 dev vmbr0 proto static onlink
192.168.68.0/24 dev vmbr0 proto kernel scope link src 192.168.68.200
10.99.0.0/24 dev vmbr1 proto kernel scope link src 10.99.0.1
```

---

## 5. Configurazione storage

### 5.1 Verifica layout LVM post-installazione

```bash
# Visualizza volume group e logical volumes
vgdisplay
lvdisplay

# Visualizza storage da Proxmox CLI
pvesm status
```

Output atteso `pvesm status`:
```
Name          Type     Status  Total   Used  Available  %
local         dir      active  xxxGB   xGB    xxxGB    x%
local-lvm     lvmthin  active  xxxGB   0GB    xxxGB    0%
```

### 5.2 Pool storage Proxmox — layout target

| Pool | Tipo | Dimensione | Contenuto |
|---|---|---|---|
| `local-lvm` | LVM-thin | ~200 GB | Dischi VM/CT OS |
| `local` | dir | ~32 GB | ISO, template CT, backup vzdump |

### 5.3 Download template LXC (per ct-101 e ct-102)

Dalla Web UI: **Node → local → CT Templates → Templates**

Scaricare:
- `debian-12-standard` (Bookworm) — per ct-101 (Uptime Kuma/Portainer)
- `debian-12-standard` (Bookworm) — per ct-102 (Greenbone)

Oppure da CLI:
```bash
pveam update
pveam available | grep debian-12
pveam download local debian-12-standard_12.x-1_amd64.tar.zst
```

### 5.4 Upload ISO Home Assistant

Scaricare da: https://www.home-assistant.io/installation/alternative/#proxmox-ve

```bash
# Sul MacBook — scarica l'immagine HAOS per Proxmox (formato qcow2)
# Cerca "KVM/Proxmox" nella pagina di download Home Assistant OS
# Poi caricarla via Web UI: Node → local → ISO Images → Upload
```

---

## 6. Aggiornamento sistema e repo

### 6.1 Disabilitare repository enterprise (senza abbonamento)

```bash
# Disabilita repo enterprise (richiede licenza a pagamento)
sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/pve-enterprise.list

# Disabilita repo Ceph enterprise (non usato)
sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/ceph.list

# Aggiunge repo community (free, no-subscription)
echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" \
  > /etc/apt/sources.list.d/pve-no-subscription.list
```

### 6.2 Aggiornamento sistema

```bash
apt update && apt full-upgrade -y
```

> ⚠️ Se durante l'upgrade viene proposto di aggiornare il kernel, confermare. Riavviare il sistema dopo il kernel upgrade:

```bash
reboot
```

Dopo il riavvio, verificare la versione Proxmox:
```bash
pveversion
# Output atteso: pve-manager/8.x.x/...
```

### 6.3 Installa utilità di sistema

```bash
apt install -y \
  curl wget vim htop iotop \
  net-tools nmap tcpdump \
  fail2ban \
  unattended-upgrades \
  apt-listchanges
```

### 6.4 Configura aggiornamenti automatici di sicurezza

```bash
# Abilita aggiornamenti non presidiati (solo security)
dpkg-reconfigure --priority=low unattended-upgrades
```

Editare `/etc/apt/apt.conf.d/50unattended-upgrades` e verificare:
```
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "root";
```

---

## 7. Hardening SSH

### 7.1 Generazione coppia di chiavi SSH (sul MacBook)

```bash
# Sul MacBook — genera chiave ED25519 dedicata al progetto HomeSOC
ssh-keygen -t ed25519 -C "homesoc-admin-$(date +%Y%m)" \
  -f ~/.ssh/id_homesoc_ed25519

# Visualizza la chiave pubblica da copiare sul server
cat ~/.ssh/id_homesoc_ed25519.pub
```

### 7.2 Autorizzare la chiave pubblica su SOC-01

```bash
# Sul server SOC-01 (come root)
mkdir -p /root/.ssh
chmod 700 /root/.ssh

# Incollare il contenuto della chiave pubblica
echo "ssh-ed25519 AAAA...tua-chiave-pubblica... homesoc-admin-YYYYMM" \
  >> /root/.ssh/authorized_keys

chmod 600 /root/.ssh/authorized_keys
```

### 7.3 Hardening configurazione SSH

```bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
```

Editare `/etc/ssh/sshd_config`:

```bash
# Porta non-standard (riduce rumore nei log da scanner automatici)
Port 2222

# Solo IPv4 (non usiamo IPv6 in questa fase)
AddressFamily inet

# Autenticazione
PermitRootLogin prohibit-password        # root solo con chiave
PasswordAuthentication no                 # disabilita autenticazione password
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Sicurezza protocollo
Protocol 2
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 3

# Algoritmi crittografici (sicuri — compatibili OpenSSH 8+)
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com

# Funzionalità non necessarie — disabilitate
X11Forwarding no
AllowTcpForwarding no
GatewayPorts no
PermitEmptyPasswords no
IgnoreRhosts yes
HostbasedAuthentication no

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Banner
Banner /etc/ssh/banner.txt
```

Creare banner di avviso:
```bash
cat > /etc/ssh/banner.txt << 'EOF'
*****************************************************
*  HomeSOC — SOC-01 — Accesso autorizzato only     *
*  Ogni accesso è registrato e monitorato           *
*****************************************************
EOF
```

Riavviare SSH e verificare:
```bash
systemctl restart sshd

# Verifica che il servizio sia attivo
systemctl status sshd

# Test connessione con nuova chiave (aprire NUOVO terminale — non chiudere la sessione attuale!)
# Sul MacBook — in un nuovo terminale:
# ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200
```

> ⚠️ **CRITICO:** Verificare il login con chiave prima di chiudere la sessione corrente. Se si chiude la sessione prima di aver verificato il nuovo accesso e c'è un errore nella configurazione SSH, si potrebbe perdere l'accesso remoto al server.

### 7.4 Aggiornare ~/.ssh/config sul MacBook

```
# ~/.ssh/config sul MacBook
Host soc-01
    HostName 192.168.68.200
    User root
    Port 2222
    IdentityFile ~/.ssh/id_homesoc_ed25519
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

Da questo momento: `ssh soc-01`

### 7.5 Configura fail2ban per SSH

```bash
cat > /etc/fail2ban/jail.d/sshd.conf << 'EOF'
[sshd]
enabled  = true
port     = 2222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600
findtime = 600
ignoreip = 127.0.0.1/8 192.168.68.0/24
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# Verifica stato
fail2ban-client status sshd
```

---

## 8. Creazione pool risorse e tag VM

### 8.1 Crea pool "phase2" nella Web UI

**Web UI:** Datacenter → Pools → Create

| Campo | Valore |
|---|---|
| Pool ID | `phase2` |
| Comment | `HomeSOC Fase 2 — vm-100, ct-101, ct-102` |

### 8.2 Pre-configurazione VM/CT Fase 2

Di seguito le specifiche per la creazione delle VM/CT (la creazione dettagliata è nei runbook dedicati). Questo passo verifica che le risorse siano disponibili.

```bash
# Verifica RAM disponibile
free -h

# Verifica spazio storage
pvesm status

# Verifica CPU
nproc && cat /proc/cpuinfo | grep "model name" | head -1
```

Requisiti minimi verificati prima di procedere:

| VM/CT | vCPU | RAM | Storage | Bridge |
|---|---|---|---|---|
| vm-100 (Home Assistant) | 2 | 2 GB | 32 GB local-lvm | vmbr0 |
| ct-101 (Uptime Kuma + Portainer) | 2 | 1 GB | 16 GB local-lvm | vmbr0 |
| ct-102 (Greenbone) | 4 | 4 GB | 32 GB local-lvm | vmbr0 |
| **TOTALE Fase 2** | **8** | **7 GB** | **80 GB** | |

> Con 16 GB RAM: Proxmox usa ~2 GB → restano ~14 GB → ampiamente sufficiente per le 3 VM/CT di Fase 2.

---

## 9. Snapshot automatici (Proxmox Backup tramite vzdump)

### 9.1 Crea job di backup schedulato

**Web UI:** Datacenter → Backup → Add

| Campo | Valore |
|---|---|
| Node | `soc-01` |
| Storage | `local` |
| Schedule | `02:00` ogni giorno |
| Selection | All (o selezionare vm-100, ct-101, ct-102) |
| Mode | **Snapshot** |
| Compression | `zstd` |
| Max Backups | `7` (retention 7 giorni) |
| Email | `root` (notifica in caso di fallimento) |

Oppure via CLI (`/etc/vzdump.conf` + cron):

```bash
# Configura vzdump.conf
cat > /etc/vzdump.conf << 'EOF'
bwlimit: 0
compress: zstd
maxfiles: 7
mode: snapshot
prune-backups: keep-daily=7
storage: local
EOF

# Aggiungi cron job
# Web UI: Datacenter → Backup → Add (preferito) oppure:
# pvecm: cron automatico gestito da Proxmox scheduler
```

### 9.2 Test backup manuale

```bash
# Backup manuale vm-100 (dopo la sua creazione nel runbook dedicato)
vzdump 100 --storage local --mode snapshot --compress zstd

# Verifica backup
ls -lh /var/lib/vz/dump/
```

---

## 10. Tailscale — accesso remoto sicuro

Tailscale permette accesso SSH al nodo Proxmox anche quando non si è nella LAN di casa (es. accesso da università o dall'esterno).

### 10.1 Installazione Tailscale

```bash
curl -fsSL https://tailscale.com/install.sh | sh

# Avvia e autentica
tailscale up --ssh

# Output: link di autenticazione da aprire nel browser
# Autenticarsi con il proprio account Tailscale
```

### 10.2 Configurazione

```bash
# Verifica IP Tailscale assegnato
tailscale ip -4

# Verifica stato
tailscale status
```

> Dopo l'autenticazione, SOC-01 sarà raggiungibile da qualsiasi device nella stessa Tailscale network tramite l'IP Tailscale (es. `100.x.x.x`) senza esporre porte pubbliche.

### 10.3 Aggiorna fail2ban per includere IP Tailscale

```bash
# Aggiungi la subnet Tailscale (100.64.0.0/10) alla whitelist fail2ban
sed -i 's/ignoreip = .*/ignoreip = 127.0.0.1\/8 192.168.68.0\/24 100.64.0.0\/10/' \
  /etc/fail2ban/jail.d/sshd.conf
systemctl restart fail2ban
```

---

## 11. Verifica finale e checklist

### 11.1 Checklist di completamento

Eseguire tutte le verifiche prima di dichiarare il nodo pronto per Fase 2.

**Installazione:**
- [ ] Proxmox VE installato e avviato correttamente
- [ ] Versione Proxmox verificata (`pveversion`)
- [ ] Web UI accessibile su `https://192.168.68.200:8006`

**Rete:**
- [ ] IP statico `192.168.68.200` assegnato e stabile
- [ ] DHCP reservation creata su Deco BE65 con MAC corretto
- [ ] Bridge `vmbr0` configurato su NIC1 → LAN
- [ ] Bridge `vmbr1` configurato su NIC2 → fisicamente isolato (NIC2 non connessa allo switch)
- [ ] Ping gateway `192.168.68.1` → OK
- [ ] Ping Internet (`1.1.1.1`) → OK
- [ ] DNS resolution funzionante

**Storage:**
- [ ] `local-lvm` (LVM-thin) disponibile → spazio ≥ 80 GB liberi
- [ ] `local` (dir) disponibile → spazio ≥ 10 GB liberi
- [ ] Template Debian 12 scaricato in `local`
- [ ] ISO Home Assistant OS caricata in `local`

**Aggiornamenti:**
- [ ] `apt full-upgrade` eseguito senza errori
- [ ] Repo enterprise disabilitati, repo no-subscription attivo
- [ ] `unattended-upgrades` configurato

**Hardening SSH:**
- [ ] Chiave ED25519 generata sul MacBook
- [ ] Login SSH con chiave funzionante (porta 2222)
- [ ] `PasswordAuthentication no` verificato
- [ ] Banner SSH attivo
- [ ] `fail2ban` attivo su porta 2222
- [ ] `~/.ssh/config` aggiornato sul MacBook

**Backup:**
- [ ] Job backup vzdump schedulato (02:00 daily, retention 7 gg)
- [ ] Test backup manuale completato con successo

**Accesso remoto:**
- [ ] Tailscale installato e autenticato
- [ ] Accesso SSH via IP Tailscale verificato

**Pool:**
- [ ] Pool `phase2` creato nella Web UI
- [ ] Risorse sufficienti per vm-100, ct-101, ct-102 verificate

### 11.2 Verifica comandi diagnostici di riepilogo

```bash
# Riepilogo stato sistema
echo "=== Proxmox Version ===" && pveversion
echo "=== Network ===" && ip addr show vmbr0 | grep inet
echo "=== Storage ===" && pvesm status
echo "=== RAM ===" && free -h
echo "=== CPU ===" && nproc
echo "=== SSH ===" && systemctl is-active sshd
echo "=== fail2ban ===" && fail2ban-client status sshd
echo "=== Tailscale ===" && tailscale status
echo "=== Uptime ===" && uptime
```

---

## 12. Troubleshooting

### Perdo la connessione SSH dopo modifica `/etc/network/interfaces`

Accedere fisicamente al device (monitor + tastiera) o via Web UI Proxmox (Console). Verificare la sintassi del file con `cat /etc/network/interfaces` e correggere eventuali errori. Ripetere `ifreload -a`.

### Proxmox Web UI non raggiungibile dopo riavvio

```bash
# Verifica che il servizio pveproxy sia attivo
systemctl status pveproxy
systemctl restart pveproxy

# Verifica che la porta 8006 sia in ascolto
ss -tlnp | grep 8006
```

### fail2ban banna il proprio IP

```bash
# Sblocca il proprio IP (es. 192.168.68.108 — MacBook)
fail2ban-client set sshd unbanip 192.168.68.108

# Verifica IP bannati
fail2ban-client status sshd
```

### SSH non accetta la chiave

```bash
# Sul server — verifica permessi
ls -la /root/.ssh/
# authorized_keys deve essere 600, directory .ssh deve essere 700

chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

# Verifica che la chiave pubblica sia su una sola riga
cat /root/.ssh/authorized_keys

# Controlla i log SSH per diagnostica
journalctl -u sshd -n 50
```

### Repo apt fallisce con errori GPG

```bash
# Riscaricare le chiavi GPG Proxmox
wget https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg \
  -O /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg

apt update
```

---

## Prossimi passi

Dopo aver completato e verificato questa checklist:

1. Commit su Git:
   ```bash
   git add runbooks/proxmox-setup.md
   git commit -m "runbooks(proxmox): add Phase 2 setup runbook v1.0"
   ```

2. Procedere con il runbook successivo: **`runbooks/homeassistant-deploy.md`**
   - Crea vm-100 su Proxmox (2 vCPU, 2 GB RAM, 32 GB disco, vmbr0)
   - Installa Home Assistant OS (HAOS)
   - Configura IP statico e integrazione base

---

*File: `runbooks/proxmox-setup.md` · v1.0 · Aprile 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
