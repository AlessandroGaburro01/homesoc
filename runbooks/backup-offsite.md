# Runbook — Backup Offsite: NAS + Cloud (rclone)
**Progetto:** HomeSOC · Domestic Security Operations Centre  
**File:** `runbooks/backup-offsite.md`  
**Versione:** 1.2 — Aprile 2026  
**Autore:** Alessandro · LM Sicurezza Informatica · UniMI  
**Fase:** Operativa — Resilienza Infrastrutturale  
**Prerequisito:** `runbooks/proxmox-setup.md` completato — vzdump schedulato su `local` — SOC-01 operativo

> **Scopo:** Aggiungere due livelli di backup offsite agli snapshot vzdump già schedulati su `local` (SSD interno di SOC-01). Il livello 1 usa il NAS WD My Cloud Home (`192.168.68.90`) come destinazione di backup **manuale opportunistico** — lanciato ogni volta che il NAS è già acceso per altri motivi (Plex, ecc.). Il livello 2 sincronizza automaticamente su Backblaze B2 (cloud, free tier 10 GB) via rclone ogni notte. Al termine di questo runbook, la perdita dell'SSD di SOC-01 non causa perdita irrecuperabile di configurazione o dati.

> **Nota di sicurezza:** Il WD My Cloud Home è un dispositivo cloud-first con relay WD non disabilitabile (vedere `docs/01-threat-model.md`). I backup vzdump archiviano configurazioni sensibili. La cifratura è opzionale per il NAS (relay WD ha accesso tecnico ai file), obbligatoria per il cloud (sezione 4.5).

**Changelog:**
- v1.0 — Aprile 2026 — Prima stesura
- v1.1 — Aprile 2026 — Livello 1 NAS ridisegnato: da backup schedulato automatico a backup manuale opportunistico. Motivazione documentata in sezione 1.1. Rimosso secondo job vzdump schedulato; aggiunto alias e procedura manuale.
- v1.2 — Aprile 2026 — Fix da esecuzione reale: `--maxfiles` deprecato → `--prune-backups keep-last=2`; `--subdir` richiede slash iniziale (`/homesoc-backup`); script cloud aggiornato per includere `*.vma.zst` (dump VM qemu) oltre a `*.tar.zst` (dump CT LXC).

---

## Indice

1. [Architettura backup — tre livelli](#1-architettura-backup--tre-livelli)
2. [Prerequisiti](#2-prerequisiti)
3. [Livello 1 — NAS WD My Cloud Home via CIFS](#3-livello-1--nas-wd-my-cloud-home-via-cifs)
4. [Livello 2 — Cloud Backblaze B2 via rclone](#4-livello-2--cloud-backblaze-b2-via-rclone)
5. [Verifica end-to-end](#5-verifica-end-to-end)
6. [Runbook di ripristino (Disaster Recovery)](#6-runbook-di-ripristino-disaster-recovery)
7. [Verifica finale e checklist](#7-verifica-finale-e-checklist)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Architettura backup — tre livelli

```
┌────────────────────────────────────────────────────────────────┐
│                    STRATEGIA 3-2-1 HomeSOC                     │
│                                                                │
│  3 copie dei dati                                              │
│  2 media diversi                                               │
│  1 copia offsite                                               │
└────────────────────────────────────────────────────────────────┘

  LIVELLO 0 (esistente)          LIVELLO 1 (questo runbook)
  ┌─────────────────┐            ┌──────────────────────────┐
  │   SOC-01 SSD    │            │   WD My Cloud Home       │
  │   /var/lib/vz/  │──CIFS──▶   │   192.168.68.90          │
  │   dump/         │  MANUALE   │   homesoc-backup/        │
  │   vzdump daily  │            │   retention: 2 copie     │
  │   retention: 7  │            └──────────────────────────┘
  └────────┬────────┘
           │                     LIVELLO 2 (questo runbook)
           │                     ┌──────────────────────────┐
           └──── rclone ────────▶│   Backblaze B2           │
                (cron 03:00)     │   bucket: homesoc-backup │
                AUTOMATICO       │   retention: 2 copie     │
                                 │   cifratura: AES-256     │
                                 └──────────────────────────┘
```

### 1.1 Decisione di design — perché il backup NAS è manuale

Il backup sul NAS è **intenzionalmente manuale e opportunistico**, non schedulato. La scelta deriva da un'analisi dei vincoli hardware del WD My Cloud Home:

**Vincolo 1 — impossibilità di spegnimento pulito remoto.** Il WD My Cloud Home su questo modello specifico non espone SSH (rimosso da WD, a differenza del My Cloud classico) e non supporta Wake-on-LAN. L'unico modo per accenderlo è fisicamente dal tasto o ricollegando il cavo di alimentazione. Staccare la spina mentre il sistema operativo interno e Plex girano è un hard shutdown con rischio di corruzione del filesystem — non accettabile come routine automatica.

**Vincolo 2 — impatto su MTBF e vita utile.** Il NAS monta un HDD 3.5" (WD Red 4TB), certificato 24/7. Il MTBF ~1,000,000 ore descrive la probabilità di guasto in funzione delle **ore di esercizio accumulate**, non del tempo di calendario. La differenza tra lasciare il NAS acceso 24/7 per automatizzare i backup notturni rispetto all'uso corrente è concreta:

| Scenario | Ore/anno | Anni per 40,000h esercizio |
|---|---|---|
| Uso attuale (~2-3x settimana, 7h) | ~2,000 h/anno | ~20 anni |
| 24/7 per backup automatico notturno | ~8,760 h/anno | ~4-5 anni |

Lasciare il NAS acceso 24/7 consuma la vita utile del disco circa **4 volte più velocemente**, a fronte di un vantaggio (automazione) sostituibile con una procedura manuale di 30 secondi.

**Conclusione:** il NAS viene usato come storage di backup opportunistico. Ogni volta che è già acceso (Plex, accesso file), si lancia il backup manuale via SSH su SOC-01. Il livello 2 (B2) copre il disaster recovery automatico notturno senza dipendere dall'uptime del NAS.

### 1.2 Cosa viene backuppato

| Contenuto | Formato | Dimensione stimata |
|---|---|---|
| vm-100 Home Assistant | vzdump `.tar.zst` | ~500 MB |
| vm-103 Wazuh SIEM | vzdump `.tar.zst` | ~4–8 GB |
| ct-101 Uptime Kuma | vzdump `.tar.zst` | ~200 MB |
| ct-102 Greenbone | vzdump `.tar.zst` | ~2–4 GB |
| ct-104 OpenCanary | vzdump `.tar.zst` | ~150 MB |

> ℹ️ **Nota Wazuh:** il dump di vm-103 include tutti gli alert storici. Se supera il free tier B2 (10 GB), escludere vm-103 dal sync cloud — rimane coperta da NAS e da livello 0. Vedere sezione 4.6.

---

## 2. Prerequisiti

### 2.1 Prerequisiti SOC-01

```bash
# Verifica che vzdump sia già schedulato
cat /etc/vzdump.conf
# Atteso: compress: zstd, maxfiles: 7, storage: local

# Verifica dump esistenti
ls -lh /var/lib/vz/dump/

# Verifica connettività NAS (deve essere acceso per la configurazione iniziale)
ping -c 3 192.168.68.90
```

### 2.2 Prerequisiti NAS

- WD My Cloud Home acceso e raggiungibile su `192.168.68.90` — **necessario solo per la configurazione iniziale**
- Credenziali SMB (username/password account WD My Cloud)

### 2.3 Prerequisiti cloud (Backblaze B2)

- Account Backblaze B2 gratuito — `https://www.backblaze.com/b2/sign-up.html`
- Bucket e Application Key (istruzioni in sezione 4.1–4.2)

---

## 3. Livello 1 — NAS WD My Cloud Home via CIFS

> ℹ️ **Questa sezione va eseguita una sola volta** per registrare il NAS come storage Proxmox. Dopo la configurazione iniziale il backup NAS si esegue con un singolo comando ogni volta che il NAS è già acceso.

### 3.1 Preparazione cartella sul NAS

**Da macOS (Finder):** `Go` → `Connect to Server` → `smb://192.168.68.90` → autenticarsi → creare cartella `homesoc-backup`.

**Oppure da browser:** `http://192.168.68.90` → spazio personale → nuova cartella `homesoc-backup`.

### 3.2 Identificare il nome della share SMB

```bash
# Da SOC-01
apt install -y smbclient

smbclient -L //192.168.68.90 -U TUO_USERNAME
```

Output atteso:
```
Sharename       Type      Comment
---------       ----      -------
Public          Disk
[TUO_NOME]      Disk      ← annotare questo nome
```

### 3.3 Registrare il NAS come storage Proxmox (configurazione una-tantum)

```bash
# Da SOC-01 — eseguire una sola volta con NAS acceso
# Note: --maxfiles è deprecato → usare --prune-backups
#       --subdir richiede slash iniziale
pvesm add cifs nas-backup \
  --server 192.168.68.90 \
  --share TUO_NOME \
  --subdir /homesoc-backup \
  --username TUO_USERNAME \
  --password 'TUA_PASSWORD_WD' \
  --content backup \
  --prune-backups keep-last=2

# Verifica
pvesm status
# Atteso: nas-backup nella lista con stato active
```

> ⚠️ La password viene salvata in `/etc/pve/storage.cfg`, leggibile solo da root. Accettabile in questo contesto.

```bash
# Verifica configurazione salvata
cat /etc/pve/storage.cfg | grep -A 10 "cifs: nas-backup"
```

### 3.4 Procedura operativa — backup manuale NAS

Una volta registrato lo storage (`pvesm add` eseguito una tantum), il backup si lancia con un singolo comando da qualsiasi sessione SSH su SOC-01 — senza conoscere IP, credenziali o percorsi, perché Proxmox ha già tutto nel suo storage config:

```bash
# Backup completo di tutte le VM/CT → NAS (foreground, terminale occupato ~20-40 min)
vzdump --all --storage nas-backup --mode snapshot --compress zstd
```

Per lanciarlo in background e poter chiudere il terminale:

```bash
nohup vzdump --all --storage nas-backup --mode snapshot --compress zstd \
  > /var/log/homesoc/backup-nas-manual.log 2>&1 &

# Monitoraggio
tail -f /var/log/homesoc/backup-nas-manual.log
```

**Alias rapido — aggiungere a `/root/.bashrc` su SOC-01:**

```bash
echo "alias backup-nas='nohup vzdump --all --storage nas-backup --mode snapshot \
  --compress zstd > /var/log/homesoc/backup-nas-manual.log 2>&1 &'" \
  >> /root/.bashrc

source /root/.bashrc
```

Da quel momento basta:

```bash
backup-nas
```

> 📌 **Routine consigliata:** ogni volta che accendi il NAS per Plex o altro, apri SSH su SOC-01 e lancia `backup-nas`. Il backup gira in background, puoi chiudere il terminale immediatamente. Proxmox applica automaticamente la retention (maxfiles: 2) — se esistono già 2 copie, elimina la più vecchia prima di scrivere la nuova.

### 3.5 (Opzionale) Cifratura dump prima del trasferimento NAS

Il relay WD ha accesso tecnico ai file sulla share. Per proteggere i dump:

```bash
apt install -y age

# Genera chiave (una sola volta)
age-keygen -o /root/.config/age/homesoc-backup.key
# Annotare la public key nel password manager

# Cifratura di un dump
age -r age1TUAPUBLICKEY \
  /var/lib/vz/dump/vzdump-qemu-103-*.tar.zst \
  > /mnt/pve/nas-backup/dump/backup-103.tar.zst.age
```

---

## 4. Livello 2 — Cloud Backblaze B2 via rclone

### 4.1 Creazione account e bucket B2

1. Registrarsi: `https://www.backblaze.com/b2/sign-up.html` (free tier: 10 GB + 1 GB/giorno download)
2. `Buckets` → `Create a Bucket`

| Campo | Valore |
|---|---|
| Bucket Name | `homesoc-backup-[tuoiniziali]` (univoco globalmente) |
| Files in Bucket | **Private** |
| Default Encryption | Enabled |
| Object Lock | Disabled |

### 4.2 Creazione Application Key B2

`App Keys` → `Add a New Application Key`

| Campo | Valore |
|---|---|
| Name of Key | `homesoc-rclone` |
| Allow access to Bucket(s) | solo `homesoc-backup-[tuoiniziali]` |
| Type of Access | **Read and Write** |
| Duration | vuoto — non scade |

> ⚠️ `applicationKey` viene mostrata **una sola volta**. Salvare subito nel password manager: `keyID` e `applicationKey`.

### 4.3 Installazione rclone

```bash
curl https://rclone.org/install.sh | bash
rclone version
```

### 4.4 Configurazione remote B2

```bash
mkdir -p /root/.config/rclone

cat > /root/.config/rclone/rclone.conf << 'EOF'
[b2-homesoc]
type = b2
account = TUO_KEY_ID_B2
key = TUA_APPLICATION_KEY_B2
EOF

# Test
rclone lsd b2-homesoc:
```

### 4.5 Cifratura lato client — rclone crypt (obbligatoria)

```bash
# Genera password offuscate (due esecuzioni separate)
rclone obscure UNA_PASSWORD_LUNGA_E_CASUALE   # → valore per "password"
rclone obscure UN_SECONDO_SALT_CASUALE         # → valore per "password2"

cat >> /root/.config/rclone/rclone.conf << 'EOF'

[b2-homesoc-crypt]
type = crypt
remote = b2-homesoc:homesoc-backup-[tuoiniziali]
filename_encryption = standard
directory_name_encryption = true
password = OUTPUT_PRIMO_OBSCURE
password2 = OUTPUT_SECONDO_OBSCURE
EOF
```

> 🔑 Salvare le password originali (pre-obscure) nel password manager. Senza di esse i backup cloud sono irrecuperabili. Non committare su Git.

**Test:**

```bash
echo "test" > /tmp/t.txt
rclone copy /tmp/t.txt b2-homesoc-crypt:
rclone ls b2-homesoc-crypt:          # leggibile
rclone ls b2-homesoc:homesoc-backup-[tuoiniziali]/ # nomi cifrati su B2
rclone delete b2-homesoc-crypt:t.txt
```

### 4.6 Script di sync con retention

```bash
cat > /usr/local/bin/homesoc-backup-cloud.sh << 'SCRIPT'
#!/bin/bash
# homesoc-backup-cloud.sh — Sync vzdump → Backblaze B2
# Automatico ogni notte alle 03:00 via cron — non dipende dall'uptime NAS

set -euo pipefail

DUMP_DIR="/var/lib/vz/dump"
REMOTE="b2-homesoc-crypt:"
LOG="/var/log/homesoc/backup-cloud.log"
MAX_COPIES=2
DATE=$(date '+%Y-%m-%d %H:%M:%S')

log() { echo "[$DATE] $1" | tee -a "$LOG"; }

log "=== Inizio sync cloud backup ==="

if [ -z "$(ls -A "$DUMP_DIR"/*.tar.zst "$DUMP_DIR"/*.vma.zst 2>/dev/null)" ]; then
  log "WARN: Nessun dump trovato — skip"
  exit 0
fi

# Decommenta se vm-103 supera il free tier B2 (10 GB):
# EXCLUDE="--exclude vzdump-qemu-103-*"
EXCLUDE=""

# *.tar.zst = CT (LXC), *.vma.zst = VM (qemu)
rclone copy $EXCLUDE \
  --include "*.tar.zst" --include "*.vma.zst" \
  --stats-one-line \
  --log-level INFO \
  "$DUMP_DIR/" "$REMOTE"

log "Sync completato. Retention in corso..."

VMIDS=$(rclone ls "$REMOTE" | grep -oP 'vzdump-\w+-\K\d+' | sort -u)
for VMID in $VMIDS; do
  FILES=$(rclone ls "$REMOTE" | grep "vzdump-.*-${VMID}-" | awk '{print $2}' | sort)
  COUNT=$(echo "$FILES" | grep -c "." || true)
  if [ "$COUNT" -gt "$MAX_COPIES" ]; then
    TO_DELETE=$(echo "$FILES" | head -n $((COUNT - MAX_COPIES)))
    for F in $TO_DELETE; do
      log "Elimino: $F"
      rclone delete "$REMOTE$F"
    done
  fi
done

log "=== Fine sync cloud backup ==="
SCRIPT

chmod +x /usr/local/bin/homesoc-backup-cloud.sh
```

### 4.7 Cron job

```bash
crontab -e
```

```cron
# HomeSOC — sync cloud backup ogni notte alle 03:00 (automatico)
0 3 * * * /usr/local/bin/homesoc-backup-cloud.sh >> /var/log/homesoc/backup-cloud.log 2>&1
```

**Sequenza notturna risultante:**

| Orario | Azione | Storage | Modalità |
|---|---|---|---|
| `02:00` | vzdump principale | `local` (SSD) | Automatico — retention 7 |
| `03:00` | rclone sync | Backblaze B2 | Automatico — retention 2 |
| *Ad hoc* | vzdump manuale | `nas-backup` (WD) | **Manuale** — quando NAS è già acceso |

---

## 5. Verifica end-to-end

```bash
# Stato storage (nas-backup active solo se NAS è acceso — atteso)
pvesm status

# Dump presenti sul NAS (dopo backup manuale)
ls -lh /mnt/pve/nas-backup/dump/

# Dump presenti su B2
rclone ls b2-homesoc-crypt:

# Spazio usato su B2
rclone about b2-homesoc:homesoc-backup-[tuoiniziali]

# Log ultimo sync cloud
tail -30 /var/log/homesoc/backup-cloud.log
```

**Smoke test ripristino da NAS:**

```bash
# Ripristino ct-101 in CT temporaneo ID 199
DUMP=$(ls -t /mnt/pve/nas-backup/dump/vzdump-lxc-101-*.tar.zst | head -1)
pct restore 199 "$DUMP" --storage local-lvm --rootfs local-lvm:4 --unprivileged 1
pct config 199
pct destroy 199
```

---

## 6. Runbook di ripristino (Disaster Recovery)

> **Scenario:** SSD SOC-01 guasto. Hardware funzionante. Proxmox reinstallato da `runbooks/proxmox-setup.md` fino al punto 8.

### 6.1 Ripristino da NAS (primario)

```bash
pvesm add cifs nas-backup \
  --server 192.168.68.90 \
  --share TUO_NOME \
  --subdir /homesoc-backup \
  --username TUO_USERNAME \
  --password 'TUA_PASSWORD_WD' \
  --content backup

ls /mnt/pve/nas-backup/dump/

# Ripristino in ordine di priorità
qm restore 103 $(ls -t /mnt/pve/nas-backup/dump/vzdump-qemu-103-*.tar.zst | head -1) --storage local-lvm
qm restore 100 $(ls -t /mnt/pve/nas-backup/dump/vzdump-qemu-100-*.tar.zst | head -1) --storage local-lvm

for CTID in 101 102 104; do
  DUMP=$(ls -t /mnt/pve/nas-backup/dump/vzdump-lxc-${CTID}-*.tar.zst | head -1)
  pct restore $CTID "$DUMP" --storage local-lvm
done

qm start 100 && qm start 103
pct start 101 && pct start 102 && pct start 104
```

### 6.2 Ripristino da B2 (secondario — NAS non disponibile)

```bash
curl https://rclone.org/install.sh | bash

mkdir -p /root/.config/rclone
cat > /root/.config/rclone/rclone.conf << 'EOF'
[b2-homesoc]
type = b2
account = TUO_KEY_ID_B2
key = TUA_APPLICATION_KEY_B2

[b2-homesoc-crypt]
type = crypt
remote = b2-homesoc:homesoc-backup-[tuoiniziali]
filename_encryption = standard
directory_name_encryption = true
password = PASSWORD_CIFRATA
password2 = SALT_CIFRATO
EOF

mkdir -p /var/lib/vz/dump
rclone copy b2-homesoc-crypt: /var/lib/vz/dump/ --include "*.tar.zst"

# Procedere come sezione 6.1 usando /var/lib/vz/dump/
```

---

## 7. Verifica finale e checklist

**Configurazione NAS (una-tantum):**
- [ ] Cartella `homesoc-backup` creata sul NAS
- [ ] `smbclient` installato, nome share SMB identificato e annotato
- [ ] `pvesm add cifs nas-backup` completato senza errori
- [ ] `pvesm status` mostra `nas-backup` active (con NAS acceso)
- [ ] Alias `backup-nas` aggiunto a `/root/.bashrc`
- [ ] Primo backup manuale completato — file `.tar.zst` in `/mnt/pve/nas-backup/dump/`

**Cloud B2:**
- [ ] Account B2 e bucket `homesoc-backup-[tuoiniziali]` creati (Private)
- [ ] Application Key `homesoc-rclone` — `keyID` + `applicationKey` nel password manager
- [ ] rclone installato, `rclone.conf` configurato con `b2-homesoc` e `b2-homesoc-crypt`
- [ ] Password originali rclone nel password manager (non su Git)
- [ ] Test cifratura completato
- [ ] Script `/usr/local/bin/homesoc-backup-cloud.sh` creato ed eseguibile
- [ ] Cron `0 3 * * *` aggiunto
- [ ] Prima esecuzione manuale OK — `rclone ls b2-homesoc-crypt:` mostra dump

**Disaster Recovery:**
- [ ] Smoke test ripristino ct-101 da NAS completato
- [ ] Credenziali B2 e password rclone nel password manager
- [ ] `runbooks/backup-offsite.md` committato su Git

---

## 8. Troubleshooting

### nas-backup in errore al boot SOC-01

Comportamento atteso — Proxmox tenta il mount CIFS all'avvio e fallisce se il NAS è spento. Nessuna azione richiesta. Lo storage torna `active` non appena il NAS viene acceso.

### vzdump manuale — "storage 'nas-backup' not available"

```bash
ping -c 3 192.168.68.90       # verifica NAS raggiungibile
pvesm set nas-backup --disable 0
pvesm status
```

### rclone — errore 401 autenticazione B2

Credenziali scadute o errate. Rigenerare Application Key da dashboard B2 e aggiornare `rclone.conf`.

### Dump vm-103 troppo grande per B2 free tier

Decommentare in `/usr/local/bin/homesoc-backup-cloud.sh`:

```bash
EXCLUDE="--exclude vzdump-qemu-103-*"
```

vm-103 rimane coperta da NAS (backup manuale) e livello 0 (SSD locale, 7 giorni).

---

*Runbook generato nell'ambito del progetto HomeSOC — versione 1.2*
