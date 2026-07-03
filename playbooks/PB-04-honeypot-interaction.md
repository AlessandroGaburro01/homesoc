# PB-04 — Honeypot Interaction

**File:** `playbooks/PB-04-honeypot-interaction.md`  
**Version:** 1.0 — June 2026  
**Author:** Alessandro · LM Sicurezza Informatica · UniMI  
**Trigger:** Wazuh rules 100080–100085 (level 10–14) — OpenCanary or Endlessh event  
**MITRE ATT&CK:** T1046 — Network Service Discovery · T1021.004 — Remote Services: SSH · T1110 — Brute Force  
**Severity:** High (default minimum) · Critical if source is internal or Tailscale  
**Assets:** ct-104 backup-srv (192.168.68.206) · SOC-01 Endlessh (:22)  
**SLA:** Triage within 15 min · Containment within 30 min

---

## Quick Reference

| Step | Action | Time |
|---|---|---|
| P | Verify honeypot and tarpit are active | 0 min (ongoing) |
| I | Identify source IP, rule ID, interaction type; determine scenario | 5 min |
| C | Block source; if internal → invoke PB-01 + PB-02 | 10 min |
| E | Investigate device/account if internal; investigate NAT if external | 10 min |
| R | Verify honeypot still operational; confirm source gone | 5 min |
| L | Document IOC, close case | 5 min |

**Total expected time:** 35 min (internal device, isolated via Deco)  
**Key principle:** Any interaction with a honeypot is by definition unauthorized. There are no structural false positives for this playbook. Severity is always at least High.

> **Expected background noise:** The honeypot ports are NOT exposed to the internet via NAT. A source IP from outside 192.168.68.0/24 (excluding Tailscale 100.x.x.x) would indicate a serious misconfiguration or active NAT manipulation — treat as Critical.

---

## Phase 1 — Preparation (pre-incident)

```bash
# Verify OpenCanary is running on ct-104
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "pct exec 104 -- systemctl status opencanaryd --no-pager | grep Active"

# Verify Endlessh tarpit on SOC-01:22
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "systemctl status endlessh --no-pager | grep Active"

# Verify Wazuh agent on ct-104 is active
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204 \
  "sudo /var/ossec/bin/agent_control -l | grep 004"
# Expected: 004 ct-104-opencanary (Active)

# Verify honeypot banner responds correctly (simulates attacker perspective)
ssh -o ConnectTimeout=3 testuser@192.168.68.206 2>&1 | head -3
# Expected: fake SSH banner (Ubuntu 22.04 / OpenSSH_8.9p1)
nc -w 2 192.168.68.206 21 2>&1 | head -1
# Expected: FTP banner (ProFTPD 1.3.5e)
```

---

## Phase 2 — Identification (Triage)

### 2.1 Open TheHive case

1. Open TheHive: `http://192.168.68.205:9000`
2. Locate case triggered by rule 1008x (title contains honeypot or service name)
3. **Assign to me** → set status **In Progress**
4. Note the rule ID — it determines the honeypot service that was touched

### 2.2 Rule ID reference

| Rule | Service | Port | Level | Notes |
|---|---|---|---|---|
| 100080 | OpenCanary SSH | 22/ct-104 | 12 | SSH connection attempt |
| 100081 | OpenCanary FTP | 21/ct-104 | 14 | FTP login attempt |
| 100082 | OpenCanary Telnet | 23/ct-104 | 12 | Telnet connection |
| 100083 | OpenCanary HTTP | 8080/ct-104 | 10 | HTTP request |
| 100084 | OpenCanary MySQL | 3306/ct-104 | 14 | MySQL auth attempt |
| 100085 | Endlessh | 22/SOC-01 | 10 | SSH tarpit connection |

### 2.3 Extract interaction details

```bash
# On vm-103
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204

RULE_PATTERN='"id":"1008[0-5]"'
sudo grep -E '100080|100081|100082|100083|100084|100085' \
  /var/ossec/logs/alerts/alerts.json \
  | tail -10 | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        a = json.loads(line)
        d = a.get('data', {})
        print('=== Rule', a['rule']['id'], '===')
        print('Time:', a['timestamp'])
        print('Src IP:', d.get('src_host', d.get('srcip', '?')))
        print('Dst Port:', d.get('dst_port', '?'))
        print('Log type:', d.get('logtype', '?'))
        print('Node:', d.get('node_id', '?'))
        print()
    except:
        pass
"
```

### 2.4 Scenario classification

**Scenario A — Internal IP (192.168.68.x):**  
A device on the local network accessed the honeypot.  
Severity: **High**. Device is either: (a) compromised and running recon, (b) an unauthorized user on the WiFi, (c) legitimate user accidentally connecting to `backup-srv` instead of a real server.

**Scenario B — Tailscale IP (100.x.x.x):**  
Access via Tailscale tunnel. Check if it was you first.  
Severity: **Critical** if not authorized. Tailscale credentials may be compromised.

**Scenario C — External IP (non-RFC1918, non-Tailscale):**  
The honeypot is NOT exposed to the internet via NAT. An external IP indicates:
- NAT misconfiguration (router accidentally forwarding ports)
- Severity: **Critical** — investigate router config immediately

**Scenario D — MacBook IP (192.168.68.108):**  
Likely: OpenWebUI/Ollama credential enumeration at startup (known FP — TK-03 canarytoken trigger pattern).  
Verify: `launchctl list | grep openwebui` on MacBook → if running, this may be the startup credential scan.  
Action: verify with stop/start test before escalating.

### 2.5 Cortex enrichment (for external IPs)

In TheHive case → run analyzers on the source IP observable:
- AbuseIPDB score → known scanner/attacker?
- Shodan → what is this IP known for?
- VirusTotal → any detections?

---

## Phase 3 — Containment

### 3.1 Scenario A — Internal device

```bash
# 1. Identify the device by MAC
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "arp -n | grep <IP_SORGENTE>"

# 2. Check if device is currently performing broader recon
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo tcpdump -i any -n 'src <IP_SORGENTE>' -c 20 2>/dev/null | head -20"

# 3. Block device at SOC-01 level
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo iptables -I INPUT -s <IP_SORGENTE> -j DROP && \
   sudo iptables -I FORWARD -s <IP_SORGENTE> -j DROP"

# 4. Invoke PB-02 for rogue device identification/isolation
# 5. Check if device also attempted SSH brute force → invoke PB-01
```

### 3.2 Scenario B — Tailscale (unauthorized)

```bash
# Immediately revoke your own Tailscale session to prevent further access
tailscale logout

# Then from a separate terminal, revoke all sessions via Tailscale web console
# https://login.tailscale.com/admin/machines
# Revoke all unknown devices

# Re-authenticate only after confirming no further access
```

### 3.3 Scenario C — External IP (Critical)

```bash
# Check which ports are forwarded by the router
# In Deco app: More → Advanced → Port Forwarding
# Remove any unexpected port forwarding rules

# Verify NAT table is clean (no accidental forwarding)
# This is a manual check via Deco UI — no CLI available
```

### 3.4 Scenario D — MacBook OpenWebUI (suspected FP)

```bash
# Stop OpenWebUI on MacBook
launchctl stop com.openwebui.serve

# Wait 2 minutes, check if alerts stop
# On vm-103:
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204 \
  "sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -E '100083|108'"

# If alerts stop → FP confirmed (OpenWebUI scanning credentials)
# Restart OpenWebUI:
launchctl start com.openwebui.serve

# Document as FP in case, add suppression comment to rule 100083 in local_rules.xml
```

### 3.5 Document containment in TheHive

```
Scenario: [A Internal / B Tailscale / C External / D MacBook FP]
Source IP: <IP>
Service touched: <SSH/FTP/Telnet/HTTP/MySQL/Endlessh>
Containment: [iptables block / Deco app block / Tailscale revoke / No action FP]
Applied at: <timestamp>
```

---

## Phase 4 — Eradication

### 4.1 Scenario A — Identify root cause of internal recon

```bash
# What process on the device initiated the connection?
# If device is a Linux host with SSH access:
ssh <DEVICE_IP> "sudo ss -tnp | grep <HONEYPOT_PORT>"
ssh <DEVICE_IP> "sudo journalctl --since '1 hour ago' | grep -i 'backup-srv\|192.168.68.206\|<PORT>'"

# Check for malware persistence
ssh <DEVICE_IP> "sudo crontab -l; sudo ls -la /tmp; sudo ps aux | grep -v '\['"
```

If the device is not SSH-accessible (IoT, phone, etc.) → physical inspection or factory reset.

### 4.2 Scenario B — Secure Tailscale account

1. Change Tailscale account password immediately
2. Enable 2FA on Tailscale account: `https://login.tailscale.com/admin/settings/auth`
3. Re-enroll SOC-01 with new authentication: `tailscale up --force-reauth`
4. Verify only your devices are enrolled: `tailscale status`

### 4.3 All scenarios — verify honeypot integrity

Confirm OpenCanary has not been tampered with:

```bash
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "pct exec 104 -- python3 -c 'import opencanary; print(opencanary.__version__)'"

# Check config integrity
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "pct exec 104 -- cat /etc/opencanaryd/opencanary.conf | python3 -m json.tool | grep -E 'port|enabled'"
```

---

## Phase 5 — Recovery

### 5.1 Verify honeypot is still operational

```bash
# SSH honeypot (from vm-103 — simulates attacker LAN access)
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204
ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no testuser@192.168.68.206 2>&1 | head -3
# Expected: fake banner + "Permission denied"

# FTP honeypot
nc -w 2 192.168.68.206 21 2>&1 | head -1
# Expected: ProFTPD banner

# Endlessh on SOC-01
timeout 3 ssh -o ConnectTimeout=2 attacker@192.168.68.200 2>&1 | head -2
# Expected: connection established but hangs (tarpit active)
```

### 5.2 Verify Wazuh agent ct-104 is active

```bash
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204 \
  "sudo /var/ossec/bin/agent_control -l | grep 004"
# Expected: 004 ct-104-opencanary (Active)
```

### 5.3 Confirm source is no longer interacting

```bash
# Monitor for 5 minutes — no new alerts from source IP
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204 \
  "sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '<IP_SORGENTE>'"
# Expected: silence
```

---

## Phase 6 — Lessons Learned

### 6.1 Close TheHive case

Tags: `resolved` + one of: `internal-recon` / `tailscale-compromise` / `external-scanner` / `false-positive-openwebui` / `unauthorized-access`

### 6.2 Case closure template

```
== INCIDENT SUMMARY ==
Date: <timestamp>
Rule triggered: <100080-100085> | Service: <service type>
Source IP: <IP> | Scenario: [A/B/C/D]
AbuseIPDB score: <score> | Shodan: <info>

== IDENTIFICATION ==
Honeypot service accessed: <SSH/FTP/Telnet/HTTP/MySQL/Endlessh>
Source classification: Internal device / Tailscale / External / MacBook FP
Attacker goal (inferred): Recon / Brute force / Scan / Accidental

== CONTAINMENT ==
Action: [iptables block / Deco app block / Tailscale revoke / No action]
Applied at: <timestamp>

== ERADICATION ==
Root cause identified: Yes / No / Partial
Root cause: <description>
Device investigated: Yes / No / Not applicable
Tailscale 2FA enabled: Yes / Already active / Not applicable

== RECOVERY ==
Honeypot verified operational: Yes
Wazuh agent 004 verified active: Yes
Source no longer interacting: Yes / Monitoring

== IOC ==
Source IP: <IP>
First seen: <timestamp>
Last seen: <timestamp>
Total interactions: <count>

== LESSONS LEARNED ==
<what worked, what to improve, any detection gaps identified>
```

### 6.3 IOC handling

If the source IP is confirmed malicious (AbuseIPDB > 50% or VirusTotal detections):
- Add to CrowdSec custom blocklist:
```bash
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo cscli decisions add --ip <IP> --reason 'honeypot-interaction' --duration 168h"
```

---

*File: `playbooks/PB-04-honeypot-interaction.md` · v1.0 · June 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
