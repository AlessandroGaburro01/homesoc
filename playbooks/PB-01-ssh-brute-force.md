# PB-01 — SSH Brute Force

**File:** `playbooks/PB-01-ssh-brute-force.md`  
**Version:** 1.0 — June 2026  
**Author:** Alessandro · LM Sicurezza Informatica · UniMI  
**Trigger:** Wazuh rule 100001 (level 10) — ≥5 SSH failures in 60s  
**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing  
**Severity:** Medium (default) → Critical if successful login confirmed  
**Asset at risk:** SOC-01 (192.168.68.200, SSH port 2222)  
**SLA:** Triage within 30 min of alert · Containment within 1h

---

## Quick Reference

| Step | Action | Time |
|---|---|---|
| P | Open TheHive case, assign to self | 2 min |
| I | Identify source IP, check for successful logins | 5 min |
| C | Verify CrowdSec ban, apply manual ban if needed | 5 min |
| E | Check for lateral movement, update whitelist if FP | 10 min |
| R | Verify SSH still operational, check audit log | 5 min |
| L | Document in case, close with tag | 3 min |

**Total expected time:** 30 min (external attacker, no successful login)  
**Escalation path:** Successful login → Critical → notify immediately, invoke full forensic review

---

## Phase 1 — Preparation (pre-incident)

Verify these controls are active before an incident occurs:

```bash
# CrowdSec active on SOC-01
sudo cscli hub list | grep crowdsecurity/ssh
sudo systemctl status crowdsec --no-pager | grep Active

# Endlessh tarpit on SOC-01:22
sudo systemctl status endlessh --no-pager | grep Active

# SSH real port accessible
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 "uptime"
```

---

## Phase 2 — Identification (Triage)

### 2.1 Open TheHive case

1. Open TheHive: `http://192.168.68.205:9000`
2. Locate case created automatically by Wazuh integration (title contains `rule 100001`)
3. **Assign to me** → set status **In Progress**
4. Note: case already contains observable `src_ip` enriched by Cortex (AbuseIPDB score, VT ratio, Shodan)

### 2.2 Extract alert details

```bash
# On vm-103 (192.168.68.204)
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204

# Last 5 SSH brute force alerts — extract source IP, timestamp, target
sudo grep '"id":"100001"' /var/ossec/logs/alerts/alerts.json \
  | tail -10 | python3 -c "
import sys, json
for line in sys.stdin:
    a = json.loads(line)
    d = a.get('data', {})
    print(a['timestamp'],
          'src:', d.get('srcip', '?'),
          'user:', d.get('dstuser', '?'),
          'attempts:', a['rule'].get('firedtimes', '?'))
"
```

### 2.3 Check for successful logins

```bash
# CRITICAL: check if attacker achieved a successful login
# Run on SOC-01
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "grep 'Accepted' /var/log/auth.log | grep <IP_SORGENTE>"

# Also check last logins
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "last -20 | head -20"
```

> ⚠️ **If any successful login from the attacker IP is found → CRITICAL.**  
> Escalate immediately: change all SSH keys, review running processes, check for persistence.

### 2.4 Triage decision matrix

| Condition | Severity | Action |
|---|---|---|
| External IP, no successful login | Medium | Standard containment |
| External IP, successful login | Critical | Full forensic review |
| Internal IP (192.168.68.x) | High | Invoke PB-02 for rogue device |
| Distributed (many different IPs) | Medium | Password spray — review SSH config |
| Tailscale IP (100.x.x.x) | High | Check if it was you; if not → credentials compromise |

### 2.5 Cortex enrichment review

In TheHive → observable → check Cortex reports:
- **AbuseIPDB Score > 50%** → known malicious IP, priority containment
- **VirusTotal detections > 0** → confirmed threat actor infrastructure
- **Shodan** → check if IP is a known scanner (e.g., Shodan/Censys nodes are normal background noise)

---

## Phase 3 — Containment

### 3.1 Verify CrowdSec automatic ban

```bash
# On SOC-01
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo cscli decisions list | grep <IP_SORGENTE>"
```

Expected output: `<IP_SORGENTE> | ban | 4h | crowdsecurity/ssh-bf`

### 3.2 Manual ban if CrowdSec did not trigger

Applies when: attacker IP is on the local network (CrowdSec whitelist includes 192.168.0.0/16).

```bash
# Manual iptables block — temporary
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo iptables -I INPUT -s <IP_SORGENTE> -j DROP"

# Verify
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo iptables -L INPUT -n | grep <IP_SORGENTE>"
```

Document this manual action in the TheHive case as a note.

### 3.3 Document containment in TheHive

Add a note to the case:
```
Containment applied: [CrowdSec ban / Manual iptables block]
Source IP: <IP>
Ban applied at: <timestamp>
Ban duration: [4h CrowdSec / manual until eradication complete]
Successful login: [Yes/No]
```

---

## Phase 4 — Eradication

### 4.1 External attacker (standard case)

CrowdSec ban is sufficient. No further action required beyond monitoring.

```bash
# Verify ban is in effect
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo cscli decisions list --limit 5"
```

### 4.2 Internal device compromised

If source IP is internal → follow **PB-02 (Rogue Device)** for device identification and isolation.

### 4.3 False positive — known service

If the source IP belongs to a legitimate internal scanner (e.g., Greenbone, a monitoring tool):

```bash
# Whitelist in CrowdSec
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo nano /etc/crowdsec/parsers/s02-enrich/whitelists.yaml"
# Add IP to the whitelist section

sudo systemctl restart crowdsec
```

### 4.4 Rule tuning (if excessive noise)

If the rule fires too frequently from background internet scanners:

```bash
# On vm-103 — increase threshold temporarily
sudo nano /var/ossec/etc/rules/local_rules.xml
# Change <frequency>5</frequency> to <frequency>10</frequency> on rule 100001

sudo systemctl restart wazuh-manager
```

Document the change in CHANGELOG.md.

---

## Phase 5 — Recovery

### 5.1 Verify SSH is still operational

```bash
# From MacBook (END-05)
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 "uptime && hostname"
```

### 5.2 Verify Endlessh is active on :22

```bash
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo systemctl status endlessh --no-pager | grep Active"
```

### 5.3 Check audit log post-incident

```bash
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo journalctl -u ssh --since '2 hours ago' --no-pager | grep -E 'Accepted|Failed|Invalid' | tail -20"
```

### 5.4 Verify Wazuh agent still active

```bash
# On vm-103
sudo /var/ossec/bin/agent_control -l | grep -E "SOC-01|002"
# Expected: Active
```

---

## Phase 6 — Lessons Learned

### 6.1 Close TheHive case

In TheHive UI:
1. Add final summary note (use template below)
2. Add resolution tags: `resolved` + one of: `external-scan` / `external-bruteforce` / `internal-compromise` / `false-positive`
3. Set status → **Resolved**
4. Set PAP → **WHITE** (if sharing summary externally)

### 6.2 Case closure template

```
== INCIDENT SUMMARY ==
Date: <timestamp>
Duration: <open time> → <close time>
Source IP: <IP> | AbuseIPDB: <score>% | VT: <n>/94 | Shodan: <info>
Total attempts: <n>
Successful login: No / Yes (see escalation log)

== CONTAINMENT ==
Method: CrowdSec automatic ban (4h) / Manual iptables / No action required
Applied at: <timestamp>

== ROOT CAUSE ==
External internet scanner / Targeted brute force / Internal device / False positive

== ACTION TAKEN ==
[ ] CrowdSec ban verified
[ ] Manual ban applied (if needed)
[ ] Rule tuning applied (if FP)
[ ] PB-02 invoked (if internal IP)

== LESSONS LEARNED ==
<free text — what worked, what didn't, what to improve>
```

### 6.3 Metrics to track

- Time from alert to triage: target < 30 min
- Time from triage to containment: target < 1h
- False positive rate: track monthly

---

*File: `playbooks/PB-01-ssh-brute-force.md` · v1.0 · June 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
