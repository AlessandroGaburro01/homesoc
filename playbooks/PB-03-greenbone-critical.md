# PB-03 — Greenbone Critical CVE

**File:** `playbooks/PB-03-greenbone-critical.md`  
**Version:** 1.0 — June 2026  
**Author:** Alessandro · LM Sicurezza Informatica · UniMI  
**Trigger:** Wazuh rule 100070 (level 14) — Greenbone finding CVSS ≥ 7.0  
**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application  
**Severity:** High (CVSS 7.0–8.9) · Critical (CVSS 9.0+)  
**Asset at risk:** Variable — depends on scan target (vm-103, SOC-01, ct-102, NAS, MacBook)  
**SLA:** Triage within 2h · Patch within 72h (Critical) or 7 days (High)

---

## Quick Reference

| Step | Action | Time |
|---|---|---|
| P | Greenbone scans run weekly (Friday 04:00) — no action | 0 min (ongoing) |
| I | Extract CVE details, verify exposure, check exploit availability | 15 min |
| C | Disable service if actively exploitable; increase monitoring | 10 min |
| E | Apply patch / upgrade / mitigate per CVE guidance | 30 min–2h |
| R | Re-scan with Greenbone to confirm finding resolved | 30 min |
| L | Document patch applied, close case | 5 min |

**Total expected time:** 1–3h depending on patch availability and complexity  
**Escalation path:** CVE with public exploit AND service exposed on LAN → Critical → patch within 24h

---

## Phase 1 — Preparation (pre-incident)

```bash
# Verify Greenbone scheduled scan is configured
# On ct-102 (192.168.68.203)
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "pct exec 102 -- docker exec -i gvm gvmd --get-tasks 2>/dev/null | grep -i homesoc"

# Verify Wazuh pipeline from Greenbone is active
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204 \
  "sudo grep -l '100070' /var/ossec/etc/rules/*.xml"
```

---

## Phase 2 — Identification (Triage)

### 2.1 Open TheHive case

1. Open TheHive: `http://192.168.68.205:9000`
2. Locate case triggered by rule 100070 (title contains CVE ID or vulnerability name)
3. **Assign to me** → set status **In Progress**

### 2.2 Extract CVE details from Wazuh alert

```bash
# On vm-103
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204

sudo grep '"id":"100070"' /var/ossec/logs/alerts/alerts.json \
  | tail -5 | python3 -c "
import sys, json
for line in sys.stdin:
    a = json.loads(line)
    d = a.get('data', {})
    print('=== Finding ===')
    print('Time:', a['timestamp'])
    print('CVE:', d.get('cve', '?'))
    print('CVSS:', d.get('cvss', '?'))
    print('Name:', d.get('name', '?'))
    print('Host:', d.get('host', '?'))
    print('Port:', d.get('vuln_port', '?'))
    print('Solution:', d.get('solution', 'see Greenbone UI')[:200])
    print()
"
```

### 2.3 Verify service exposure

```bash
# Check if the vulnerable service is reachable on LAN
# Replace PORT and IP with values from alert
nmap -sV -p <PORT> <IP_HOST> --open

# Is it exposed only on localhost, or on LAN interface?
# Localhost only: lower risk — still patch, but not urgent
# LAN exposed: moderate risk — patch within SLA
# Internet exposed (via NAT): Critical — patch immediately
```

### 2.4 Check for public exploit

```bash
# Search NVD for CVE details (manual)
# https://nvd.nist.gov/vuln/detail/<CVE_ID>

# Check Exploit-DB (manual)
# https://www.exploit-db.com/search?cve=<CVE_ID>

# Searchsploit if available on local machine
searchsploit <CVE_ID> 2>/dev/null || echo "searchsploit not installed — check exploit-db.com manually"
```

### 2.5 Verify current package version

```bash
# For Linux hosts — check installed version
ssh <HOSTNAME_OR_IP> "dpkg -l | grep <PACKAGE_NAME>"

# Compare with patched version from CVE advisory
# NVD or vendor advisory will list the fixed version
```

### 2.6 Triage decision matrix

| Condition | Severity | SLA |
|---|---|---|
| CVSS ≥ 9.0 + public exploit + LAN exposed | Critical | Patch within 24h |
| CVSS 7.0–8.9 + no public exploit | High | Patch within 72h |
| CVSS 7.0–8.9 + service localhost only | High | Patch within 7 days |
| Duplicate finding (already patched) | Informational | Verify + close |
| False positive (version detection error) | None | Document + close |

---

## Phase 3 — Containment

> Containment for CVE is about reducing exposure while the patch is being prepared. Not all CVEs require active containment — use judgment based on triage.

### 3.1 Option A — No immediate containment needed

When: CVSS < 9.0, no public exploit, service not internet-facing.

Action: Proceed directly to eradication (patch).

### 3.2 Option B — Increase monitoring temporarily

```bash
# Add temporary Wazuh FIM monitoring on the affected service config files
# On vm-103
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204 \
  "sudo nano /var/ossec/etc/ossec.conf"
# Add syscheck entry for affected service config directory
# Restart: sudo systemctl restart wazuh-manager
```

### 3.3 Option C — Disable service temporarily (Critical CVE + active exploit)

Only if the CVE has a known public exploit AND the service is exposed:

```bash
# Identify and stop the service on the affected host
ssh <HOST> "sudo systemctl stop <SERVICE_NAME>"
ssh <HOST> "sudo systemctl disable <SERVICE_NAME>"

# Verify service is no longer listening
nmap -p <PORT> <IP_HOST>
# Expected: port closed or filtered
```

Document the service disruption in TheHive case and add to Uptime Kuma if applicable.

### 3.4 Document in TheHive

```
Containment decision: [No action / Increased monitoring / Service disabled]
Reason: <CVSS score + exploit availability + exposure level>
Patch ETA: <date>
```

---

## Phase 4 — Eradication

### 4.1 Apply patch (Linux host)

```bash
ssh <HOST>

# Standard OS package update
sudo apt update
sudo apt list --upgradable 2>/dev/null | grep <PACKAGE_NAME>
sudo apt upgrade -y <PACKAGE_NAME>

# Verify installed version post-patch
dpkg -l | grep <PACKAGE_NAME>
# Compare with fixed version from CVE advisory
```

### 4.2 Verify patch applied correctly

```bash
# Check version matches or exceeds the fixed version in CVE advisory
dpkg -l | grep <PACKAGE_NAME>

# If service was disabled during containment — re-enable after patch
sudo systemctl enable --now <SERVICE_NAME>
sudo systemctl status <SERVICE_NAME> --no-pager
```

### 4.3 MacBook (END-05) — macOS vulnerability

If the finding is on the MacBook (Greenbone agent scan):
- Apply macOS system update: **System Settings → General → Software Update**
- Apply application updates: **App Store → Updates**
- Document update applied in TheHive case

### 4.4 NAS (WD My Cloud Home)

If the finding is on the NAS:
- Check WD firmware update: **My Cloud Home app → Device → Firmware**
- If no firmware update available → document as accepted risk (vendor dependency)
- Note: NAS is powered off when not in use — limited attack surface

---

## Phase 5 — Recovery

### 5.1 Trigger Greenbone re-scan

Verify the vulnerability is resolved by running a targeted scan:

```bash
# On ct-102 — run scan against affected host only
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "pct exec 102 -- docker exec -i gvm gvm-cli \
    --gmp-username admin --gmp-password <GVM_PASSWORD> \
    socket --xml '<create_task><name>Post-patch verify</name><config id=\"daba56c8-73ec-11df-a475-002264764cea\"/><target id=\"<TARGET_ID>\"/></create_task>'"
```

Alternatively, trigger re-scan from Greenbone UI:
1. Open `http://192.168.68.203:9392` (via SSH tunnel if needed)
2. Scans → New Task → select affected host as target
3. Run immediately
4. Check results after 30–60 minutes

### 5.2 Verify finding is resolved

After re-scan completes:
- Confirm the CVE-triggering finding no longer appears in results
- If still present → patch was insufficient → escalate to manual investigation

### 5.3 Re-enable any disabled services

```bash
# If service was disabled during containment
ssh <HOST> "sudo systemctl enable --now <SERVICE_NAME>"
ssh <HOST> "sudo systemctl status <SERVICE_NAME> --no-pager | grep Active"
```

### 5.4 Verify Wazuh rule 100070 does not re-trigger

Wait 24h after re-scan and confirm no new alert for the same CVE:

```bash
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204 \
  "sudo grep '"id":"100070"' /var/ossec/logs/alerts/alerts.json \
   | grep '<CVE_ID>' | tail -3"
# Expected: empty or only pre-patch alerts
```

---

## Phase 6 — Lessons Learned

### 6.1 Close TheHive case

Tags: `resolved` + one of: `patched` / `accepted-risk` / `false-positive` / `no-fix-available`

### 6.2 Case closure template

```
== INCIDENT SUMMARY ==
Date: <timestamp>
CVE: <CVE_ID> | CVSS: <score>
Affected host: <hostname/IP> | Service: <service> | Port: <port>
Public exploit available: Yes / No
LAN exposed: Yes / No

== TRIAGE ==
Severity assessed: Critical / High
Exploit availability: <link to PoC or None>
Exposure level: localhost only / LAN / Internet

== CONTAINMENT ==
Action taken: None / Increased monitoring / Service disabled
Duration: <if disabled: from <timestamp> to <timestamp>>

== ERADICATION ==
Patch applied: Yes / No / Not available
Package: <name> <old version> → <new version>
Patched at: <timestamp>
Re-scan triggered: Yes / No

== RECOVERY ==
Greenbone re-scan result: Finding resolved / Still present
Rule 100070 re-triggered: Yes / No
Service restored: Yes / N/A

== LESSONS LEARNED ==
<patch delay reason if SLA missed, false positive notes, process improvements>

== RISK REGISTER UPDATE ==
<if this CVE exposes a new risk not in register — note here for monthly review>
```

---

*File: `playbooks/PB-03-greenbone-critical.md` · v1.0 · June 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
