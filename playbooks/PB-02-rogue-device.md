# PB-02 — Rogue Device Detected

**File:** `playbooks/PB-02-rogue-device.md`  
**Version:** 1.0 — June 2026  
**Author:** Alessandro · LM Sicurezza Informatica · UniMI  
**Trigger:** Wazuh rule 100040 (level 12, MAC not in whitelist) or 100041 (level 8, first-seen known MAC)  
**MITRE ATT&CK:** T1078 — Valid Accounts (unauthorized use of network via SSID credentials)  
**Severity:** High (rule 100040) · Low (rule 100041 — informational)  
**Asset at risk:** Entire flat LAN 192.168.68.0/24  
**SLA:** Triage within 1h · Containment within 2h (if threat confirmed)

---

## Quick Reference

| Step | Action | Time |
|---|---|---|
| P | Verify rogue-device-check.sh schedule, baseline current | 0 min (ongoing) |
| I | Identify MAC vendor, IP, physical presence | 10 min |
| C | Isolate via Deco app (if threat), rotate SSID password | 15 min |
| E | Whitelist if legitimate, update baseline | 5 min |
| R | Verify monitoring resumed, confirm device off network | 5 min |
| L | Document in TheHive, update MAC whitelist if needed | 5 min |

**Total expected time:** 40 min (unknown device confirmed legitimate guest)  
**Escalation path:** Unknown device with active lateral movement → Critical → invoke PB-01 for SSH brute force if observed

> **Known limitation:** In the absence of OPNsense and VLAN segmentation (deferred to Phase 6), true network isolation is limited to SSID password rotation. This limitation is documented as R-05 and R-07 in the risk register. The TheHive case documents the event regardless of containment completeness.

---

## Phase 1 — Preparation (pre-incident)

```bash
# Verify rogue-device-check.sh is running (scheduled cron on vm-103)
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204 \
  "sudo crontab -l | grep rogue"

# Check current MAC whitelist
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204 \
  "cat /var/ossec/etc/lists/mac-whitelist.txt"

# Verify Wazuh rules 100040/100041 are loaded
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204 \
  "sudo grep -l '100040\|100041' /var/ossec/etc/rules/*.xml"
```

---

## Phase 2 — Identification (Triage)

### 2.1 Open TheHive case

1. Open TheHive: `http://192.168.68.205:9000`
2. Locate case triggered by rule 100040 or 100041 (title contains MAC address)
3. **Assign to me** → set status **In Progress**
4. Note the MAC address and IP from the case title/description

### 2.2 Extract device details from alert

```bash
# On vm-103
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204

sudo grep '"id":"100040"\|"id":"100041"' /var/ossec/logs/alerts/alerts.json \
  | tail -5 | python3 -c "
import sys, json
for line in sys.stdin:
    a = json.loads(line)
    d = a.get('data', {})
    print('=== Alert', a['rule']['id'], '===')
    print('Time:', a['timestamp'])
    print('MAC:', d.get('mac', '?'))
    print('IP:', d.get('ip', '?'))
    print('Vendor:', d.get('vendor', '?'))
    print('Rule:', a['rule']['description'])
"
```

### 2.3 Identify MAC vendor

```bash
# Query MAC vendor API (first 6 hex chars = OUI)
MAC="<MAC_ADDRESS>"
OUI=$(echo $MAC | tr -d ':' | head -c 6)
curl -s "https://api.macvendors.com/${OUI}" 2>/dev/null
# Example output: "Apple, Inc." / "Samsung Electronics" / "Unknown"
```

### 2.4 Check device current presence on network

```bash
# ARP scan from SOC-01 to identify device location
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "arp -n | grep <IP_DEVICE>"

# Check DHCP lease if available (Deco manages DHCP — check via app)
# Alternatively, check if device is still active
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "ping -c 2 <IP_DEVICE> && echo REACHABLE || echo OFFLINE"
```

### 2.5 Check for suspicious activity from the device

```bash
# Look for SSH attempts, port scans, or unusual traffic originating from this IP
sudo grep '<IP_DEVICE>' /var/ossec/logs/alerts/alerts.json \
  | tail -10 | python3 -c "
import sys, json
for line in sys.stdin:
    a = json.loads(line)
    print(a['timestamp'], 'Rule:', a['rule']['id'], '-', a['rule']['description'])
"

# Also check if this IP has brute forced SSH → invoke PB-01 if confirmed
sudo grep '"id":"100001"' /var/ossec/logs/alerts/alerts.json \
  | grep '<IP_DEVICE>' | tail -5
```

### 2.6 Triage decision matrix

| Condition | Action |
|---|---|
| MAC vendor matches a known household device (Apple/Samsung/etc.) | Ask household members — likely legitimate guest |
| MAC vendor unknown or Chinese OEM | Investigate further before dismissing |
| Device actively scanning ports (nmap, etc.) | Critical — immediate containment |
| Device connected to honeypot | Critical — invoke PB-04, this device is hostile |
| MAC not seen before but vendor is Apple at typical guest hours | Likely legitimate — confirm and whitelist |
| Rule 100041 (known MAC, first access) | Informational — verify it's the expected device |

---

## Phase 3 — Containment

> **Current limitation:** True network isolation requires VLAN segmentation (Phase 6 — OPNsense). Available containment methods are listed below in order of preference.

### 3.1 Option A — Isolate via Deco app (preferred)

If device is confirmed hostile or unknown:
1. Open TP-Link Deco app on iPhone
2. Navigate to: **Deco** → **Device Details** → find device by IP/MAC
3. **Block** the device from the network
4. Document action in TheHive case

### 3.2 Option B — Block at SOC-01 level

Blocks device from reaching SOC-01 and other monitored assets:

```bash
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo iptables -I INPUT -s <IP_DEVICE> -j DROP && \
   sudo iptables -I FORWARD -s <IP_DEVICE> -j DROP"

# Verify
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo iptables -L -n | grep <IP_DEVICE>"
```

### 3.3 Option C — SSID password rotation (worst-case)

If the SSID password may be compromised (device is unknown and not physically present):
1. Change WiFi password via Deco app for all SSIDs
2. All legitimate devices will need to reconnect
3. Document the rotation in TheHive case

### 3.4 Document containment in TheHive

Add a note:
```
Containment method: [Deco block / iptables / SSID rotation / None — legitimate]
Device MAC: <MAC>
Device IP: <IP>
Vendor: <vendor>
Physical presence confirmed: [Yes/No/Unknown]
Household member confirmed: [Yes/No]
```

---

## Phase 4 — Eradication

### 4.1 Device confirmed legitimate (whitelist)

If the device belongs to a known person (family member, guest with permission):

```bash
# On vm-103 — add MAC to whitelist
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204

# Edit whitelist
sudo nano /var/ossec/etc/lists/mac-whitelist.txt
# Add line: <MAC_ADDRESS>  # <owner> — <device type> — <date added>

# Reload Wazuh to pick up new list
sudo systemctl restart wazuh-manager

# Verify rule no longer triggers for this MAC
sudo /var/ossec/bin/agent_control -l
```

### 4.2 Device confirmed hostile (remove access)

If device was blocked via Deco app:
- Confirm device is no longer visible in ARP table
- Monitor for reconnection attempts (MAC spoofing possible)

If SSID password was rotated:
- Update all legitimate device connections
- Verify monitoring resumed (Wazuh agents reconnected, Uptime Kuma shows all green)

---

## Phase 5 — Recovery

### 5.1 Verify monitoring is operational

```bash
# Wazuh agents still active
ssh -i ~/.ssh/id_homesoc_ed25519 alessandro@192.168.68.204 \
  "sudo /var/ossec/bin/agent_control -l | grep -v Never"
# Expected: all agents Active

# rogue-device-check.sh will run on next schedule
# Verify it can still reach the network
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "sudo arp -n | wc -l"
```

### 5.2 Verify blocked device is not on network

```bash
ssh -i ~/.ssh/id_homesoc_ed25519 -p 2222 root@192.168.68.200 \
  "ping -c 1 -W 1 <IP_DEVICE> && echo STILL_REACHABLE || echo OFFLINE_OK"
```

---

## Phase 6 — Lessons Learned

### 6.1 Close TheHive case

Add final summary note, set tags, resolve:
- Tags: `resolved` + one of: `legitimate-guest` / `unknown-device-blocked` / `false-positive` / `hostile-device`

### 6.2 Case closure template

```
== INCIDENT SUMMARY ==
Date: <timestamp>
Trigger: Rule <100040/100041> — MAC <MAC_ADDRESS>
Device IP: <IP> | Vendor: <vendor>
Physical presence: <confirmed/unknown>
Household member: <name or Unknown>

== IDENTIFICATION ==
Device type (based on vendor + context): <description>
Suspicious activity detected: Yes / No
  If yes: <detail — port scan / honeypot / SSH brute force>

== CONTAINMENT ==
Method: <Deco block / iptables / SSID rotation / No action — legitimate>
Applied at: <timestamp>

== RESOLUTION ==
[ ] Legitimate device → whitelisted in mac-whitelist.txt
[ ] Unknown/hostile device → blocked via Deco app
[ ] SSID password rotated
[ ] iptables rule added temporarily

== LESSONS LEARNED ==
<what worked, what didn't, known limitation (R-05 flat network), what to improve>

== KNOWN LIMITATION ==
Without OPNsense VLAN segmentation (Phase 6), a device on the flat LAN can reach
all other devices even if blocked at SOC-01. True isolation requires hardware upgrade.
This limitation is documented as R-05 in the risk register.
```

---

*File: `playbooks/PB-02-rogue-device.md` · v1.0 · June 2026*  
*HomeSOC Project — Alessandro · LM Sicurezza Informatica · UniMI*
