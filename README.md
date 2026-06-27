# SSH Key Persistence Detection (MITRE T1098)

![Wazuh](https://img.shields.io/badge/Wazuh-FIM-blue) ![Splunk](https://img.shields.io/badge/Splunk-SIEM-green) ![MITRE](https://img.shields.io/badge/MITRE-T1098-red) ![Lab](https://img.shields.io/badge/SOC-Home%20Lab-purple)

## Overview

This project demonstrates the detection of SSH key-based persistence on a Linux system using Wazuh File Integrity Monitoring (FIM) and Splunk SIEM. The simulation follows the MITRE ATT&CK framework and is part of an ongoing home SOC lab build documenting real-world attack detection techniques.

**Technique:** [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)  
**Tactic:** Persistence  
**Platform:** Linux (Ubuntu)  
**Severity:** High  

---

## Lab Environment

| Machine | IP | Role |
|---|---|---|
| SOC101-Ubuntu | 192.168.1.4 | Wazuh Manager (target) |
| DESKTOP-DDNOGVU | 192.168.1.6 | Splunk SIEM (Windows) |
| Kali Linux | 192.168.1.5 | Attack machine |

**Tools Used:**
- Wazuh 4.x (FIM / HIDS)
- Splunk Free (500MB/day)
- Splunk Universal Forwarder
- Kali Linux (ssh-keygen)

---

## Attack Simulation

### What Is SSH Key Persistence?

After gaining initial access to a system (e.g., via brute force - T1110), an attacker can add their own SSH public key to the target's `~/.ssh/authorized_keys` file. This creates a **persistent backdoor** — the attacker can silently return anytime without a password, even after the victim changes their password.

This is one of the most common post-exploitation techniques seen in real-world Linux intrusions.

### Attack Steps (from Kali)

**Step 1: Generate an attacker SSH key pair**
```bash
ssh-keygen -t rsa -b 4096 -C "attacker@kali" -f ~/.ssh/evil_key
# Hit Enter twice — no passphrase for silent access
```

**Step 2: Gain initial access (simulating post-exploitation)**
```bash
ssh cyberintelhq@192.168.1.4
```

**Step 3: Inject the malicious public key**
```bash
cat ~/.ssh/evil_key.pub | ssh cyberintelhq@192.168.1.4 \
  "cat >> ~/.ssh/authorized_keys"
```

**Step 4: Verify backdoor access works**
```bash
ssh -i ~/.ssh/evil_key cyberintelhq@192.168.1.4
# Connects without password — persistence confirmed
```

---

## Detection — Wazuh FIM Configuration

Wazuh's File Integrity Monitoring (FIM) module monitors critical files and directories for unauthorized changes. By default, `/home` is **not monitored** — this must be explicitly configured.

### ossec.conf Syscheck Block

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>300</frequency>
  <scan_on_start>yes</scan_on_start>

  <!-- Generate alert when new file detected -->
  <alert_new_files>yes</alert_new_files>

  <!-- Critical system directories -->
  <directories check_all="yes" realtime="yes">/etc</directories>
  <directories check_all="yes" realtime="yes">/usr/bin,/usr/sbin</directories>
  <directories check_all="yes" realtime="yes">/bin,/sbin</directories>

  <!-- Home directories - catches SSH key persistence -->
  <directories check_all="yes" realtime="yes">/home</directories>
  <directories check_all="yes" realtime="yes">/root</directories>

  <!-- Ignore noisy files -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <ignore>/etc/mail/statistics</ignore>
</syscheck>
```

> **Key insight:** `realtime="yes"` is critical. Without it, Wazuh only scans every 12 hours by default — an attacker would have hours of undetected access.

---

## Detection Results

### Wazuh Alert
Wazuh fired immediately upon detecting the `authorized_keys` file modification:

- **Rule:** Integrity checksum changed
- **File:** `/home/cyberintelhq/.ssh/authorized_keys`
- **Agent:** SOC101-ubuntu
- **Time:** 2026-06-27 15:23:40

### Splunk Query (Evidence)
```splunk
index=wazuh sourcetype=wazuh-alerts earliest=-24h
| search syscheck.path="*authorized*" OR syscheck.path="*ssh*"
| table _time, agent.name, syscheck.path, rule.description
```

### Splunk Result
| Time | Agent | Path | Description |
|---|---|---|---|
| 2026-06-27 15:23:40 | SOC101-ubuntu | /home/cyberintelhq/.ssh/authorized_keys | Integrity checksum changed |

📸 See `/screenshots/splunk-fim-detection.png`

---

## Key Lessons Learned

1. **Wazuh syscheck is effectively blind out of the box** — `/home` is not monitored by default and must be manually configured
2. **`realtime="yes"` is non-negotiable** — periodic scanning gives attackers a massive detection window
3. **Wazuh needs a baseline before it can detect changes** — restart Wazuh and wait 60 seconds before running the attack so FIM can establish what "normal" looks like
4. **The Splunk field `syscheck.path` is the key forensic artifact** — it gives you the exact file that was touched

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Persistence |
| Technique | T1098 - Account Manipulation |
| Sub-technique | T1098.004 - SSH Authorized Keys |
| Detection | DS0022 - File Modification |
| Mitigation | M1022 - Restrict File and Directory Permissions |

---

## Related Detections in This Lab

| Repo | Technique | Description |
|---|---|---|
| [wazuh-powershell-detection](https://github.com/MartyDickerson/wazuh-powershell-detection) | T1059.001 | PowerShell abuse detection |
| [ssh-key-persistence-detection](https://github.com/MartyDickerson/ssh-key-persistence-detection) | T1098 | SSH key persistence (this repo) |

---

## Author

**Marty Dickerson**  
SOC Analyst (in progress) | Atlanta, GA  
GitHub: [@MartyDickerson](https://github.com/MartyDickerson) | Project: [cyberintelhq](https://github.com/MartyDickerson)

*Building a home SOC lab to demonstrate real-world detection engineering across the MITRE ATT&CK kill chain.*
