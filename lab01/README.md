# 🛡️ SOC-01 — SSH Invalid-User / Brute-Force Detection

> **SafeTest-Dev | SOC / Blue Team Series · Lab 01**
> Detecting and triaging an SSH credential-access attempt against a monitored Linux host using a Wazuh SIEM stack.

---

## 📌 Overview

| | |
|---|---|
| **Lab ID** | SOC-01 |
| **Category** | SOC / Threat Detection & Hunting |
| **SIEM** | Wazuh 4.x |
| **Attack Class** | Credential Access / Brute Force |
| **Log Source** | journald → `sshd-session` |
| **Seed Rule** | 5710 (level 5) — invalid user |
| **Escalation Rule** | 2502 (level 10) — repeated password miss |
| **MITRE ATT&CK** | T1110.001 (Password Guessing) · T1021.004 (SSH) |
| **Tactics** | Credential Access · Lateral Movement |
| **Outcome** | ❌ No breach — all attempts failed |
| **Difficulty** | 🟡 Beginner |

This lab walks through the full blue-team workflow: detecting an SSH brute-force attempt in the Wazuh dashboard, scoping and triaging the alerts, decoding the raw log into evidence, mapping the activity to MITRE ATT&CK, and producing an incident-response plan.

---

## 🧪 Lab Environment

The lab runs on a **3-VM topology** on a single host hypervisor, on an isolated NAT network (`192.168.122.0/24`). One VM acts as the SIEM core, one as the protected asset, and one as the attacker.

| VM | Role | OS | Wazuh Components | IP |
|----|------|----|------------------|----|
| **VM 1** | SIEM Core / Monitoring Server | Ubuntu **Desktop** | **Manager + Indexer + Dashboard** (all-in-one) **+ Agent** | `mike-pc` (manager) |
| **VM 2** | Protected Asset (monitored) | Ubuntu **Server** | **Agent** only | `monitor` · `192.168.122.187` |
| **VM 3** | Attacker | **Arch Linux** | — (none) | `192.168.122.97` |

**Component roles (Wazuh):**
- **Wazuh Manager** — the analysis engine. Receives events from agents, decodes them, runs them against the ruleset, and generates alerts.
- **Wazuh Indexer** — the storage & search layer (OpenSearch-based). Stores alerts and powers fast querying.
- **Wazuh Dashboard** — the web UI. Used here for the Threat Hunting / Discover views, histograms, and document inspection.
- **Wazuh Agent** — installed on each monitored endpoint (VM 1 and VM 2); ships log data to the Manager.

> VM 1 also runs an agent so the SIEM host monitors itself, but in this lab the alerts of interest all originate from **VM 2 (`monitor`)**.

---

## 🗺️ Architecture Diagram

```
                          ISOLATED LAB NETWORK  ·  192.168.122.0/24
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │                                                                                 │
 │   ┌─────────────────────────┐          SSH brute-force          ┌───────────┐  │
 │   │   VM 3 — ATTACKER        │   user "hacker" · port 58318      │           │  │
 │   │   Arch Linux             │ ────────────────────────────────►│  VM 2     │  │
 │   │   192.168.122.97         │     (repeated failed logins)      │  monitor  │  │
 │   └─────────────────────────┘                                   │  Ubuntu   │  │
 │                                                                  │  Server   │  │
 │                                                                  │ .187      │  │
 │                                                                  │           │  │
 │                                                                  │ [Wazuh    │  │
 │                                                                  │  Agent]   │  │
 │                                                                  └─────┬─────┘  │
 │                                                                        │        │
 │                                              events / logs (TCP 1514)  │        │
 │                                                                        ▼        │
 │   ┌────────────────────────────────────────────────────────────────────────┐  │
 │   │   VM 1 — SIEM CORE  ·  Ubuntu Desktop  ·  manager: mike-pc              │  │
 │   │   ┌──────────────┐   ┌──────────────┐   ┌────────────────────────────┐  │  │
 │   │   │ Wazuh        │──►│ Wazuh        │──►│ Wazuh Dashboard            │  │  │
 │   │   │ Manager      │   │ Indexer      │   │ (Threat Hunting / Discover)│  │  │
 │   │   │ decode+rules │   │ store+search │   │   ← analyst works here     │  │  │
 │   │   └──────────────┘   └──────────────┘   └────────────────────────────┘  │  │
 │   │                          + local Wazuh Agent (self-monitoring)          │  │
 │   └────────────────────────────────────────────────────────────────────────┘  │
 │                                                                                 │
 └───────────────────────────────────────────────────────────────────────────────┘

 FLOW:
   1. VM 3 (Arch) launches repeated SSH logins as a non-existent user against VM 2.
   2. VM 2's Wazuh Agent forwards the sshd/journald logs to the Manager on VM 1 (TCP 1514).
   3. Manager decodes the logs → matches rules 5710 / 5503 → correlates into 2502 (level 10).
   4. Indexer stores the alerts; the analyst triages them in the Dashboard.
```

---

## 🎯 Attack Scenario

From the **Arch Linux attacker (VM 3, 192.168.122.97)**, repeated SSH login attempts were issued against the **Ubuntu Server (VM 2, `monitor`)** using the username **`hacker`** — an account that does not exist on the target. The rapid repetition of failed authentications is characteristic of automated password guessing rather than legitimate user error.

**Raw log (decoded by the `sshd` decoder):**
```
Jun 07 18:07:20 monitor sshd-session[86982]: Failed password for invalid user hacker from 192.168.122.97 port 58318 ssh2
```

---

## 🔬 Detection & Triage Workflow

```
1. DETECTION
   └── Wazuh Threat Hunting dashboard — events histogram shows a spike ~01:07
       scoped to manager.name: mike-pc + agent.id: 001 (host monitor)

2. SCOPING
   └── filter to the SSH failures — 6 correlated events in the 01:01–01:16 window

3. ALERT INSPECTION
   └── open the rule 5710 document — decoded fields, rule metadata, MITRE tags

4. EVIDENCE EXTRACTION
   └── data.srcuser = hacker · data.srcip = 192.168.122.97 · target host = monitor

5. CORRELATION & ESCALATION
   └── rule 5710 (lvl 5) ×N + rule 5503 (PAM fail) → rule 2502 (lvl 10) escalation

6. THREAT INTEL MAPPING
   └── MITRE T1110.001 + T1021.004 · compliance tags (PCI-DSS, HIPAA, NIST, GDPR, TSC)

7. INCIDENT RESPONSE
   └── containment, hardening, hunting pivots
```

---

## 🚨 Alert Chain

| Order | Rule ID | Level | Description | Meaning |
|-------|---------|-------|-------------|---------|
| 1 | **5710** | 5 | sshd: Attempt to login using a non-existent user | Seed event — invalid username |
| 2 | **5503** | 5 | PAM: User login failed | Auth subsystem failure |
| 3 | **2502** | **10** | syslog: User missed the password more than one time | **Escalation** — brute-force confirmed |

The value of Wazuh here is **correlation**: individual low-severity events (level 5) are aggregated within a time window into a single high-confidence, high-severity alert (level 10) — the alert an analyst should prioritize.

---

## 🔑 Key Evidence

| Field | Value | Note |
|-------|-------|------|
| `data.srcuser` | `hacker` | Username does not exist on host |
| `data.srcip` | `192.168.122.97` | Single external source (VM 3 / Arch attacker) |
| `agent.name` | `monitor` | Target host (VM 2 / Ubuntu Server) |
| `agent.ip` | `192.168.122.187` | Monitored asset address |
| `manager.name` | `mike-pc` | SIEM core (VM 1) |
| `decoder.name` | `sshd` | Log decoder |
| `location` | `journald` | Log source |
| `rule.firedtimes` | 4 | Repetition count for rule 5710 |

---

## 🧭 MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Brute Force: Password Guessing | **T1110.001** | Credential Access |
| Remote Services: SSH | **T1021.004** | Lateral Movement |

---

## 📋 Compliance Mapping

| Framework | Controls |
|-----------|----------|
| **PCI-DSS** | 10.2.4, 10.2.5, 10.6.1 |
| **HIPAA** | 164.312.b |
| **NIST 800-53** | AU.14, AC.7, AU.6 |
| **GDPR** | IV_35.7.d, IV_32.2 |
| **TSC** | CC6.1, CC6.8, CC7.2, CC7.3 |
| **GPG13** | 7.1 |

---

## ✅ Findings & Verdict

- A single external source (VM 3, `192.168.122.97`) attempted repeated SSH logins against VM 2 (`monitor`) using a non-existent account.
- Wazuh correctly correlated the low-severity invalid-user events into a **level-10 brute-force escalation (rule 2502)**.
- **No `Accepted password` / successful-session event** accompanied the failures → **the attack did not succeed; no breach occurred.**
- Risk remains elevated while SSH is reachable from the attacker's subnet.

---

## 🛡️ Incident Response & Recommendations

| Action | Recommendation |
|--------|----------------|
| **Block** | Ban/rate-limit `192.168.122.97` at the host & perimeter firewall; enable fail2ban or Wazuh active-response to auto-ban on rule 2502. |
| **Harden** | Disable password authentication (`PasswordAuthentication no`); enforce SSH key-based auth; disable direct root login (`PermitRootLogin no`). |
| **Reduce Exposure** | Restrict SSH to a management VLAN/VPN; do not expose port 22 to untrusted networks; consider a non-default port to cut automated noise. |
| **Tune Detection** | Confirm Wazuh correlation thresholds for rule 2502; alert SOC on any level ≥ 10 SSH alert; add the source IP to a watchlist. |
| **Hunt** | Pivot on `data.srcip` across all agents to confirm the source is not targeting other hosts; review for any successful logins from the same subnet. |

---

## 📂 Deliverables

| File | Description |
|------|-------------|
| `SOC-01_SSH_Invalid_User_Detection.pdf` | Full analysis report |
| `SOC-01_slide[1-8].jpg` | Instagram carousel (300 DPI) |
| `SOC-01_caption.md` | Instagram captions (long / short) |
| `SOC-01_linkedin_caption.md` | LinkedIn caption |
| `alert.json` | Raw Wazuh alert document |
| `README.md` | This file |

---

## ⚠️ Disclaimer

This lab was conducted in an **isolated, self-owned virtual environment** for **defensive security research and educational purposes** only. The attacker VM and all activity were authorized within the lab. Do **not** use any documented attacker behavior against systems you do not own or have explicit permission to test.

---

## 👤 Author

**Michael.A** — SafeTest-Dev
Binary | Malware | Exploitation | Reverse | SOC | AI

---

*SafeTest-Dev © 2026 — All rights reserved*
