# 🛡️ SOC / Blue Team Series

> **SafeTest-Dev | SOC Detection & Threat Hunting Research**
> A progressive lab series covering SIEM-based detection, alert triage, log analysis, and incident response using a Wazuh stack.

---

## 📖 About This Repository

This repository is a hands-on SOC research collection maintained by **SafeTest-Dev**. Each lab folder contains a self-contained case study built around a real alert scenario — documenting the full workflow from raw log ingestion through detection, triage, MITRE ATT&CK mapping, and incident response.

Labs are designed for:
- 🎓 Aspiring SOC analysts and students learning detection engineering
- 🛠️ Practitioners studying SIEM workflows, alert correlation, and threat hunting
- 📋 Reference material for blue-team operations and compliance-aware reporting

---

## 🗂️ Repository Structure

```
04_SOC/
│
├── lab01/                        # SSH Invalid-User / Brute-Force Detection
│   ├── alert.json                # raw Wazuh alert document
│   └── output/
│       ├── SOC-01_SSH_Invalid_User_Detection.pdf
│       ├── SOC-01_slide[1-8].jpg
│       ├── SOC-01_caption.md
│       ├── SOC-01_linkedin_caption.md
│       └── README.md
│
└── README.md                     ← You are here
```

---

## 🧪 Labs Index

| # | Lab | Source | Behavior | Tooling | Difficulty |
|---|-----|--------|----------|---------|------------|
| [SOC-01](./lab01/) | SSH Invalid-User / Brute-Force | `sshd-session` via journald | Repeated invalid-user logins → level-10 escalation | Wazuh · MITRE ATT&CK | 🟡 Beginner |

> Labs are released progressively. Each follows the same structured detection-and-response methodology.

---

## 🔍 Complexity Progression

```
SOC-01  [ SSH Brute-Force · Credential Access · No Breach · Triage + IR ]
          →  rule 5710 (level 5)  — sshd: attempt to login using a non-existent user
          →  rule 5503            — PAM: user login failed
          →  rule 2502 (level 10) — repeated password miss within correlation window
          →  data.srcuser=hacker  data.srcip=192.168.122.97  target host=monitor
          →  MITRE T1110.001 (Password Guessing) + T1021.004 (SSH)
          →  verdict: failed logins only — no successful authentication
```

---

## 📊 Lab Comparison

| Feature | SOC-01 |
|---------|--------|
| **Attack Class** | Credential Access / Brute Force |
| **Log Source** | journald → `sshd-session` |
| **SIEM** | Wazuh 4.x |
| **Seed Rule** | 5710 (level 5) |
| **Escalation Rule** | 2502 (level 10) |
| **Correlation** | ✅ low-severity → high-severity grouping |
| **MITRE Mapping** | T1110.001, T1021.004 |
| **Compliance Tags** | PCI-DSS, HIPAA, NIST 800-53, GDPR, TSC |
| **Outcome** | No breach — attempts failed |
| **Analysis Type** | Alert triage + threat hunting |
| **Slides** | 8 |

---

## 🔬 Methodology

Every lab follows a consistent detection-and-response pipeline:

```
1. DETECTION
   └── Wazuh dashboard — events histogram, alert table, severity scoring

2. SCOPING
   └── filter by manager.name / agent.id — isolate relevant alert window

3. ALERT INSPECTION
   └── document detail view — decoded fields, rule metadata, MITRE tags

4. EVIDENCE EXTRACTION
   └── raw log → data.srcuser, data.srcip, target host, ports

5. CORRELATION & ESCALATION
   └── trace low-severity primitives → high-severity composite alert

6. THREAT INTEL MAPPING
   └── MITRE ATT&CK technique/tactic + compliance framework mapping

7. INCIDENT RESPONSE
   └── containment (IP block), hardening, hunting pivots

8. DOCUMENTATION
   └── PDF report + README + carousel slides + LinkedIn caption
```

---

## 🛠️ Tools Used Across Labs

| Category | Tools | Labs |
|----------|-------|------|
| **SIEM / Detection** | Wazuh (indexer, manager, dashboard) | All |
| **Threat Hunting** | Wazuh Discover / Threat Hunting views, DQL | All |
| **Log Decoding** | Wazuh `sshd` decoder, journald | All |
| **Threat Intel** | MITRE ATT&CK technique/tactic mapping | All |
| **Compliance** | PCI-DSS, HIPAA, NIST 800-53, GDPR, TSC tagging | All |
| **Documentation** | PDF reports, Markdown, JPG carousel slides | All |

---

## 📂 Detection Classes

| Class | Description | Status |
|-------|-------------|--------|
| 🔑 **Credential Access** | Brute-force / invalid-user login detection | ✅ SOC-01 |
| 🚪 **Privilege Escalation** | sudo abuse, suspicious root activity | 🔜 Planned |
| 🌐 **C2 / Beaconing** | Outbound callback & exfil detection | 🔜 Planned |
| 🦠 **Malware Execution** | Process & file integrity monitoring (FIM) | 🔜 Planned |
| 📡 **Lateral Movement** | Cross-host login & remote service abuse | 🔜 Planned |
| 🕵️ **Defense Evasion** | Log tampering & anti-forensics detection | 🔜 Planned |

---

## 📐 Key Findings Summary

### SOC-01 — SSH Invalid-User / Brute-Force Detection
```
source 192.168.122.97 → host monitor (agent 001)
loop {
    ssh login attempt as user "hacker"   // account does not exist
    → rule 5710 (level 5)                // invalid user
    → rule 5503                          // PAM login failed
}
threshold exceeded within window
    → rule 2502 (level 10)               // repeated password miss — ESCALATION
verdict: no "Accepted password" event   // attack failed, no breach
response: block srcip · enforce key auth · restrict SSH exposure · pivot on IP
```

---

## ⚠️ Disclaimer

All content in this repository is created **solely for defensive security research, detection engineering, and educational purposes** under the SafeTest-Dev SOC research framework.

- ✅ Alert artifacts are sanitized lab data — no production or personal data
- ✅ All techniques are documented for defensive understanding and incident response
- ❌ Do **not** use any documented attacker behavior against systems you do not own or have explicit authorization to test

---

## 👤 Author

**Michael.A** — SafeTest-Dev
Binary | Malware | Exploitation | Reverse | SOC | AI

---

*SafeTest-Dev © 2026 — All rights reserved*
