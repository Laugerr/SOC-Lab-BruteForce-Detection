# 🛡️ SOC Lab – SSH Brute-Force Detection Engine

> A mini detection engineering project simulating how a real Security Operations Center (SOC) detects and classifies SSH brute-force attacks using time-window correlation and SIEM-style alerting.

---

## 🚀 Project Overview

This project simulates a real-world SOC detection workflow.

It analyzes SSH authentication logs (`auth.log`) to:

- 🔍 Detect brute-force login attempts  
- 🔁 Correlate failed attempts with successful logins  
- 📊 Classify risk levels (LOW → CRITICAL)  
- 📦 Export alerts in:
  - CSV (human-readable)
  - JSONL (SIEM-ready structured format)

This is not just log parsing —  
this is detection engineering logic.

---

## 🧠 Detection Strategy

Real brute-force detection is not:

> “3 failures = attack”

It is:

> “X failures within Y minutes”

This project implements:

- ⏱️ Time-window detection  
- 🔁 Event correlation (fail → success)  
- 🚨 Risk-based alerting  
- 🧾 Structured SIEM-style alert output  

---

## 🔍 Detection Logic

For each IP address:

1. Count total failed login attempts  
2. Detect maximum failures within a configurable time window  
3. Check for successful login after failures  
4. Assign risk level  

| Condition | Risk Level |
|------------|------------|
| 1 failed attempt | LOW |
| 2 failed attempts | MEDIUM |
| ≥ threshold failures in time window | HIGH |
| ≥ threshold failures + successful login | CRITICAL |

---

## 🖥 Example Console Output

```
========== SOC ALERT REPORT (Time-Window Detection) ==========

IP Address: 192.168.1.50
Total Failed Attempts: 3
Max Failed Attempts in 2 min window: 3
Successful Logins: 1
Risk Level: CRITICAL
🚨 ALERT: Brute-force pattern detected within time window!

📁 Alerts exported to alerts.csv
📄 Alerts exported to alerts.jsonl (JSONL)
```

---

## 🧾 Example SIEM-Style JSON Alert

```json
{
  "@timestamp": "2026-02-28T12:10:25.384920",
  "event": {
    "kind": "alert",
    "category": ["authentication"],
    "type": ["start"],
    "dataset": "soc_lab.ssh"
  },
  "rule": {
    "name": "SSH Brute Force (Time Window)",
    "threshold": 3,
    "window_minutes": 2
  },
  "source": {
    "ip": "192.168.1.50"
  },
  "ssh": {
    "failed_attempts_total": 3,
    "max_failed_attempts_in_window": 3,
    "successful_logins": 1
  },
  "severity": "CRITICAL",
  "message": "Brute-force pattern detected within time window"
}
```

This structured format is compatible with:

- Elastic / OpenSearch
- SIEM ingestion pipelines
- Log shippers
- Detection engineering workflows

---

## ⚙️ Usage

### ▶ Default Run

```bash
python3 parser.py
```

### ▶ Custom Threshold & Time Window

```bash
python3 parser.py --threshold 4 --window 3
```

### ▶ Custom Output Files

```bash
python3 parser.py --output alerts.csv --json alerts.jsonl
```

---

## 📂 Project Structure

```
SOC-Lab-BruteForce-Detection/
│
├── sample_logs/
│   └── auth.log
│
├── parser.py
├── README.md
└── .gitignore
```

Generated files (not committed):

- alerts.csv
- alerts.jsonl

---

## 🛠 Technologies Used

- Python 3
- argparse (CLI configuration)
- Regular Expressions (log parsing)
- datetime & timedelta (time-window logic)
- CSV module
- JSON module
- Detection engineering principles
- MITRE ATT&CK (T1110 – Brute Force)

---

## 🎯 Skills Demonstrated

- Log analysis  
- Detection rule design  
- Time-based attack correlation  
- Risk classification modeling  
- Structured alert generation  
- SIEM-ready output formatting  
- Clean documentation & engineering mindset  

---

## 🔐 MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|------------|------|
| Credential Access | Brute Force | T1110 |

This project simulates detection of SSH password brute-force attempts that may lead to credential compromise.

---

## 🏁 Version

**v1.0 – Stable Release**

Features included:

- Time-window brute-force detection
- Risk classification engine
- CSV export
- SIEM-style JSONL export
- CLI configuration

---

## 👨‍💻 About the Author

Cybersecurity Management MSc student focused on:

- Security Operations (SOC)
- Detection Engineering
- Application Security
- Risk & Threat Modeling

Building practical security tools while transitioning into IT security roles.