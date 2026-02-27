# 🛡 SOC Lab – SSH Brute-Force Detection

## 📌 Project Overview

This project simulates a Security Operations Center (SOC) detection workflow by analyzing SSH authentication logs to identify potential brute-force attacks.

The script parses system log files, detects failed login attempts, correlates them with successful logins, and assigns a risk level based on observed behavior.

---

## 🎯 Objectives

- Simulate SOC-style log monitoring
- Detect SSH brute-force attempts
- Correlate failed and successful login events
- Classify risk severity (LOW / MEDIUM / HIGH / CRITICAL)
- Map detected behavior to MITRE ATT&CK framework
- Generate structured security alerts

---

## 🧠 Detection Logic

The tool performs the following steps:

1. Parse authentication logs (`auth.log`)
2. Count failed login attempts per IP address
3. Detect successful login attempts
4. Correlate:
   - Multiple failed attempts
   - Followed by successful login
5. Assign risk levels:
   - LOW → 1 failed attempt
   - MEDIUM → 2 failed attempts
   - HIGH → 3+ failed attempts
   - CRITICAL → 3+ failed attempts + successful login
6. Generate alert if risk ≥ HIGH

---

## 🚨 Example Output


========== SOC ALERT REPORT ==========

IP Address: 192.168.1.50
Failed Attempts: 3
Successful Logins: 1
Risk Level: CRITICAL
🚨 ALERT: Potential brute-force attack detected!


---

## 🗂 Project Structure


SOC-Lab-BruteForce-Detection/
│
├── sample_logs/
│ └── auth.log
│
├── parser.py
├── mitre_mapping.md
├── incident_report.md
└── README.md


---

## 🔐 MITRE ATT&CK Mapping

| Tactic             | Technique   | ID    |
|--------------------|-------------|-------|
| Credential Access  | Brute Force | T1110 |

**Description:**  
Multiple failed SSH authentication attempts followed by a successful login may indicate brute-force credential compromise.

---

## 🛠 Technologies Used

- Python 3
- Regular Expressions (re)
- Collections (defaultdict)
- Log analysis methodology
- MITRE ATT&CK framework

---

## 📈 Skills Demonstrated

- Log parsing and event correlation
- Security detection engineering
- Risk classification logic
- Incident documentation
- Threat intelligence mapping
- Cybersecurity analytical thinking

---

## 🚀 Future Improvements

- Export alerts to CSV
- Time-window based detection
- JSON output for SIEM integration
- Add support for multiple attack types
- Build web-based dashboard visualization

---

## 👨‍💻 Author

Cybersecurity Management MSc student focused on:

- Security Operations
- Application Security
- Risk Management
- Detection Engineering