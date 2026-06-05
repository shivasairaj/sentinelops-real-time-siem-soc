# SentinelOPS – Real-Time SIEM & SOC Dashboard

![Cybersecurity](https://img.shields.io/badge/Cybersecurity-SIEM-blue)
![Wazuh](https://img.shields.io/badge/Wazuh-4.7-green)
![Python](https://img.shields.io/badge/Python-3.11-yellow)
![Flask](https://img.shields.io/badge/Flask-API-red)
![Status](https://img.shields.io/badge/Status-Active-success)

## Overview

SentinelOPS is a real-time Security Information and Event Management (SIEM) and Security Operations Center (SOC) monitoring platform built using Wazuh, Python Flask, Kali Linux, and Telegram integration.

The project demonstrates how modern security teams detect, analyze, and respond to cyber threats by implementing an end-to-end monitoring and alerting pipeline using real attack traffic instead of simulated data.

This project was developed as a hands-on cybersecurity lab to understand SIEM architecture, threat detection, log analysis, and incident response workflows.

---

## Key Features

* Real-time attack detection using Wazuh
* SSH brute-force attack monitoring
* Live security event processing
* Python Flask REST API
* Real-time alert generation
* Telegram mobile notifications
* MITRE ATT&CK mapped detections
* Multi-VM cybersecurity lab environment
* Security event visualization

---

## Architecture

```text
Attacker (Kali Linux)
        │
        ▼
SSH Brute Force / Nmap Scan
        │
        ▼
Ubuntu Server
        │
        ▼
Wazuh SIEM
(Log Collection & Analysis)
        │
        ▼
alerts.json
        │
 ┌──────┴──────┐
 ▼             ▼

Flask API      Telegram Alerter
 ▼             ▼

Dashboard      Mobile Alerts
```
<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/799cba6e-ea1a-4872-a807-e2c4d7049cac" />

---

## Technology Stack

### Security

* Wazuh SIEM
* Hydra
* Nmap

### Backend

* Python 3
* Flask
* Flask-CORS
* Requests

### Infrastructure

* Ubuntu Server
* Kali Linux
* VirtualBox

### Alerting

* Telegram Bot API

---

## Demonstration

The project demonstrates the following workflow:

1. Attack launched from Kali Linux
2. SSH brute-force attempts generated
3. Ubuntu server logs authentication failures
4. Wazuh detects suspicious activity
5. Security alerts generated
6. Flask API processes alert data
7. Telegram alert sent to mobile device
8. Security events displayed on dashboard

---

## Sample Detection Workflow

```text
Hydra Attack
     │
     ▼
Failed SSH Logins
     │
     ▼
Wazuh Rule Triggered
     │
     ▼
Security Alert Generated
     │
     ▼
Telegram Notification

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/d021ed38-210a-47df-9ffc-46233f50b6c3" />

```

---

## MITRE ATT&CK Coverage

| Technique | Description               |
| --------- | ------------------------- |
| T1110.001 | Password Guessing         |
| T1046     | Network Service Discovery |
| T1078     | Valid Accounts Detection  |
| T1548.003 | Sudo and Sudo Caching     |

---

## Screenshots

### Wazuh Security Events

<img width="956" height="569" alt="Screenshot 2026-03-24 012036" src="https://github.com/user-attachments/assets/a155ff1a-580a-4f7d-9659-002e25428b90" />


### Real-Time Alerts

<img width="959" height="570" alt="Screenshot 2026-03-24 121338" src="https://github.com/user-attachments/assets/dd0bc68c-6300-4e9e-bbc9-24ed2f2aaefc" />


---

## Installation

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/SentinelOPS-Real-Time-SIEM-SOC-Dashboard.git
cd SentinelOPS-Real-Time-SIEM-SOC-Dashboard
```

### Install Dependencies

```bash
pip install flask flask-cors requests
```

### Start API

```bash
python3 backend/api.py
```

### Start Telegram Alerter

```bash
python3 backend/alerter.py
```

---

## Attack Simulation

### SSH Brute Force

```bash
hydra -l username -P /usr/share/wordlists/rockyou.txt ssh://TARGET_IP
```

### Port Scan

```bash
nmap -sS -p 1-1024 TARGET_IP
```

---

## Lessons Learned

This project provided practical experience with:

* SIEM deployment
* Log analysis
* Security monitoring
* Incident detection
* Threat hunting fundamentals
* Virtual networking
* Linux administration
* Security automation
* Alert engineering

---

## Future Improvements

* AI-based anomaly detection
* Automated IP blocking
* Email alerting
* Cloud deployment
* Threat intelligence integration
* Advanced correlation engine
* Interactive SOC dashboard
* Multi-user support

---

## YouTube Demonstration

Video:
https://youtu.be/4ggKs061MCs?si=xeQEoFLXe6hOA-SU

---

## Author

Shivasairaj

Cybersecurity Student | Linux Enthusiast | SOC & Security Engineering Learner

Building practical cybersecurity projects and documenting the journey publicly.

---

## Disclaimer

This project is intended for educational and research purposes only.

All attack simulations were performed within a controlled lab environment owned and operated by the author.
