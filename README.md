# 🛡️ AI Log Analytics — Intrusion Detection System

An **AI-driven cybersecurity log analytics platform** that analyzes authentication, application, and network logs to detect abnormal behavior and cyberattacks using **Machine Learning and rule-based detection**.

## 🎯 Key Features

* AI/ML-based anomaly and attack detection
* Multi-source security log analysis
* Behavioral analysis and event correlation
* Risk scoring and threat categorization
* Real-time security alerts and monitoring
* MITRE ATT&CK mapping
* WebSocket-based live updates
* NSL-KDD dataset integration

## 🔍 Attack Types

**ML-Based**

* DoS
* Port Scanning
* Brute Force

**Rule-Based**

* IP Spoofing
* Session Hijacking
* DNS Spoofing
* ARP Spoofing
* MITM

## 🏗️ Project Structure

```text
AI-Log-Analytics-Intrusion-Detection/
├── backend_final/     # FastAPI + ML + detection modules
├── frontend_final/    # HTML + CSS + JavaScript dashboard
├── .gitignore
└── README.md
```

## ⚙️ Technologies

**Python • FastAPI • Machine Learning • HTML • CSS • JavaScript • SQLite • WebSocket • GitHub**

## 🚀 Quick Start

### Backend

```bash
cd backend_final
pip install -r requirements.txt
uvicorn backend.app.main:app --reload --port 8000
```

API Documentation:

```text
http://localhost:8000/docs
```

### Frontend

Open a new terminal:

```bash
cd frontend_final
python -m http.server 8080
```

Open:

```text
http://localhost:8080/login.html
```

**Demo Login:** `admin / admin123`

## 📊 Dataset

The project uses the **NSL-KDD dataset** along with authentication, application, and network log datasets.

## 🧪 Testing

```bash
cd backend_final
pytest
```

**43 backend tests** are included.

## 👨‍💻 Authors

**Hemalatha A** — Assistant Professor
Department of Artificial Intelligence
Rathinam Global Deemed to be University, Coimbatore

**Mahalingam R** — M.Sc. Data Science and Business Analysis
Rathinam Global Deemed to be University, Coimbatore

## 📌 Project Focus

**Artificial Intelligence • Machine Learning • Cybersecurity • Intrusion Detection • Log Analytics**
