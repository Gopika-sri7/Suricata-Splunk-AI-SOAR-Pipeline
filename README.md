🛡️ SOC Alert Investigation \& Automated Response Dashboard





An end-to-end Security Operations Center (SOC) automation pipeline that detects, analyzes, and responds to security alerts using Suricata, Splunk, Python, and AI-based enrichment.









📖 Overview



In a real SOC environment, analysts spend 15–20 minutes per alert — reading raw logs, identifying attack types, assessing severity, and deciding on a response. This project compresses that process to a few seconds by automating the analysis while keeping a human in control of every response action.



The system ingests alerts from a Suricata IDS, enriches them using an AI model (with a local fallback engine), presents findings through a Streamlit dashboard, and optionally executes firewall rules upon analyst approval.





🏗️ Architecture



\[Suricata IDS]

&#x20;     │

&#x20;     ▼

\[Splunk SIEM]          ← Collects, indexes, and stores alert logs

&#x20;     │

&#x20;     ▼

\[Python / Streamlit]   ← Fetches alerts, extracts key fields

&#x20;     │

&#x20;     ├──► \[AI Enrichment]     ← MITRE mapping, severity score, recommended actions

&#x20;     └──► \[Fallback Engine]   ← Rule-based classifier if AI is unavailable

&#x20;               │

&#x20;               ▼

&#x20;     \[Analyst Dashboard]      ← Human reviews findings and approves actions

&#x20;               │

&#x20;               ▼

&#x20;     \[Firewall Response]      ← Optional IP block via Windows Firewall (netsh)

&#x20;               │

&#x20;               ▼

&#x20;       \[Audit Log]            ← All actions recorded for review





## ✨ Features

| Feature | Description |
|--------|-------------|
| 🔍 Alert Enrichment | Extracts IPs and attack signatures from Suricata logs |
| 🗺️ MITRE Mapping | Maps alerts to ATT&CK tactics and techniques |
| 📊 Severity Scoring | Generates severity score (1–10) |
| 🔁 Fallback Engine | Rule-based system when AI fails |
| 👨‍💻 Human Control | Analyst approves all actions |
| 🔥 Firewall Integration | Blocks IP using Windows Firewall (netsh) |
| 📋 Audit Trail | Logs all actions with timestamp |



## 🧱 Tech Stack

| Layer | Technology |
|------|------------|
| Network Detection | Suricata IDS |
| SIEM | Splunk |
| Backend | Python 3.8+ |
| Dashboard | Streamlit |
| AI Enrichment | Gemini / Claude API |
| Firewall Control | Windows Firewall (netsh) |



## ⚙️ Prerequisites

Before running this project, ensure you have the following installed and configured:

- Python 3.8 or higher  
- Suricata IDS (generating `eve.json` or `fast.log`)  
- Splunk (with a Suricata log source configured)  
- A valid Google Gemini or Anthropic Claude API key  
- Windows OS (for firewall response feature)





## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/your-username/soc-alert-dashboard.git
cd soc-alert-dashboard
```

### 2. Install dependencies

```bash
pip install streamlit splunk-sdk google-genai
```

### 3. Set environment variables

#### Windows (Command Prompt)

```cmd
set SPLUNK_HOST=localhost
set SPLUNK_PORT=8089
set SPLUNK_USERNAME=admin
set SPLUNK_PASSWORD=your_password
set GEMINI_API_KEY=your_api_key
```

#### Windows (PowerShell)

```powershell
$env:SPLUNK_HOST = "localhost"
$env:SPLUNK_PORT = "8089"
$env:SPLUNK_USERNAME = "admin"
$env:SPLUNK_PASSWORD = "your_password"
$env:GEMINI_API_KEY = "your_api_key"
```

### 4. Run the dashboard

```bash
streamlit run app.py
```

### 5. Open in your browser

```text
http://localhost:8501
```

---

## 🔄 Pipeline Walkthrough

### Step 1 — Detection

Suricata monitors network traffic and writes alerts (e.g., SSH brute force, port scans) to `eve.json`.

### Step 2 — Ingestion

Splunk indexes the Suricata logs and makes them queryable.

### Step 3 — Fetching

The Python application queries Splunk for the latest alert and extracts:

* Source IP
* Target IP
* Attack signature

### Step 4 — Enrichment

The AI model analyzes the alert and returns:

* MITRE ATT&CK mapping
* Severity score
* Recommended response actions

If the AI service is unavailable, the local fallback engine classifies the threat using predefined signature rules.

### Step 5 — Review

The analyst reviews the enriched alert in the Streamlit dashboard and decides whether to:

* Block
* Monitor
* Dismiss

### Step 6 — Response

If approved, the system executes a `netsh` command to block the attacker IP and records the action in the audit log.

## 🧠 What This Project Demonstrates

### Security Concepts

* SOC workflow understanding and alert triage
* SIEM + IDS integration (Splunk + Suricata)
* AI-based security alert enrichment and analysis
* Incident response automation with human oversight

### Engineering Concepts

* Fault-tolerant design using a rule-based fallback engine
* Secure command execution
* Audit logging and tracking
* End-to-end security pipeline design

---

## ⚠️ Disclaimer

This project is built for educational and portfolio purposes to simulate a SOC environment. It is not intended for production use.

### Important Notes

* Always review AI-generated analysis before taking action.
* Never block an IP address without verifying the alert.
* Firewall commands require administrative privileges.
* Tested on Windows environments.
* Linux firewall integration (`iptables` / `ufw`) is not currently implemented.

---

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
