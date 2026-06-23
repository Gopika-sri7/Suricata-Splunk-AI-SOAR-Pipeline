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




🧱 Tech Stack



LayerTechnologyNetwork DetectionSuricata IDSLog ManagementSplunkBackendPython 3.8+Dashboard UIStreamlitAI EnrichmentGoogle Gemini / Claude APIFirewall ControlWindows Firewall (netsh)





⚙️ Prerequisites



Before running this project, ensure you have the following installed and configured:





Python 3.8 or higher

Suricata IDS (generating eve.json or fast.log)

Splunk (with a Suricata log source configured)

A valid Google Gemini or Anthropic Claude API key

Windows OS (for firewall response feature)







🚀 Quick Start



1\. Clone the repository



bashgit clone https://github.com/your-username/soc-alert-dashboard.git

cd soc-alert-dashboard



2\. Install dependencies



bashpip install streamlit splunk-sdk google-genai



3\. Set environment variables



Windows (Command Prompt):



cmdset SPLUNK\_HOST=localhost

set SPLUNK\_PORT=8089

set SPLUNK\_USERNAME=admin

set SPLUNK\_PASSWORD=your\_password

set GEMINI\_API\_KEY=your\_api\_key



Windows (PowerShell):



powershell$env:SPLUNK\_HOST = "localhost"

$env:SPLUNK\_PORT = "8089"

$env:SPLUNK\_USERNAME = "admin"

$env:SPLUNK\_PASSWORD = "your\_password"

$env:GEMINI\_API\_KEY = "your\_api\_key"



4\. Run the dashboard



bashstreamlit run app.py



5\. Open in your browser



http://localhost:8501





🔄 Pipeline Walkthrough



Step 1 — Detection: Suricata monitors network traffic and writes alerts (e.g., SSH brute force, port scans) to eve.json.



Step 2 — Ingestion: Splunk indexes the Suricata logs and makes them queryable.



Step 3 — Fetching: The Python app queries Splunk for the latest alert and extracts source IP, target IP, and attack signature.



Step 4 — Enrichment: The AI model analyzes the alert and returns a MITRE ATT\&CK mapping, severity score, and recommended actions. If the AI service is unavailable, the local fallback engine classifies the threat using predefined signature rules.



Step 5 — Review: The analyst sees the enriched alert on the Streamlit dashboard and decides whether to block, monitor, or dismiss.



Step 6 — Response: If approved, the system runs a netsh command to block the attacker IP and records the action in the audit log.





🧠 What This Project Demonstrates





SOC workflow understanding and alert triage process

SIEM + IDS integration (Splunk + Suricata)

AI-based security alert enrichment and analysis

Fault-tolerant design with a rule-based fallback engine

Incident response automation with human oversight

Secure command execution and audit logging







⚠️ Disclaimer



This is a learning project built to simulate a SOC environment. It is not intended for production use.





Always review AI-generated analysis before taking any action

Never block an IP address without verifying the alert

Firewall commands require administrative privileges — use responsibly

Tested on Windows; Linux firewall integration (iptables/ufw) is not yet implemented







📄 License



This project is licensed under the MIT License. See LICENSE for details.

