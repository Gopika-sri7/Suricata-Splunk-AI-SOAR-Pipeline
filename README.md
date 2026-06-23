# SOC Alert Investigation & Automated Response Dashboard

A Security Operations Center (SOC) automation project that integrates Suricata IDS, Splunk SIEM, AI-powered threat enrichment, and analyst-approved response actions to accelerate alert investigation and incident response.

## Data Flow

```text
Suricata IDS
      │
      ▼
Splunk SIEM
      │
      ▼
Python Streamlit Dashboard
      │
      ├──► Gemini AI Analysis
      └──► Local Fallback Engine
      │
      ▼
Analyst Review
      │
      ▼
Windows Firewall Response
      │
      ▼
Audit Log
```

## Project Overview

In a traditional SOC environment, analysts spend significant time reviewing alerts, identifying attack patterns, assessing severity, and determining response actions.

This project automates alert enrichment by retrieving alerts from Splunk, analyzing them using AI, mapping them to MITRE ATT&CK techniques, assigning severity scores, and presenting findings through an interactive Streamlit dashboard.

Response actions remain analyst-controlled to ensure safe and responsible incident handling.

## Pipeline Stages

| Stage | Component         | Purpose                                                         |
| ----- | ----------------- | --------------------------------------------------------------- |
| 1     | Detection         | Suricata detects suspicious network activity                    |
| 2     | Ingestion         | Splunk collects and indexes security alerts                     |
| 3     | Parsing           | Python extracts source IP, destination IP, and alert signatures |
| 4     | Enrichment        | Gemini AI generates threat analysis and severity scoring        |
| 5     | Fallback Analysis | Local rule engine activates if AI is unavailable                |
| 6     | Review            | Analyst reviews findings and recommended actions                |
| 7     | Response          | Optional firewall containment using Windows Firewall            |
| 8     | Audit             | Response actions are recorded for tracking                      |

## Key Features

* Automated alert enrichment
* MITRE ATT&CK mapping
* Threat severity scoring
* AI-assisted threat analysis
* Local fallback engine for resilience
* Human-in-the-loop approval workflow
* Automated firewall containment
* Audit logging and action tracking

## Technology Stack

| Component        | Technology               |
| ---------------- | ------------------------ |
| IDS              | Suricata                 |
| SIEM             | Splunk                   |
| Backend          | Python                   |
| Dashboard        | Streamlit                |
| AI Enrichment    | Google Gemini API        |
| Response Engine  | Windows Firewall (netsh) |
| Threat Framework | MITRE ATT&CK             |

## Response Logic

The system analyzes each alert and generates:

* Threat classification
* MITRE ATT&CK mapping
* Severity score (1–10)
* Recommended response actions

If the AI service is unavailable, the fallback engine performs local rule-based analysis to ensure alert investigation continues without interruption.

## Skills Demonstrated

* SOC Alert Triage
* SIEM Integration
* IDS Monitoring
* Threat Intelligence Enrichment
* MITRE ATT&CK Mapping
* Incident Response Automation
* Python Security Automation
* Fault-Tolerant System Design
* Human-in-the-Loop Security Operations

## Author

**Gopika sri G.K**
B.E. Cyber Security (3rd Year)
SRM Madurai College for Engineering and Technology

Built as a portfolio project to demonstrate SOC operations, threat detection, alert enrichment, and incident response automation.
