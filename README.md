# SOC Phishing Email Investigation

### Phishing Email Investigation & Threat Intelligence Platform

This is a Python-based phishing email investigation tool designed to help security analysts analyze suspicious emails, extract indicators of compromise (IOCs), investigate URLs and email authentication information, enrich indicators using VirusTotal, and generate a risk assessment/report.

The project demonstrates a practical SOC-style workflow for phishing email triage and investigation.

---

## 🔍 Project Overview

Phishing emails are one of the most common attack vectors used to steal credentials, deliver malware, and compromise organizations.

Manually investigating suspicious emails can involve checking:

- Email headers
- Sender information
- Authentication results
- URLs
- Domains
- IP addresses
- Suspicious indicators
- Threat intelligence sources
- Overall risk

This project brings several of these investigation steps together into a single workflow.

```text
                    .EML FILE
                        │
                        ▼
                 Email Parser
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
     Headers           Body          Attachments
        │               │                │
        │               ▼                ▼
        │             URLs          SHA-256 Hash
        │               │                │
        │               ▼                ▼
        │          VirusTotal      Extension Check
        │                                │
        │                         Double Extension
        │                                │
        └───────────────┬────────────────┘
                        ▼
               SPF / DKIM / DMARC
                        │
                        ▼
                 Risk Engine
                        │
                        ▼
             Risk Score + Findings
