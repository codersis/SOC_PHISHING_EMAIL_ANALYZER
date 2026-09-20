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

```text
```

## 🔍 Key Features

### 📧 1. Email Parsing & Header Analysis

The application accepts `.eml` email files and extracts relevant information for investigation.

The parser analyzes:

- Sender address
- Recipient address
- Subject
- Reply-To address
- Email headers
- Return-Path
- Email body
- Received headers
- Attachments
- URLs contained in the email

This provides the initial evidence required for further investigation.

---

### 🔐 2. SPF / DKIM / DMARC Analysis

The project analyzes email authentication results including:

- **SPF — Sender Policy Framework**
- **DKIM — DomainKeys Identified Mail**
- **DMARC — Domain-based Message Authentication, Reporting and Conformance**

These results are treated as **investigation signals**, not as definitive proof that an email is malicious or legitimate.

For example:

```text
SPF   → PASS
DKIM  → PASS
DMARC → PASS
```

does not automatically mean that the email is safe.

Similarly:

```text
SPF   → FAIL
DKIM  → FAIL
DMARC → FAIL
```

does not automatically prove that the email is malicious.

The authentication results are therefore considered together with other investigation evidence.

---

### 👤 3. Sender & Reply-To Analysis

The application examines sender-related information and can identify inconsistencies between email addresses.

For example:

```text
From:
support@example.com

Reply-To:
attacker@malicious-domain.com
```

A mismatch between sender-related fields can be treated as a suspicious signal during investigation.

The project can also examine information such as:

- From
- Reply-To
- Return-Path
- Sender
- Recipient

These fields provide useful context for email-header investigation.

---

### 🔗 4. IOC Extraction

The project extracts potentially relevant **Indicators of Compromise (IOCs)** from the email.

These may include:

- URLs
- Domains
- IP addresses
- Email addresses

The extracted indicators can then be passed to additional analysis and threat-intelligence modules.

Example:

```text
Email Body
    │
    ├── URL
    ├── Domain
    └── IP Address
```

---

### 🌐 5. URL Analysis

URLs found inside the email are extracted and analyzed.

The application can submit relevant URLs to VirusTotal for reputation and threat-intelligence information.

Example workflow:

```text
Email Body
     │
     ▼
URL Extraction
     │
     ▼
URL Analysis
     │
     ▼
VirusTotal Lookup
     │
     ▼
Threat Intelligence Result
```

URL analysis can provide additional evidence when determining the risk associated with a suspicious email.

---

### 🌍 6. Domain & IP Investigation

Domains and IP addresses extracted from emails can also be investigated through threat-intelligence lookups.

The project uses these indicators as additional evidence rather than treating reputation results as absolute verdicts.

Example:

```text
Suspicious URL
      │
      ▼
Extract Domain / IP
      │
      ▼
Threat Intelligence Lookup
      │
      ▼
Investigation Evidence
```

---

## ⚠️ Limitations

The current version is a **rule-based phishing email investigation and triage tool**.

It does not guarantee that an email is malicious or legitimate.

### Important Limitations

- SPF, DKIM, and DMARC results can be affected by email forwarding and email infrastructure.

- VirusTotal results represent threat-intelligence evidence and do not guarantee that an email is malicious or safe.

- Previously unseen malicious URLs or files may have little or no reputation data.

- Heuristic rules can produce false positives and false negatives.

- The current version has primarily been tested using controlled/sample phishing emails.

- Final investigation decisions should include analyst review and contextual evidence.

- Threat intelligence is dependent on the availability and coverage of external reputation databases.


## 👨‍💻 Author

### Akanksha Gupta

**Cybersecurity | SOC | Threat Detection | Security Automation**
