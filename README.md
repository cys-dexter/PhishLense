# PhishLense

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-CDN-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Creator](https://img.shields.io/badge/Creator-AHMAD-blueviolet?style=for-the-badge)](https://github.com/cys-dexter)
[![GitHub](https://img.shields.io/badge/GitHub-cys--dexter-181717?style=for-the-badge&logo=github)](https://github.com/cys-dexter/PhishLense)

**PhishLense** is a high-performance, lightweight web application designed for real-time suspicious URL analysis. Built with Python (FastAPI), modern HTML5, Tailwind CSS, and vanilla JavaScript, PhishLense disassembles complex web links into their foundational components, matches them against advanced heuristic threat indicators, and delivers clear, plain-English security explanations on a dark-mode dashboard.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Heuristics Engine & Detection Matrix](#heuristics-engine--detection-matrix)
- [UI/UX Architecture & Preview](#uiux-architecture--preview)
- [System Architecture](#system-architecture)
- [Repository Structure](#repository-structure)
- [Local Installation & Setup](#local-installation--setup)
- [Running with Uvicorn](#running-with-uvicorn)
- [API Reference & Usage](#api-reference--usage)
- [Author & Credits](#author--credits)
- [License](#license)

---

## Overview

Modern phishing attacks exploit visual deception, obscure domain structures, homoglyphs, and opaque redirects. Non-technical users and security teams need rapid, transparent visibility into the mechanics behind deceptive URLs without uploading sensitive internal indicators to centralized databases.

**PhishLense operates completely statelessly:**
- **Zero Database Requirement**: Instant execution with zero persistence or telemetry logging.
- **Microsecond Analysis**: Fast regex and string decomposition algorithms.
- **Human-Centric Output**: Transforms technical anomalies (Punycode, basic authentication delimiters, nested subdomains) into plain-English risk assessments.

---

## Key Features

- **Structural URL Dissection**: Extracts protocol, authority host, nested subdomains, registered domain, top-level domain (TLD), port, path, and query parameters complying with RFC 3986.
- **Color-Coded Severity Scoring**: Dynamic 0-100 score with tiered risk classifications (`SAFE`, `LOW RISK`, `SUSPICIOUS`, `DANGEROUS`).
- **Brand Mimicry Identification**: Detects brand names inserted into subdomains or paths when the authoritative domain is an untrusted third party.
- **Homoglyph & Punycode Detection**: Uncovers internationalized domain names (IDNs) exploiting lookalike characters (Cyrillic, Greek, Latin) to mimic trusted institutions.
- **Direct IP Host & Port Anomalies**: Flags raw IPv4, IPv6, hex/octal representations, and non-standard connection ports.
- **Syntax Abuse Interception**: Catches userinfo delimiter `@` redirect tricks and nested open redirect patterns.
- **One-Click Threat Samples**: Instant loading of real-world test scenarios directly from the UI.
- **Modern Dark-Mode Dashboard**: Sleek cyber-aesthetic with glassmorphism, responsive Tailwind design, and interactive DOM rendering.

---

## Heuristics Engine & Detection Matrix

PhishLense assesses incoming links against multi-layered security rules:

| Rule Identifier | Heuristic Category | Trigger Condition | Severity | Risk Impact | Plain-English Defense Explanation |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `RULE-IP-HOST` | Host Identification | Dotted decimal IPv4, IPv6, or hex address as host | **CRITICAL** | +40 | Attackers bypass domain registration verification and DNS filters by serving phishing portals directly from numerical IPs. |
| `RULE-AUTH-AT` | Syntax Deception | Presence of `@` symbol in authority or path | **CRITICAL** | +35 | The `@` delimiter instructs browsers to discard everything before it as login credentials and connect to the rogue domain that follows. |
| `RULE-IMPERSONATE-*` | Brand Spoofing | Recognized brand keyword in subdomain or path on foreign domain | **CRITICAL** | +35 | Displays a trusted brand name inside the subdomain to visually trick users while the real registered domain belongs to the adversary. |
| `RULE-HOMOGLYPH-IDN` | IDN Deception | Punycode prefix (`xn--`) or non-ASCII characters | **HIGH** | +25 | Uses lookalike characters from international alphabets that appear identical to Latin characters to impersonate legitimate domains. |
| `RULE-EXCESSIVE-HYPHENS`| Naming Patterns | Two or more hyphen characters in hostname | **HIGH** | +20 | Attackers chain words with hyphens (e.g., `secure-login-account-update`) because authentic single-word domains are unavailable. |
| `RULE-NONSTANDARD-PORT` | Network Configuration | Non-standard port specified (e.g., `:8080`, `:8443`) | **HIGH** | +20 | Threat actors host temporary credential harvesters on non-standard ports to bypass standard corporate proxies. |
| `RULE-OPEN-REDIRECT` | Navigation Manipulation | Double slash `//` or secondary nested protocol in path/query | **HIGH** | +20 | Chains redirects to bounce victims through a benign server before redirecting them to an exploit destination. |
| `RULE-CREDENTIAL-HARVEST`| Behavioral Lure | Dense clustering of keywords (`login`, `verify`, `banking`, `wallet`) | **HIGH / MED** | +10 to +20 | High concentration of urgent authentication terms indicates a targeted credential harvesting landing page. |
| `RULE-ABUSE-TLD` | Reputation Anomalies | Cataloged high-abuse top-level domains (`.xyz`, `.top`, `.tk`, etc.) | **MEDIUM** | +15 | Extensions with high rates of malicious registrations due to low prices and lax abuse enforcement. |
| `RULE-SHORTENER` | Destination Concealment | Recognized shortening service (`bit.ly`, `tinyurl.com`, `t.co`) | **MEDIUM** | +15 | Masks the final target domain, preventing users and basic filters from inspecting the true destination before clicking. |
| `RULE-DEEP-SUBDOMAIN` | Structural Obfuscation | Subdomain depth exceeding 2 nested levels | **MEDIUM** | +15 | Chains multiple subdomains to push the actual domain offscreen in mobile address bars. |
| `RULE-HEX-ENCODING` | Content Obfuscation | Four or more percent-encoded characters (`%XX`) | **MEDIUM** | +15 | Encodes characters to evade string filters while web browsers automatically decode them on render. |
| `RULE-INSECURE-HTTP` | Transport Security | Cleartext `http://` transmission protocol | **MEDIUM / HIGH** | +10 to +20 | Transmits traffic unencrypted, leaving passwords and personal data vulnerable to network interception. |
| `RULE-LENGTH-*` | Evasion Technique | Total URL length exceeds 75 or 120 characters | **LOW / HIGH** | +5 to +20 | Bloated URLs used to hide malicious arguments or push domains out of the visible browser viewport. |

---

## UI/UX Architecture & Preview

The dashboard layout offers a focused, distraction-free environment:

1. **Brand Bar**: Displays the PhishLense identity, version metadata, operational status badge, and author GitHub link.
2. **Analysis Input Hub**: Centered input bar supporting keyboard shortcuts (`Enter`), one-click clipboard paste, quick input clearance, and interactive scanning states.
3. **Quick Threat Presets**: Instant pills allowing users to test safe repositories, brand impersonation attacks, direct IP logins, Punycode homoglyphs, and shortened links with zero manual typing.
4. **Verdict Banner**: A high-contrast score card showing the numerical risk index (`0 - 100`), classification badge, and an executive verdict summary.
5. **Visual URL Dissection Bar**: A tokenized interactive view color-coding each URL element (Protocol in Cyan, Subdomain in Amber, Domain in Indigo, TLD in Purple, Port in Red, Path in Slate).
6. **Detailed Findings Grid**: Severity-coded cards detailing each triggered rule, category tag, score penalty, plain-English explanation, and technical context.
7. **Actionable Defense Checklist**: Concrete guidance specifying immediate safety measures.

---

## System Architecture

```
[ Client Browser / Frontend UI ]
               │
               ▼  HTTP REST (POST /api/v1/analyze)
┌────────────────────────────────────────────────────────┐
│ FastAPI Application Router (app/main.py, routes.py)   │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│ UrlAnalyzer Engine (app/core/analyzer.py)              │
│  ├─ Normalization & RFC 3986 Deconstruction           │
│  ├─ Component Label Extraction (Multi-part TLD aware) │
│  ├─ Heuristic Rule Assessment (app/core/heuristics.py) │
│  ├─ Risk Score Aggregation & Severity Normalization   │
│  └─ Plain-English Narrative & Recommendation Synthesis│
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
           [ JSON Response Payload ]
```

---

## Repository Structure

```
PhishLense/
├── app/
│   ├── __init__.py
│   ├── main.py              <- FastAPI application entrypoint and route mounting
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py        <- REST API endpoints (/analyze, /samples, /health)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py        <- Application configuration and runtime settings
│   │   ├── heuristics.py    <- Catalog of threat patterns, brands, TLDs, and regex
│   │   └── analyzer.py      <- Core parsing and heuristic evaluation engine
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py       <- Pydantic validation models and API contracts
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css    <- Cyber-aesthetic glow animations and custom scrollbars
│   │   └── js/
│   │       └── app.js       <- Vanilla JS asynchronous UI controller
│   └── templates/
│       └── index.html       <- Responsive dark-mode Tailwind CSS dashboard
├── requirements.txt         <- Production dependencies (FastAPI, Uvicorn, Pydantic)
├── run.py                   <- Local execution runner
└── README.md                <- Comprehensive project documentation
```

---

## Local Installation & Setup

### Prerequisites

- Python 3.10, 3.11, or 3.12
- Git
- Virtual environment tool (`venv`)

### Installation Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/cys-dexter/PhishLense.git
   cd PhishLense
   ```

2. **Create and Activate a Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

---

## Running with Uvicorn

### Method 1: Using the Runner Script

```bash
python run.py
```

### Method 2: Direct Uvicorn Command

For production deployment:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

For development with hot-reload enabled:
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Once running, navigate to:
- **Interactive UI**: `http://127.0.0.1:8000`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **ReDoc API Documentation**: `http://127.0.0.1:8000/redoc`

---

## API Reference & Usage

### 1. Inspect a URL

- **Endpoint**: `POST /api/v1/analyze`
- **Content-Type**: `application/json`

#### Example Request

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/analyze" \
     -H "Content-Type: application/json" \
     -d '{"url": "http://paypal.com.account-update.notice-security.xyz/login/verify.php"}'
```

#### Example Response (Truncated for readability)

```json
{
  "url": "http://paypal.com.account-update.notice-security.xyz/login/verify.php",
  "normalized_url": "http://paypal.com.account-update.notice-security.xyz/login/verify.php",
  "risk_score": 80,
  "risk_level": "DANGEROUS",
  "verdict_summary": "Extreme risk detected (Score: 80/100). This URL exhibits deceptive characteristics including Brand Mimicry: Paypal, High-Risk Top-Level Domain (.xyz). Engaging with this link is strongly inadvisable.",
  "components": {
    "raw_url": "http://paypal.com.account-update.notice-security.xyz/login/verify.php",
    "normalized_url": "http://paypal.com.account-update.notice-security.xyz/login/verify.php",
    "scheme": "http",
    "netloc": "paypal.com.account-update.notice-security.xyz",
    "hostname": "paypal.com.account-update.notice-security.xyz",
    "subdomain": "paypal.com.account-update",
    "domain": "notice-security",
    "registered_domain": "notice-security.xyz",
    "tld": "xyz",
    "port": null,
    "path": "/login/verify.php",
    "query": "",
    "fragment": "",
    "query_params": {},
    "is_ip_address": false
  },
  "severity_counts": {
    "critical": 1,
    "high": 0,
    "medium": 3,
    "low": 0,
    "info": 0
  },
  "findings": [
    {
      "rule_id": "RULE-IMPERSONATE-PAYPAL",
      "title": "Brand Mimicry: Paypal",
      "category": "Brand Spoofing",
      "severity": "CRITICAL",
      "score_impact": 35,
      "plain_english_explanation": "This address places the high-profile brand 'paypal' in its subdomain, but the authoritative domain actually belongs to 'notice-security.xyz'. Attackers do this to create a false sense of security.",
      "technical_detail": "Keyword 'paypal' detected in subdomain, but registered authority is 'notice-security.xyz' instead of genuine 'paypal.com'."
    },
    {
      "rule_id": "RULE-ABUSE-TLD",
      "title": "High-Risk Top-Level Domain (.xyz)",
      "category": "Reputation Anomalies",
      "severity": "MEDIUM",
      "score_impact": 15,
      "plain_english_explanation": "The domain ends with '.xyz', a top-level extension with historically disproportionate rates of spam, bulletproof hosting, and malicious registrations due to low registry oversight.",
      "technical_detail": "TLD '.xyz' is cataloged in cyber threat feeds for elevated abuse frequency."
    },
    {
      "rule_id": "RULE-CREDENTIAL-HARVEST-MED",
      "title": "Authentication Keyword on Non-Standard Domain",
      "category": "Behavioral Lure",
      "severity": "MEDIUM",
      "score_impact": 10,
      "plain_english_explanation": "The keyword 'login' appears in an address that already exhibits atypical infrastructure traits, indicating a potential fake login landing page.",
      "technical_detail": "Sensitive term 'login' coupled with secondary structural flags."
    },
    {
      "rule_id": "RULE-INSECURE-HTTP",
      "title": "Unencrypted Cleartext HTTP Protocol",
      "category": "Transport Security",
      "severity": "HIGH",
      "score_impact": 20,
      "plain_english_explanation": "This site communicates over plain, unencrypted HTTP rather than modern HTTPS. Any data, passwords, or personal details you type into this page can be intercepted or altered by anyone on the same network.",
      "technical_detail": "Scheme is http://. Modern commercial and authentication portals strictly enforce HTTPS."
    }
  ],
  "recommendations": [
    "DO NOT click or open this link in your web browser.",
    "Never enter usernames, passwords, or credit card details on this destination.",
    "If received via email, SMS, or direct message, mark the communication as phishing or spam.",
    "If you have already entered credentials on this site, immediately reset your password on the genuine official website."
  ],
  "scan_timestamp": "2026-10-14T15:08:45.123456+00:00"
}
```

### 2. Retrieve Sample Threat Scenarios

- **Endpoint**: `GET /api/v1/samples`
- **Output**: Array of curated sample links with expected risk levels and threat summaries.

### 3. Service Health Check

- **Endpoint**: `GET /api/v1/health`
- **Output**:
  ```json
  {
    "status": "healthy",
    "app_name": "PhishLense",
    "version": "1.0.0",
    "creator": "AHMAD",
    "github": "cys-dexter",
    "repository": "PhishLense"
  }
  ```

---

## Author & Credits

- **Creator & Lead Engineer**: AHMAD
- **GitHub**: [@cys-dexter](https://github.com/cys-dexter)
- **Project Repository**: [cys-dexter/PhishLense](https://github.com/cys-dexter/PhishLense)

---

## License

This project is licensed under the MIT License. You are free to inspect, modify, and distribute it in accordance with the license conditions.
