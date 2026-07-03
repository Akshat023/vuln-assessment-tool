# 🛡️ AI-Powered Website Vulnerability Assessment Tool

> An automated, AI-assisted security assessment platform that scans websites for vulnerabilities, classifies them by severity, and generates actionable reports powered by OWASP ZAP, Nuclei, and Groq AI.

---

## 📸 Demo

![Dashboard Screenshot](docs/dashboard.png)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Next.js Dashboard                         │
│         URL Submission · Results · History · Export          │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP
┌──────────────────────▼──────────────────────────────────────┐
│                  FastAPI Backend                              │
│         REST API · Input Validation · Auth                   │
└──────────────────────┬──────────────────────────────────────┘
                       │ Task Queue
┌──────────────────────▼──────────────────────────────────────┐
│              Celery + Redis (Async Queue)                     │
│         Scan jobs run in background · Non-blocking           │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                  Scan Orchestrator                            │
│      Coordinates all scanners · Merges · Deduplicates        │
└──┬──────────┬──────────┬──────────┬──────────┬─────────────┘
   │          │          │          │          │
 ZAP      Nuclei    Headers    SSL/TLS    Tech Fingerprint
                                            + NVD CVE Lookup
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              CVSS Scoring + OWASP Top 10 Mapping             │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│           Groq AI Analysis (Llama 3.3 70B)                   │
│   Remediation · Business Impact · Executive Summary          │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              Report Generation + PostgreSQL                   │
│              PDF · Excel · Persistent History                │
└─────────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

| Feature | Description |
|---|---|
| **Multi-engine scanning** | OWASP ZAP, Nuclei, custom Header/SSL/Tech scanners running in parallel |
| **AI enrichment** | Groq AI (Llama 3.3 70B) generates remediation guidance and business impact per finding |
| **OWASP Top 10 mapping** | Every finding tagged to its OWASP 2021 category |
| **CVSS scoring** | Industry-standard severity scores, not AI-determined |
| **Async pipeline** | Celery + Redis queue — submit URL, get results when ready, no blocking |
| **Persistent history** | PostgreSQL stores all scans across sessions |
| **PDF reports** | Professional multi-page report with cover page, executive summary, findings table |
| **Excel reports** | 3-sheet workbook with findings, remediation checklist, executive summary |
| **Dashboard** | Real-time scan progress, expandable findings, scan history |

---

## 🔍 Scanning Modules

### 1. OWASP ZAP (Active Scanner)
- SQL Injection, XSS (Reflected, Stored, DOM), CSRF
- Path Traversal, Remote Code Execution
- Authentication bypass, Security misconfigurations
- Directory browsing, Information disclosure

### 2. Nuclei (Template-Based Scanner)
- Known CVE detection across 9000+ templates
- Exposed files (`.env`, `.git`, backup files)
- Default credentials, exposed admin panels
- Misconfiguration detection

### 3. HTTP Header Scanner (Passive)
- Missing Content-Security-Policy
- Missing X-Frame-Options (Clickjacking)
- Missing HSTS, Referrer-Policy, Permissions-Policy
- Dangerous headers (Server version disclosure, X-Powered-By)

### 4. SSL/TLS Scanner (Passive)
- Certificate validity and expiry
- Weak protocol versions (TLS 1.0/1.1)
- Missing HSTS header
- HTTP-only site detection

### 5. Technology Fingerprinter (Passive)
- Web server detection (Apache, Nginx, IIS)
- CMS detection (WordPress, Drupal, Joomla)
- Framework detection (Laravel, Django, Express, ASP.NET)
- JS library detection (jQuery, React, Angular, Vue)

### 6. NVD/CVE Lookup
- Cross-references detected software versions against NVD database
- Returns real CVE IDs with CVSS scores
- Powered by NIST NVD REST API v2 (free, no key required)

---

## 🧠 AI Layer Design

> **Key principle: CVSS scores decide severity. AI explains it.**

The AI layer (Groq API, Llama 3.3 70B) runs **after** scanning is complete and does three jobs:

1. **Remediation guidance** — specific, actionable fix per finding (not generic advice)
2. **Business impact** — one sentence explaining real-world consequence per finding
3. **Executive summary** — 3-4 paragraph non-technical narrative for stakeholders

Prompts return structured JSON — no free-form text parsing.

---

## 🗂️ Project Structure

```
vuln-assessment-tool/
├── api/
│   ├── main.py              # FastAPI endpoints
│   ├── models.py            # Pydantic schemas
│   ├── tasks.py             # Scan store (PostgreSQL-backed)
│   ├── celery_app.py        # Celery configuration
│   └── celery_tasks.py      # Background scan task
├── scanner/
│   ├── orchestrator.py      # Coordinates all scanners
│   └── modules/
│       ├── zap_scanner.py        # OWASP ZAP wrapper
│       ├── nuclei_scanner.py     # Nuclei CLI wrapper
│       ├── header_scanner.py     # HTTP header checks
│       ├── ssl_scanner.py        # SSL/TLS analysis
│       ├── tech_fingerprinter.py # Technology detection
│       └── nvd_lookup.py         # CVE/NVD API lookup
├── ai/
│   └── analyzer.py          # Groq AI enrichment
├── reports/
│   ├── pdf_generator.py     # PDF via xhtml2pdf
│   └── excel_generator.py   # Excel via OpenPyXL
├── db/
│   ├── models.py            # SQLAlchemy ORM models
│   ├── database.py          # PostgreSQL connection
│   └── scan_store.py        # PostgresScanStore interface
├── frontend/                # Next.js dashboard
├── docker-compose.yml       # Full stack orchestration
├── Dockerfile.api           # API + Celery image
└── Dockerfile.frontend      # Next.js image
```

---

## 🚀 Quick Start

### Prerequisites
- Docker Desktop installed and running
- Git

### 1. Clone the repository
```bash
git clone https://github.com/Akshat023/vuln-assessment-tool.git
cd vuln-assessment-tool
```

### 2. Set up environment variables
```bash
cp .env.example .env
```
Edit `.env` and add your Groq API key:
```
GROQ_API_KEY=your_groq_api_key_here
```
Get a free key at: https://console.groq.com

### 3. Start everything with one command
```bash
docker-compose up
```

This starts:
- PostgreSQL (port 5432)
- Redis (port 6379)
- OWASP ZAP (port 8080)
- DVWA test target (port 8888)
- FastAPI backend (port 8000)
- Celery worker
- Next.js dashboard (port 3000)

### 4. Open the dashboard
```
http://localhost:3000
```

### 5. Run your first scan
Enter `http://vuln_dvwa` in the URL field and click **Start Scan**.

The scan takes 3-5 minutes. When complete you'll see:
- Severity summary (Critical / High / Medium / Low counts)
- AI-generated executive summary
- Full findings table with expandable rows
- PDF and Excel download buttons

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/scans` | Submit URL for scanning |
| `GET` | `/scans/{scan_id}` | Poll scan status and results |
| `GET` | `/scans` | List all scan history |
| `GET` | `/scans/{scan_id}/report/pdf` | Download PDF report |
| `GET` | `/scans/{scan_id}/report/excel` | Download Excel report |
| `DELETE` | `/scans/{scan_id}` | Delete a scan |

Interactive API docs: `http://localhost:8000/docs`

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15, TypeScript, Tailwind CSS |
| Backend | Python, FastAPI |
| Task Queue | Celery + Redis |
| Database | PostgreSQL + SQLAlchemy |
| Scanners | OWASP ZAP, Nuclei, Custom Python modules |
| AI | Groq API (Llama 3.3 70B) |
| Reports | xhtml2pdf, OpenPyXL |
| Container | Docker, Docker Compose |

---

## ⚠️ Legal & Ethical Notice

**Only scan websites you own or have explicit written permission to test.**

This tool is intended for:
- Security assessment of your own applications
- Authorized penetration testing engagements
- Educational purposes on deliberately vulnerable targets (DVWA, WebGoat)

Scanning systems without authorization is illegal. The tool logs all scans with timestamp for audit purposes.

---

## 🗺️ Roadmap

- [ ] Scheduled recurring scans with email alerts
- [ ] Multi-tenant support with user authentication
- [ ] Cloud deployment (Render + Vercel)
- [ ] Domain ownership verification before scanning
- [ ] Slack/Teams integration for alerts
- [ ] CVE intelligence feed integration

---

## 👨‍💻 Author

**Akshat** — B.Tech 2027, AI/ML & Full-Stack Development

Built as an internship project demonstrating applied AI, cybersecurity tooling, and production-grade software architecture.

- GitHub: [@Akshat023](https://github.com/Akshat023)
- Project: [vuln-assessment-tool](https://github.com/Akshat023/vuln-assessment-tool)