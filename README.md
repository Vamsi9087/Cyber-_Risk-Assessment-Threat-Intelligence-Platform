# 🛡️ CyberScan Pro

> **Professional Network Reconnaissance & Threat Intelligence Platform**  
> Built with Python · Streamlit · FastAPI · SQLite · VirusTotal API · Nmap

---

## 📌 What is CyberScan Pro?

CyberScan Pro is an end-to-end automated network security scanner that:
- Scans any IP/hostname using **Nmap** to discover open ports and running services
- Enriches every finding with **VirusTotal** threat intelligence
- Scores each finding using a **3-dimensional risk model** (Exposure + Threat + Context)
- Displays results on a **live Streamlit dashboard** with charts, tables, and filters
- Stores all scan history in a **local SQLite database**
- Sends **automated email alerts** with an HTML report and PDF attachment
- Exposes a **secured REST API** (FastAPI) for external integrations

---

## 🗂️ Project Structure

```
CyberScan Pro/
│
├── modules/
│   ├── scanner.py          # Nmap scanning + VirusTotal enrichment
│   ├── analyser.py         # 3D risk scoring engine
│   ├── database.py         # SQLite history store
│   └── emailer.py          # HTML email + PDF report generator
│
├── dashboard/
│   ├── app.py              # Main Streamlit app (scan trigger + home)
│   └── pages/
│       ├── 1_Overview.py       # Charts: severity, country, radar, gauges
│       ├── 2_Analysis.py       # Deep dive: scatter, heatmap, VT reports
│       ├── 3_History.py        # Scan history trends + drill-down
│       ├── 4_Settings.py       # Configure API keys and targets
│       ├── 5_Scan_Data.py      # Full findings table with filters
│       ├── 6_Host_Summary.py   # Per-host risk summary
│       ├── 8_Export.py         # Download PDF / CSV reports
│       └── 9_Email_Alert.py    # Send alert email manually
│
├── api.py                  # FastAPI REST API (authenticated + rate-limited)
├── scan_results/           # Raw Nmap XML output (auto-created)
├── reports/                # Generated PDF reports (auto-created)
├── cyberscan.db            # SQLite database (auto-created)
├── u.env                   # Environment variables (API keys, email config)
└── .streamlit/
    └── config.toml         # Dark theme configuration
```

---

## ⚙️ Modules — What Each File Does

| Module | File | Description |
|--------|------|-------------|
| **Scanner** | `modules/scanner.py` | Runs Nmap with `-Pn -sV -sC --open -p-`, parses XML output, queries VirusTotal API for each unique IP |
| **Analyser** | `modules/analyser.py` | Calculates 3-dimensional risk scores, assigns severity levels, generates key findings and recommendations |
| **Database** | `modules/database.py` | Saves scan results to SQLite, loads scan history, retrieves past scans by ID |
| **Emailer** | `modules/emailer.py` | Generates PDF reports using fpdf2, builds HTML email body, sends via Gmail SMTP with PDF attachment |
| **Dashboard** | `dashboard/app.py` | Main Streamlit UI — triggers scans, shows posture banner, host overview, runs email alert automatically |
| **API** | `api.py` | FastAPI REST service — load scan data, query results, get analysis summary, per-host lookup |

---

## 🔬 How the Risk Scoring Works

Each finding (IP + Port combination) is scored across **3 dimensions**:

### 1. Exposure Score (40% weight)
Based on how dangerous the service is if exposed to the internet.

| Service | Score |
|---------|-------|
| Telnet | 10 |
| RDP, SMB | 9 |
| FTP, VNC | 8 |
| MongoDB, Redis | 8 |
| MySQL, MSSQL | 7 |
| SSH | 3 |
| HTTP | 2 |
| HTTPS | 1 |

Dangerous ports (21, 23, 135, 445, 3389, 6379, 27017, etc.) get a base score of 6 if the service is unknown. Filtered ports are penalised by 50%.

### 2. Threat Score (40% weight)
Based on VirusTotal engine reports for the IP address.

```
Threat Score = (malicious_reports × 2.0) + (suspicious_count × 0.5)
               + community_penalty (if negative votes)
```

### 3. Context Score (20% weight)
Based on geolocation and threat category intelligence.

| Factor | Score Added |
|--------|-------------|
| High-risk country (CN, RU, KP, IR, NG, UA, VN, RO) | +3.0 |
| Malware category (VirusTotal) | +4.0 |
| Phishing category | +3.0 |
| Botnet category | +3.5 |
| Spam category | +2.0 |

### Final Risk Score
```
Risk Score = (Exposure × 0.40) + (Threat × 0.40) + (Context × 0.20)
```

### Severity Levels
| Score | Severity |
|-------|----------|
| ≥ 7.0 | 🔴 Critical |
| ≥ 5.0 | 🟠 High |
| ≥ 3.0 | 🟡 Medium |
| < 3.0 | 🟢 Low |

---

## 🖥️ Dashboard Pages

| Page | What It Shows |
|------|---------------|
| **Home** | Scan trigger, security posture banner, key findings, host overview table |
| **1 — Overview** | Severity bar chart, pie chart, country chart, score radar, risk histogram, treemap, host gauges |
| **2 — Analysis** | Exposure vs Threat scatter, risk by service, port frequency, VirusTotal bar chart, heatmap, top 10 risks |
| **3 — History** | All scans table, risk score evolution, hosts vs ports bubble chart, drill into past scan |
| **4 — Settings** | Update API keys, scan targets, email config for the session |
| **5 — Scan Data** | Full findings table with severity/service/IP filters, colour-coded severity, progress bars |
| **6 — Host Summary** | Per-host aggregated table — open ports, max risk, severity, country, categories, services |
| **8 — Export** | Generate and download PDF report, full CSV, host summary CSV |
| **9 — Email Alert** | Send HTML email + PDF to any recipient, live field validation, debug info |

---

## 🔌 REST API Endpoints

The FastAPI service runs alongside the dashboard and provides programmatic access to scan data.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check — returns status and record count |
| POST | `/load` | Load enriched scan records into memory |
| GET | `/results` | Get all results (optional `?severity=Critical` filter) |
| GET | `/analysis` | Aggregated summary — severity breakdown, risk scores, VT flagged IPs |
| GET | `/host/{ip}` | All findings for a specific IP address |

All endpoints except `/` require the `x-api-key` header.  
Rate limits: 20 req/min (load), 60 req/min (results), 30 req/min (analysis).

---

## 📧 Email Alert System

When a scan completes, CyberScan Pro automatically:
1. Generates a **styled HTML email** with severity summary cards and a full findings table
2. Creates a **PDF report** using fpdf2 with executive summary and detailed findings
3. Sends both via **Gmail SMTP** (port 465 SSL or 587 STARTTLS fallback)

### Gmail Setup
1. Enable 2-Step Verification at [myaccount.google.com](https://myaccount.google.com)
2. Generate an App Password: Security → App passwords → Mail
3. Add to `u.env`:
```
GMAIL_SENDER=youremail@gmail.com
GMAIL_PASSWORD=xxxxxxxxxxxxxxxx
GMAIL_RECIPIENT=recipient@company.com
```

---

## 🛠️ Tech Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.9+ | Core language |
| Streamlit | Latest | Web dashboard framework |
| Plotly | Latest | Interactive charts and visualizations |
| FastAPI | Latest | REST API framework |
| Uvicorn | Latest | ASGI server for FastAPI |
| Slowapi | Latest | Rate limiting for FastAPI |
| fpdf2 | Latest | PDF report generation |
| SQLite | Built-in | Scan history database |
| python-nmap | Latest | Python wrapper for Nmap |
| requests | Latest | HTTP client for VirusTotal API |
| pandas | Latest | Data manipulation and analysis |
| python-dotenv | Latest | Load `.env` configuration |
| pydantic | Latest | Data validation for API models |
| nmap | System binary | Network port scanner |

---

## 🚀 How to Run

### 1. Install Dependencies
```python
# Run Cell 1 in the notebook — installs all Python packages automatically
# Also ensure nmap is installed:
# Linux:   sudo apt-get install nmap
# Mac:     brew install nmap
# Windows: https://nmap.org/download.html
```

### 2. Configure Environment
Create a `u.env` file in the project root:
```env
VT_API_KEY=your_virustotal_api_key
CYBERSCAN_API_KEY=your_custom_api_key
SCAN_TARGETS=scanme.nmap.org
GMAIL_SENDER=youremail@gmail.com
GMAIL_PASSWORD=your_app_password
GMAIL_RECIPIENT=recipient@email.com
```

### 3. Start the Dashboard
```bash
streamlit run dashboard/app.py --server.port 8501
```

### 4. Start the API (optional)
```bash
uvicorn api:app --host 0.0.0.0 --port 8000
```

### 5. Open in Browser
```
Dashboard → http://localhost:8501
API Docs  → http://localhost:8000/docs
```

---

## 🔑 Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `VT_API_KEY` | VirusTotal API key (free at virustotal.com) | ✅ Yes |
| `CYBERSCAN_API_KEY` | Custom API key for REST API auth | ✅ Yes |
| `SCAN_TARGETS` | Comma-separated targets to scan | ✅ Yes |
| `GMAIL_SENDER` | Gmail address to send alerts from | Optional |
| `GMAIL_PASSWORD` | Gmail App Password (16 chars) | Optional |
| `GMAIL_RECIPIENT` | Email address to receive alerts | Optional |

---

## 📚 References

| Resource | URL |
|----------|-----|
| Nmap Official Docs | https://nmap.org/docs.html |
| VirusTotal API v3 | https://developers.virustotal.com/reference |
| Streamlit Docs | https://docs.streamlit.io |
| FastAPI Docs | https://fastapi.tiangolo.com |
| fpdf2 Docs | https://py-pdf.github.io/fpdf2/ |
| Plotly Python | https://plotly.com/python/ |
| Slowapi (Rate Limiting) | https://github.com/laurentS/slowapi |
| python-nmap | https://xael.org/pages/python-nmap-en.html |
| SQLite Python | https://docs.python.org/3/library/sqlite3.html |
| Gmail App Passwords | https://myaccount.google.com/apppasswords |

---

## 📝 Notes

- **Scan target `scanme.nmap.org`** is a legally authorised test target provided by the Nmap project for testing purposes.
- Always ensure you have **permission** before scanning any IP or hostname.
- The VirusTotal free API is limited to **4 requests per minute** — scanning many unique IPs may be slow.
- Scan history is stored locally in `cyberscan.db` and persists across sessions.
- PDF reports are saved to the `reports/` folder with a timestamp in the filename.

---

*CyberScan Pro — Built for educational and authorised security assessment purposes only.*
