# AI-Assisted Network Exposure Analysis

**Modern web-based vulnerability scanner with real-time CVE detection and AI-powered analysis**

A comprehensive vulnerability analysis tool that processes Nmap scan data, fetches real CVE information from NIST NVD, calculates industry-standard risk scores, and provides AI-powered explanations and remediation guidance.

**CYSE 610 - Network Security Course Project**

---

## Key Features

### **Web Interface**
- **Modern Flask Web App** - Upload scans, view results in browser
- **Interactive Dashboard** - Summary cards, risk scores, vulnerability tables
- **Multi-Scan Support** - Upload multiple scans, aggregated results
- **Responsive Design** - Works on desktop and mobile

### **Real-Time CVE Detection**
- **NVD API Integration** - Fetches actual CVE data from NIST National Vulnerability Database
- **Auto-Updating** - CVE data updates automatically as NVD changes
- **Version-Specific** - Matches CVEs to detected product versions
- **CISA KEV Detection** - Flags actively exploited vulnerabilities

### **Industry-Standard Risk Scoring**
- **CVSS-Based** - Uses official CVSS v3.1 scores (0-100 scale)
- **Weighted Average** - Diminishing returns for multiple vulnerabilities
- **Color-Coded** - Critical (red), High (orange), Medium (yellow), Low (green)
- **Defensible** - Based on NIST, FIRST, and CISA standards

### **AI-Powered Analysis**
- **Anthropic Claude** - AI explains vulnerabilities in plain language
- **Validation** - AI checks if CVEs actually apply to detected versions
- **Q&A Interface** - Ask natural language questions about scan results
- **Remediation Guidance** - AI provides actionable fix recommendations

### **Smart Prioritization**
- **Risk-Based Sorting** - Highest-risk hosts appear first
- **Host Grouping** - Groups multiple scans of same IP
- **Severity Distribution** - See critical/high/medium/low counts at a glance

---

## Documentation

- **[DESIGN_RATIONALE.md](DESIGN_RATIONALE.md)** - Why we made each design decision (for professor questions)
- **[RISK_SCORING_METHODOLOGY.md](RISK_SCORING_METHODOLOGY.md)** - Detailed risk scoring algorithm explanation
- **[NVD_INTEGRATION.md](NVD_INTEGRATION.md)** - How NVD API integration works
- **[WEB_INTERFACE_README.md](WEB_INTERFACE_README.md)** - Web interface technical details
- **[MIDTERM_REPORT.md](MIDTERM_REPORT.md)** - Full project report

---

## Quick Start

### Prerequisites

- **Python 3.9+** (or **Docker** as alternative)
- **Anthropic API Key** ([Get free key](https://console.anthropic.com/))

---

### Standard Setup (4 Steps)

```bash
# Step 1: Create .env file
make setup

# Step 2: Edit .env and add your ANTHROPIC_API_KEY
make env

# Step 3: Create virtual environment and install dependencies
make build

# Step 4: Run application
make run
```

**Then open:** http://localhost:8080

**Note:** Dependencies are installed in an isolated virtual environment (`venv/`) that doesn't affect your system Python.

### Cleanup

```bash
# Remove virtual environment only (keeps data and .env)
make clean-venv

# Remove everything (venv, uploads, cache, .env)
make clean-all
```

---

### Docker Alternative

If you prefer Docker:

```bash
# Step 1: Create .env file
make setup

# Step 2: Edit .env and add your ANTHROPIC_API_KEY
make env

# Step 3: Build Docker image
make docker-build

# Step 4: Run in Docker
make docker-run
```

**Docker Commands:**
```bash
make logs    # View logs
make stop    # Stop container
make clean   # Remove container and image
```

---

### Usage

1. **Open browser**: http://localhost:8080
2. **Upload Nmap scans**: Drag & drop XML files or click to browse
3. **Enable AI** (optional): Check "Use AI for enhanced analysis"
4. **View results**: See vulnerabilities, risk scores, and AI explanations

---

## Dataset

Uses **InfoSecWarrior/Vulnerable-Box-Resources** for testing:
- **Source**: https://github.com/InfoSecWarrior/Vulnerable-Box-Resources
- **Content**: 822 real Nmap scans, 11 vulnerable systems
- **Primary Target**: My-File-Server-1 (FTP, Telnet, SMB, NFS, etc.)

See `docs/DATASET_SELECTION_PROCESS.md` for selection process.

---

## Architecture

```
User uploads Nmap scan(s)
         ↓
   Flask Web Server (app.py)
         ↓
   Parser → Processor → Analyzer
                           ↓
                    NVD API (real CVEs)
                           ↓
                    Risk Score Calculation
                           ↓
                    AI Explanation (Claude)
                           ↓
                    Web Interface Display
```

---

## Academic Context

**Course**: CYSE 610 - Network Security  
**Objective**: Demonstrate practical vulnerability analysis with modern tools  
**Key Innovations**:
- Real-time CVE data (not hardcoded)
- Industry-standard risk scoring (CVSS-based)
- AI-enhanced accessibility (explains technical CVEs)
- Defensible methodology (NIST/FIRST/CISA aligned)

---

## Key Files

- `app.py` - Flask web application
- `src/analyzer.py` - Vulnerability detection with NVD integration
- `src/nvd_client.py` - NVD API client
- `src/explainer.py` - AI explanation generation
- `templates/results.html` - Results display with risk scoring
- `static/css/style.css` - Modern UI styling

---

## Advanced Features

### Optional: NVD API Key
Get higher rate limits (50 req/30sec vs 5 req/30sec):
```bash
# Add to .env
NVD_API_KEY=your-key-here
```
Request free key: https://nvd.nist.gov/developers/request-an-api-key

### Docker Deployment
```bash
docker-compose up
```

---

## License

Academic project for CYSE 610. See course materials for usage guidelines.

---

## Acknowledgments

- **NIST NVD** - CVE data source
- **CISA** - Known Exploited Vulnerabilities catalog
- **Anthropic** - Claude AI for explanations
- **InfoSecWarrior** - Vulnerable-Box-Resources dataset
