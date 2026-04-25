# AI-Assisted Network Exposure Analysis Tool

**Modern web-based vulnerability scanner with CPE-based detection and AI-powered analysis**

A comprehensive vulnerability analysis tool that processes Nmap scan data, uses CPE (Common Platform Enumeration) for precise vulnerability matching, fetches real CVE information from NIST NVD, and provides AI-powered explanations and remediation guidance.

**CYSE 610 - Network Security Course Project**

---

## Key Features

### **Web Interface**
- **Modern Flask Web App** - Upload scans, view results in browser
- **Live Monitor** - Real-time scan progress with per-port CVE tracking
  - Watch CVEs progress from Pending (1/3) → Validated (2/3) → Validated (3/3)
  - See Found/Filtered/Final counts update live
  - Collapsible port cards with CVE details
- **Interactive Dashboard** - Summary cards, risk scores, vulnerability tables
- **Collapsible Vulnerability Sections** - Each CVE has 6 expandable sections
- **AI Q&A** - Ask questions about vulnerabilities in natural language
- **Responsive Design** - Works on desktop and mobile

### **Intelligent CVE Detection**
- **CPE-Based Matching** - Uses Common Platform Enumeration for precise vulnerability identification
- **NVD API Integration** - Fetches actual CVE data from NIST National Vulnerability Database
- **Hybrid Strategy** - CPE-first matching with keyword fallback for comprehensive coverage
- **Auto-Updating** - CVE data updates automatically as NVD changes
- **CISA KEV Detection** - Flags actively exploited vulnerabilities

### **Industry-Standard Risk Scoring**
- **CVSS v3.x** - Uses official CVSS scores with consistent severity labels
  - CRITICAL: 9.0-10.0
  - HIGH: 7.0-8.9
  - MEDIUM: 4.0-6.9
  - LOW: 0.1-3.9
- **Color-Coded** - Critical (red), High (orange), Medium (yellow), Low (green)
- **Defensible** - Based on NIST, FIRST, and CISA standards

### **AI-Powered Analysis (Claude Haiku 4.5)**
- **Multi-Pass Consensus System** - 3-pass analysis with confidence scoring
  - High Confidence: CVE found in all 3 passes (3/3)
  - Medium Confidence: CVE found in 2+ passes (2/3)
  - Low Confidence: CVE found in 1 pass only (1/3) - filtered as likely false positive
- **Real-Time Validation** - CVEs turn green when consensus (2+ passes) is reached
- **Structured Explanations** - 6 standardized sections per vulnerability:
  - Validation Assessment
  - What is this vulnerability?
  - Discovery & Timeline
  - Severity Context
  - Attack Scenarios
  - Recommended Fix
- **Interactive Q&A** - Ask questions about scan results
- **Automated False Positive Filtering** - AI removes unlikely vulnerabilities

### **Smart Prioritization**
- **Risk-Based Sorting** - Highest-risk hosts and vulnerabilities appear first
- **Port Consolidation** - Groups same CVE across multiple ports
- **Severity Distribution** - See critical/high/medium/low counts at a glance

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
# Stop running Flask application
make stop-app

# Remove virtual environment only (keeps data and .env)
make clean-venv

# Stop app and remove everything (venv, uploads, cache, .env)
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
   - **Important**: Use Nmap version scans (`-sV` flag) for best results
   - Version scans include CPE data for precise vulnerability matching
   - Example: `nmap -sV -p- -oX output.xml <target>`
3. **Enable AI** (optional): Check "Use AI for enhanced analysis"
4. **View results**: 
   - Vulnerabilities sorted by CVSS score
   - AI explanations for each CVE
   - Ask questions about findings
   - Download HTML reports

---

## Example Datasets

The `example-datasets/` folder contains ready-to-use Nmap scan files:
- **Blue-nmap-version-scan-output.xml** - Windows 7 with EternalBlue (SMB vulnerabilities)
- **Devel-nmap-version-scan-output.xml** - Windows Server with IIS 7.5 + FTP

These demonstrate:
- **CPE-based detection** (IIS 7.5 with precise CPE matching)
- **Keyword fallback** (SMB services without application CPE)
- **Port consolidation** (EternalBlue across ports 139, 445)

---

## How It Works

### CPE-Based Vulnerability Detection

1. **Nmap Scan** → Extracts CPE data from service fingerprints
2. **CPE Matching** → Queries NVD API with exact CPE strings (e.g., `cpe:/a:microsoft:internet_information_services:7.5`)
3. **Keyword Fallback** → If no CPE or no results, falls back to keyword search
4. **Relevance Filtering** → Ensures CVEs match the detected OS and service context
5. **Severity Calculation** → Recalculates severity from CVSS score for consistency

**Result**: Eliminates false positives (e.g., TitanFTP CVEs for Microsoft FTP) while maintaining comprehensive coverage (e.g., EternalBlue detection).

---

## Architecture

```
User uploads Nmap scan(s) with -sV flag
         ↓
   Flask Web Server (app.py)
   - Async processing with progress tracking
   - Real-time CVE updates via WebSocket-style polling
         ↓
   Parser (extracts CPE, OS, services)
         ↓
   Processor (preserves CPE data)
         ↓
   ┌─────────────────────────────────────────┐
   │  Analyzer - Multi-Pass Consensus System │
   │  ┌─────────────────────────────────┐    │
   │  │ Pass 1: Initial CVE Detection   │    │
   │  │  - CPE-first matching           │    │
   │  │  - Keyword fallback             │    │
   │  │  - AI false positive filtering  │    │
   │  └─────────────────────────────────┘    │
   │              ↓                           │
   │  ┌─────────────────────────────────┐    │
   │  │ Pass 2: Validation Pass         │    │
   │  │  - Re-run detection             │    │
   │  │  - Track consensus              │    │
   │  │  - CVEs with 2/3 → VALIDATED    │    │
   │  └─────────────────────────────────┘    │
   │              ↓                           │
   │  ┌─────────────────────────────────┐    │
   │  │ Pass 3: Final Confirmation      │    │
   │  │  - Final consensus check        │    │
   │  │  - Assign confidence levels     │    │
   │  │  - Filter low-confidence CVEs   │    │
   │  └─────────────────────────────────┘    │
   └─────────────────────────────────────────┘
         ↓
   NVD Client (CPE queries + keyword search)
         ↓
   Confidence Assignment
   - High: 3/3 passes
   - Medium: 2/3 passes  
   - Low: 1/3 passes (filtered)
         ↓
   AI Explainer (Claude Haiku 4.5)
   - 6 standardized sections per CVE
   - Validation assessment
   - Remediation guidance
         ↓
   Reporter (HTML + JSON)
   - Valid vulnerabilities (2+ pass consensus)
   - Filtered false positives (with reasons)
         ↓
   Web Interface Display
   - Live Monitor (real-time progress)
   - Summary Dashboard
   - Detailed Reports
```

---

## Academic Context

**Course**: CYSE 610 - Network Security  
**Objective**: Demonstrate practical vulnerability analysis with modern tools  
**Key Innovations**:
- **Multi-Pass Consensus System** - 3-pass analysis reduces false positives through AI consensus
- **Real-Time Validation Feedback** - Live monitor shows CVEs progressing from pending to validated
- **CPE-based matching** - Precise vulnerability identification using industry-standard CPE
- **Hybrid detection** - CPE-first with keyword fallback for comprehensive coverage
- **Real-time CVE data** - No hardcoded rules, 100% NVD automation
- **Structured AI Explanations** - 6 standardized sections with collapsible UI for easy navigation
- **Defensible methodology** - NIST/FIRST/CISA aligned with consistent CVSS severity labels

---

## Key Files

### Core Application
- `app.py` - Flask web server with async scan processing
- `src/parser.py` - Nmap XML parser (extracts CPE, OS, services)
- `src/processor.py` - Data processor (preserves CPE for analyzer)
- `src/analyzer.py` - Vulnerability analyzer (CPE-first strategy)
- `src/nvd_client.py` - NVD API client (CPE queries + keyword search)
- `src/explainer.py` - AI explainer (Claude Haiku 4.5)
- `src/reporter.py` - Report generator (HTML + JSON)

### Web Interface
- `templates/index.html` - Upload interface
- `templates/results.html` - Results display with AI Q&A
- `static/css/style.css` - Modern responsive UI
- `static/js/results.js` - Interactive features

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
