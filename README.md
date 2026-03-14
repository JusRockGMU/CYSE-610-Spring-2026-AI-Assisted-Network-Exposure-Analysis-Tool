# AI-Assisted Network Exposure Analysis

A comprehensive vulnerability analysis tool that processes nmap scan data, identifies security vulnerabilities using rule-based and AI-powered methods, and generates prioritized reports for network security assessment.

**CYSE 610 - Network Security Course Project**

## Features

-  **Nmap Scan Parsing** - Supports XML and text format nmap outputs
-  **Data Processing** - Normalizes and enriches scan data with risk categorization
-  **AI-Powered Analysis** - Optional Anthropic Claude integration for contextual insights
-  **Professional Reports** - Generates JSON (machine-readable) and HTML (presentation-ready) reports
-  **Evaluation Framework** - Compares results against baseline data with precision/recall metrics
-  **Automated Workflow** - Comprehensive Makefile for easy setup and operation
- **Real Public Dataset**: Uses InfoSecWarrior/Vulnerable-Box-Resources (822 scans, 11 targets)

## Dataset

This project uses the **InfoSecWarrior/Vulnerable-Box-Resources** dataset from GitHub:
- **Source**: https://github.com/InfoSecWarrior/Vulnerable-Box-Resources
- **Content**: 822 real nmap scans across 11 vulnerable systems
- **Scan Date**: September 2024
- **Primary Target**: My-File-Server-1 (8 ports, 6 vulnerable services)
- **Additional Targets**: 10 more systems available for testing

See `docs/DATASET_SELECTION_PROCESS.md` for how this dataset was selected.

## Quick Start

### Prerequisites

- Python 3.9 or higher
- nmap (for generating scan data)
- Anthropic API key (optional, for AI features)

### Installation

```bash
# Clone or navigate to project directory
cd ai-network-exposure-analysis

# Set up environment (creates venv, installs dependencies)
make setup

# Configure API key (optional, for AI features)
cp .env.example .env
```

### 1. Setup Environment

```bash
make setup
```

### 2. Run Analysis on Real Data

```bash
# Analyze InfoSecWarrior File Server (real public dataset)
python main.py --input data/raw/infosecwarrior_fileserver.xml \
               --baseline data/baseline/infosecwarrior_fileserver.json \
               --evaluate
```

This analyzes a real nmap scan from the InfoSecWarrior/Vulnerable-Box-Resources dataset.

### Analyze Your Own Scans

```bash
# Place your nmap scan in data/raw/
# Then run:
make run INPUT=data/raw/your_scan.xml

# Or use the Python script directly:
source venv/bin/activate
python main.py --input data/raw/your_scan.xml
```

## Usage

### Basic Analysis

```bash
python main.py --input data/raw/scan.xml
```

### With AI Analysis

```bash
python main.py --input data/raw/scan.xml --ai
```

### With Evaluation

```bash
python main.py --input data/raw/scan.xml \
               --baseline data/baseline/known_vulns.json \
               --evaluate
```

### Command Line Options

```
--input, -i       Path to nmap scan file (XML or text)
--output, -o      Output directory for reports (default: data/reports)
--baseline, -b    Path to baseline vulnerability data
--evaluate, -e    Evaluate results against baseline
--ai              Enable AI-powered analysis using Claude
--verbose, -v     Enable verbose output
--demo            Run demo with sample data
```

## Makefile Commands

```bash
make setup     # Create virtual environment and install dependencies
make clean     # Remove generated data and reset to fresh state
make archive   # Move old reports to archive folder
make test      # Run test suite
make run       # Execute pipeline (requires INPUT=path/to/scan.xml)
make demo      # Run demo with sample data
make reset     # Complete fresh start (clean + setup)
make help      # Show all available commands
```

## Project Structure

```
ai-network-exposure-analysis/
├── main.py              # Main pipeline orchestrator
├── Makefile             # Automation commands
├── requirements.txt     # Python dependencies
├── .env.example         # API key template
├── src/
│   ├── parser.py        # Nmap scan parser
│   ├── processor.py     # Data normalization and feature extraction
│   ├── analyzer.py      # Vulnerability analysis (rule-based + AI)
│   ├── reporter.py      # Report generation (JSON + HTML)
│   └── evaluator.py     # Evaluation against baseline
├── data/
│   ├── raw/             # Input nmap scans
│   ├── processed/       # Normalized data
│   ├── baseline/        # Known vulnerabilities for evaluation
│   └── reports/         # Generated reports
├── archive/             # Old file versions
└── tests/
    └── test_pipeline.py # Test suite
```

## Pipeline Flow

```
1. Parse      → Read nmap XML/text and extract host/port/service data
2. Process    → Normalize data, categorize risks, extract features
3. Analyze    → Identify vulnerabilities using rules + AI (optional)
4. Report     → Generate JSON and HTML reports with prioritization
5. Evaluate   → Compare against baseline (optional)
```

## Vulnerability Detection

### Rule-Based Detection

The analyzer uses a knowledge base of common vulnerabilities:

- **Critical Services**: Telnet, FTP, SMBv1, RDP (BlueKeep), VNC
- **Misconfigurations**: Unencrypted HTTP, missing version info
- **Risk Scoring**: CVSS-based prioritization with severity multipliers

### AI-Enhanced Analysis (Optional)

When enabled with `--ai`, the system uses Anthropic Claude to:

- Provide contextual vulnerability analysis
- Identify potential attack vectors
- Generate actionable remediation recommendations
- Explain security implications in natural language

## Report Formats

### JSON Report
- Machine-readable format
- Complete vulnerability data
- Used for evaluation and integration
- Includes metadata and timestamps

### HTML Report
- Professional, visual presentation
- Color-coded severity levels
- Executive summary dashboard
- Detailed findings per host
- Remediation recommendations
- Ideal for non-technical stakeholders

## Evaluation Metrics

When baseline data is provided:

- **Precision**: Percentage of detected vulnerabilities that are real
- **Recall**: Percentage of real vulnerabilities that were detected
- **F1 Score**: Harmonic mean of precision and recall
- **Confusion Matrix**: True/false positives and negatives

## Creating Baseline Data

Baseline files should be JSON format:

```json
{
  "hosts": [
    {
      "ip": "192.168.1.100",
      "vulnerabilities": [
        {
          "port": 23,
          "service": "telnet"
        },
        {
          "port": 21,
          "service": "ftp"
        }
      ]
    }
  ]
}
```

## Generating Nmap Scans

```bash
# Basic scan
nmap -sV -oX scan.xml target_ip

# Comprehensive scan
nmap -sV -sC -O -oX scan.xml target_ip

# Scan network range
nmap -sV -oX scan.xml 192.168.1.0/24
```

## Development

### Running Tests

```bash
make test

# Or directly with pytest
source venv/bin/activate
pytest tests/ -v
```

### Adding New Vulnerability Rules

Edit `src/analyzer.py` and add to `VULNERABILITY_DATABASE`:

```python
'service_name': {
    'default': {
        'cve': 'CVE-XXXX-XXXX',
        'description': 'Vulnerability description',
        'severity': 'HIGH',
        'cvss': 7.5,
        'recommendation': 'How to fix'
    }
}
```

## Troubleshooting

### API Key Issues

```bash
# Check if API key is set
echo $ANTHROPIC_API_KEY

# Or check .env file
cat .env
```

### Permission Errors

```bash
# Make main.py executable
chmod +x main.py
```

### Module Import Errors

```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
make install-deps
```

## Future Enhancements

- [ ] Machine learning model for vulnerability pattern recognition
- [ ] Integration with CVE databases (NVD, MITRE)
- [ ] Support for additional scan formats (Nessus, OpenVAS)
- [ ] Real-time scanning capabilities
- [ ] Web dashboard interface
- [ ] Automated remediation scripts

## Contributors

CYSE 610 Group 2 - Spring 2026

## License

Educational use only - CYSE 610 Course Project

## Acknowledgments

- Anthropic Claude API for AI-powered analysis
- NIST National Vulnerability Database
- nmap project for network scanning capabilities
