# Quick Start Guide

## Getting Started in 3 Steps

### 1. Setup (One-time)

```bash
cd ai-network-exposure-analysis
make setup
```

This creates a virtual environment and installs all dependencies.

### 2. Run Demo

```bash
make demo
```

This runs the pipeline with sample data and generates reports in `data/reports/`.

### 3. View Results

Open the HTML report in your browser:
```bash
open data/reports/vulnerability_report_*.html
```

## Next Steps

### Analyze Your Own Scans

1. **Generate an nmap scan:**
   ```bash
   nmap -sV -oX data/raw/myscan.xml target_ip
   ```

2. **Run the analysis:**
   ```bash
   make run INPUT=data/raw/myscan.xml
   ```

3. **View the report:**
   ```bash
   open data/reports/vulnerability_report_*.html
   ```

### Enable AI Analysis

1. **Get your Anthropic API key** from https://console.anthropic.com/

2. **Set up environment:**
   ```bash
   cp .env.example .env
   # Edit .env and add: ANTHROPIC_API_KEY=your-key-here
   ```

3. **Run with AI:**
   ```bash
   source venv/bin/activate
   python main.py --input data/raw/myscan.xml --ai
   ```

### Evaluate Against Baseline

1. **Create baseline file** in `data/baseline/` (see sample_baseline.json)

2. **Run with evaluation:**
   ```bash
   source venv/bin/activate
   python main.py --input data/raw/myscan.xml \
                  --baseline data/baseline/your_baseline.json \
                  --evaluate
   ```

## Common Commands

```bash
make demo      # Run demo with sample data
make clean     # Remove generated reports
make archive   # Archive old reports
make test      # Run test suite
make reset     # Complete fresh start
```

## Troubleshooting

**Problem:** `make: command not found`
- **Solution:** Install make or run commands directly with Python

**Problem:** API key not working
- **Solution:** Check `.env` file exists and has correct key format

**Problem:** No reports generated
- **Solution:** Check `data/reports/` directory permissions

## For Your Midterm Presentation

1. Run demo: `make demo`
2. Open HTML report in browser
3. Show the visual dashboard with vulnerability counts
4. Walk through detailed findings for each host
5. Explain the risk scoring and prioritization

The HTML report is designed for non-technical audiences!

## Project Structure Quick Reference

```
data/raw/        → Put nmap scans here
data/reports/    → Generated reports appear here
data/baseline/   → Baseline vulnerability data for evaluation
src/             → Source code modules
tests/           → Test files
archive/         → Old versions (use 'make archive')
```

## Need Help?

See full documentation in `README.md`
