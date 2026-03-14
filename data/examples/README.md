# Example Reports

This directory contains sample output reports demonstrating the tool's capabilities.

## Files

### Individual Host Report
- `example_individual_report.html` - HTML report for a single host (My-File-Server-1, IP: 192.168.1.39)
- `example_individual_report.json` - Machine-readable JSON version

**Contents:**
- Host information (IP, OS, services)
- Detailed vulnerability findings
- Risk score and severity breakdown
- Remediation recommendations

### Batch Summary Report
- `example_batch_summary.html` - Combined summary of all 11 InfoSecWarrior targets
- `example_batch_summary.json` - Machine-readable JSON version

**Contents:**
- Overall statistics across all hosts
- Host-by-host vulnerability breakdown
- Top vulnerabilities by frequency
- Risk score rankings

## Dataset

These reports were generated from the InfoSecWarrior/Vulnerable-Box-Resources dataset:
- 11 intentionally vulnerable hosts
- Real nmap scan data
- Demonstrates rule-based vulnerability detection

## Viewing Reports

Open the `.html` files in any web browser to view the formatted reports.
