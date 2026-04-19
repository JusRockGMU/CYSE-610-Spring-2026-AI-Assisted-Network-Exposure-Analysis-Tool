# Example Nmap Scan Datasets

This folder contains sample Nmap XML scan files for testing the vulnerability analysis tool.

## Included Scans

### Hack The Box Vulnerable Systems

1. **Blue** - Windows system with SMB vulnerabilities (EternalBlue)
   - `Blue-all-ports-scan-output.xml`
   - `Blue-nmap-version-scan-output.xml`

2. **Devel** - Windows IIS server with FTP
   - `Devel-all-ports-scan-output.xml`
   - `Devel-nmap-version-scan-output.xml`

3. **Blocky** - Linux system with web services
   - `Blocky-all-ports-scan-output.xml`
   - `Blocky-nmap-version-scan-output.xml`

4. **Delivery** - Linux system with multiple services
   - `Delivery-all-ports-scan-output.xml`
   - `Delivery-nmap-version-scan-output.xml`

5. **Admirer** - Linux web server
   - `Admirer-all-ports-scan-output.xml`
   - `Admirer-nmap-version-scan-output.xml`

## Usage

Upload these XML files to the web interface at http://localhost:8080 to:
- Test vulnerability detection
- See real CVE data from NVD API
- View AI-powered explanations
- Explore risk scoring methodology

## Source

These scans are from the InfoSecWarrior/Vulnerable-Box-Resources dataset:
https://github.com/InfoSecWarrior/Vulnerable-Box-Resources

All scans are from intentionally vulnerable training systems (Hack The Box).
