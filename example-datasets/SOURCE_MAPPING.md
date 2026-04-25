# Example Dataset Source Mapping

This document maps the files in `example-datasets/` to their original source locations.

## File Mapping

All files in this directory are **exact copies** (verified by MD5 checksum) from the InfoSecWarrior Vulnerable-Box-Resources dataset.

### Original Source Repository
- **Repository:** InfoSecWarrior/Vulnerable-Box-Resources
- **URL:** https://github.com/InfoSecWarrior/Vulnerable-Box-Resources
- **Local Path:** `project-extras/datasets/vulnerable-box-resources/`

### File Mappings

#### Hack The Box Machines (5 machines, 10 files)

| Example Dataset File | Original Source Path | Machine | Notes |
|---------------------|---------------------|---------|-------|
| `Admirer-all-ports-scan-output.xml` | `Hack-The-Box/Admirer/Admirer-all-ports-scan-output.xml` | Admirer (HTB) | All ports scan |
| `Admirer-nmap-version-scan-output.xml` | `Hack-The-Box/Admirer/Admirer-nmap-version-scan-output.xml` | Admirer (HTB) | Version detection scan with CPE |
| `Blocky-all-ports-scan-output.xml` | `Hack-The-Box/Blocky/Blocky-all-ports-scan-output.xml` | Blocky (HTB) | All ports scan |
| `Blocky-nmap-version-scan-output.xml` | `Hack-The-Box/Blocky/Blocky-nmap-version-scan-output.xml` | Blocky (HTB) | Version detection scan with CPE |
| `Blue-all-ports-scan-output.xml` | `Hack-The-Box/Blue/Blue-all-ports-scan-output.xml` | Blue (HTB) | All ports scan |
| `Blue-nmap-version-scan-output.xml` | `Hack-The-Box/Blue/Blue-nmap-version-scan-output.xml` | Blue (HTB) | Version detection scan with CPE - **EternalBlue test case** |
| `Delivery-all-ports-scan-output.xml` | `Hack-The-Box/Delivery/Delivery-all-ports-scan-output.xml` | Delivery (HTB) | All ports scan |
| `Delivery-nmap-version-scan-output.xml` | `Hack-The-Box/Delivery/Delivery-nmap-version-scan-output.xml` | Delivery (HTB) | Version detection scan with CPE |
| `Devel-all-ports-scan-output.xml` | `Hack-The-Box/Devel/Devel-all-ports-scan-output.xml` | Devel (HTB) | All ports scan |
| `Devel-nmap-version-scan-output.xml` | `Hack-The-Box/Devel/Devel-nmap-version-scan-output.xml` | Devel (HTB) | Version detection scan with CPE - **IIS 7.5 test case** |

#### Vulnhub Machines (1 machine, 2 files)

| Example Dataset File | Original Source Path | Machine | Notes |
|---------------------|---------------------|---------|-------|
| `Metasploitable-2-all-ports-scan-output.xml` | `Vulnhub/Metasploitable-2/Metasploitable-2-all-ports-scan-output.xml` | Metasploitable 2 | Industry standard vulnerable VM |
| `Metasploitable-2-nmap-version-scan-output.xml` | `Vulnhub/Metasploitable-2/Metasploitable-2-nmap-version-scan-output.xml` | Metasploitable 2 | **Many services, high vulnerability count** |

#### Infosecwarrior Custom VMs (2 machines, 4 files)

| Example Dataset File | Original Source Path | Machine | Notes |
|---------------------|---------------------|---------|-------|
| `my-file-server-1-all-ports-scan-output.xml` | `Infosecwarrior/My-File-Server-1/my-file-server-1-all-ports-scan-output.xml` | My-File-Server-1 | Custom vulnerable file server |
| `my-file-server-1-nmap-version-scan-output.xml` | `Infosecwarrior/My-File-Server-1/my-file-server-1-nmap-version-scan-output.xml` | My-File-Server-1 | FTP, SMB, NFS services |
| `My-Web-Server-all-ports-scan-output.xml` | `Infosecwarrior/My-Web-Server/My-Web-Server-all-ports-scan-output.xml` | My-Web-Server | Custom vulnerable web server |
| `My-Web-Server-nmap-version-scan-output.xml` | `Infosecwarrior/My-Web-Server/My-Web-Server-nmap-version-scan-output.xml` | My-Web-Server | Apache, MySQL, PHP stack |

## File Verification

Files were verified as exact copies using MD5 checksums:

```bash
# Example verification
md5 example-datasets/Devel-nmap-version-scan-output.xml
# MD5: dddf1158c2ff67b21b02de4f58d0105f

md5 project-extras/datasets/vulnerable-box-resources/Hack-The-Box/Devel/Devel-nmap-version-scan-output.xml
# MD5: dddf1158c2ff67b21b02de4f58d0105f
```

## Why These Files Were Selected

These 8 machines (16 files total) were selected from the 138 available machines for the following reasons:

### 1. **Blue** (Windows 7 - EternalBlue)
- **Purpose:** Test SMB vulnerability detection (MS17-010)
- **Challenge:** No application-level CPE for SMB service
- **Expected:** Should detect EternalBlue using keyword fallback

### 2. **Devel** (Windows - IIS 7.5)
- **Purpose:** Test CPE-based detection and false positive filtering
- **Challenge:** Previously returned TitanFTP CVEs for Microsoft FTP
- **Expected:** Should only return Microsoft IIS CVEs using CPE matching

### 3. **Admirer** (Linux - Apache/MySQL)
- **Purpose:** Test Linux service detection
- **Services:** Apache 2.4.25, MySQL, FTP
- **Expected:** Proper version-specific CVE matching

### 4. **Blocky** (Linux - Apache/SSH)
- **Purpose:** Test common Linux stack
- **Services:** Apache 2.4.18, OpenSSH 7.2p2
- **Expected:** Accurate version detection

### 5. **Delivery** (Linux - Nginx/SSH)
- **Purpose:** Test alternative web server
- **Services:** Nginx 1.14.0, OpenSSH 7.9p1
- **Expected:** Nginx-specific CVE detection

### 6. **Metasploitable 2** (Linux - Intentionally Vulnerable)
- **Purpose:** Industry-standard vulnerable VM for testing
- **Services:** 20+ vulnerable services (FTP, SSH, Telnet, SMTP, HTTP, MySQL, PostgreSQL, VNC, etc.)
- **Expected:** High vulnerability count, diverse CVE types, stress test for analyzer
- **Why Important:** Most widely used vulnerable VM in security training

### 7. **My-File-Server-1** (Custom - File Services)
- **Purpose:** Test file sharing protocol detection
- **Services:** FTP, SMB, NFS
- **Expected:** File server specific vulnerabilities
- **Dataset:** Infosecwarrior custom vulnerable VMs

### 8. **My-Web-Server** (Custom - LAMP Stack)
- **Purpose:** Test classic web application stack
- **Services:** Apache, MySQL, PHP
- **Expected:** Web application vulnerabilities
- **Dataset:** Infosecwarrior custom vulnerable VMs

## File Naming Convention

Files follow the original naming convention from the source repository:
- `{MachineName}-all-ports-scan-output.xml` - Basic port scan
- `{MachineName}-nmap-version-scan-output.xml` - Version detection with CPE data

**No files were renamed.** The names in `example-datasets/` are identical to the source.

## Usage in Testing

These files are used for:
1. **Development testing** - Quick validation during development
2. **CI/CD testing** - Automated test suite
3. **Documentation examples** - README and demo screenshots
4. **Regression testing** - Verify CPE detection and false positive filtering

## Full Dataset

The complete dataset (138 machines) is available in:
```
project-extras/datasets/vulnerable-box-resources/
```

This includes scans from:
- **Hack The Box:** 57 machines
- **Vulnhub:** 69 machines (including Metasploitable 1 & 2, Kioptrix series, Mr-Robot, etc.)
- **Infosecwarrior:** 11 custom vulnerable VMs
- **Other:** 1 machine (Metasploitable 3)

## Attribution

**Dataset Credit:**
- **Author:** InfoSecWarrior
- **Repository:** https://github.com/InfoSecWarrior/Vulnerable-Box-Resources
- **License:** Check repository for license information
- **Purpose:** Educational vulnerability scanning dataset

## Last Updated
April 25, 2026
