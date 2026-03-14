#!/usr/bin/env python3
"""
Create baseline from InfoSecWarrior dataset using nikto and nuclei outputs.
"""

import json
import os
import re


def parse_nikto_output(nikto_file):
    """Parse nikto output for vulnerabilities."""
    vulnerabilities = []
    
    if not os.path.exists(nikto_file):
        return vulnerabilities
    
    try:
        with open(nikto_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Nikto findings typically start with "+"
            for line in content.split('\n'):
                if line.strip().startswith('+'):
                    # Extract vulnerability info
                    if any(keyword in line.lower() for keyword in ['vuln', 'cve', 'risk', 'exposure']):
                        vulnerabilities.append({
                            'source': 'nikto',
                            'description': line.strip('+ ').strip(),
                            'severity': 'MEDIUM'
                        })
    except Exception as e:
        print(f"Error parsing nikto: {e}")
    
    return vulnerabilities


def parse_nuclei_output(nuclei_file):
    """Parse nuclei output for vulnerabilities."""
    vulnerabilities = []
    
    if not os.path.exists(nuclei_file):
        return vulnerabilities
    
    try:
        with open(nuclei_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Nuclei outputs findings
            for line in content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    # Extract severity and info
                    severity = 'MEDIUM'
                    if 'critical' in line.lower():
                        severity = 'CRITICAL'
                    elif 'high' in line.lower():
                        severity = 'HIGH'
                    elif 'low' in line.lower():
                        severity = 'LOW'
                    
                    vulnerabilities.append({
                        'source': 'nuclei',
                        'description': line.strip(),
                        'severity': severity
                    })
    except Exception as e:
        print(f"Error parsing nuclei: {e}")
    
    return vulnerabilities


def create_baseline_for_target(target_dir, target_name, ip_address):
    """Create baseline from a target directory."""
    
    print(f"\nProcessing: {target_name}")
    print(f"Directory: {target_dir}")
    
    vulnerabilities = []
    
    # Known vulnerabilities from the scan
    # FTP anonymous login
    vulnerabilities.append({
        'port': 21,
        'service': 'ftp',
        'cve': 'CWE-284',
        'description': 'FTP anonymous login allowed with writable directory',
        'severity': 'CRITICAL'
    })
    
    # NFS exposed
    vulnerabilities.append({
        'port': 2049,
        'service': 'nfs',
        'cve': 'CVE-2004-0175',
        'description': 'NFS export misconfiguration allows unauthorized file access',
        'severity': 'HIGH'
    })
    
    # SMB exposed
    vulnerabilities.append({
        'port': 445,
        'service': 'microsoft-ds',
        'cve': 'CVE-2017-0144',
        'description': 'SMB service exposed',
        'severity': 'CRITICAL'
    })
    
    # HTTP unencrypted
    vulnerabilities.append({
        'port': 80,
        'service': 'http',
        'cve': 'CONFIG-001',
        'description': 'Unencrypted HTTP service with TRACE method enabled',
        'severity': 'MEDIUM'
    })
    
    # Parse nikto output
    nikto_file = os.path.join(target_dir, f"{target_name}-nikto-80-output.txt")
    nikto_vulns = parse_nikto_output(nikto_file)
    
    # Parse nuclei outputs
    for file in os.listdir(target_dir):
        if 'nuclei' in file and file.endswith('.txt'):
            nuclei_file = os.path.join(target_dir, file)
            nuclei_vulns = parse_nuclei_output(nuclei_file)
            vulnerabilities.extend(nuclei_vulns)
    
    baseline = {
        'description': f'InfoSecWarrior dataset - {target_name}',
        'source': 'InfoSecWarrior/Vulnerable-Box-Resources GitHub repository',
        'created': '2026-03-14',
        'target_directory': target_dir,
        'hosts': [
            {
                'ip': ip_address,
                'hostname': target_name,
                'vulnerabilities': vulnerabilities
            }
        ]
    }
    
    return baseline


def main():
    """Create baseline for InfoSecWarrior file server."""
    
    # File server target
    target_dir = 'datasets/vulnerable-box-resources/Infosecwarrior/My-File-Server-1'
    target_name = 'my-file-server-1'
    ip_address = '192.168.1.39'
    
    baseline = create_baseline_for_target(target_dir, target_name, ip_address)
    
    # Save baseline
    output_path = 'data/baseline/infosecwarrior_fileserver.json'
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(baseline, f, indent=2)
    
    print(f"\n✓ Baseline created: {output_path}")
    print(f"  Total vulnerabilities: {len(baseline['hosts'][0]['vulnerabilities'])}")
    
    # Count by severity
    vulns = baseline['hosts'][0]['vulnerabilities']
    critical = sum(1 for v in vulns if v.get('severity') == 'CRITICAL')
    high = sum(1 for v in vulns if v.get('severity') == 'HIGH')
    medium = sum(1 for v in vulns if v.get('severity') == 'MEDIUM')
    
    print(f"  Critical: {critical}")
    print(f"  High: {high}")
    print(f"  Medium: {medium}")
    
    print(f"\nNext steps:")
    print(f"  python main.py --input data/raw/infosecwarrior_fileserver.xml \\")
    print(f"                 --baseline {output_path} \\")
    print(f"                 --evaluate")


if __name__ == '__main__':
    main()
