#!/usr/bin/env python3
"""
Parse Nessus .nessus files to extract vulnerability baselines.
"""

import xml.etree.ElementTree as ET
import json
import os


def parse_nessus_file(nessus_path):
    """Parse a .nessus file and extract vulnerabilities."""
    
    print(f"\nParsing Nessus file: {nessus_path}")
    
    try:
        tree = ET.parse(nessus_path)
        root = tree.getroot()
        
        hosts = {}
        
        # Find all ReportHost elements
        for report_host in root.findall('.//ReportHost'):
            host_name = report_host.get('name')
            
            if host_name not in hosts:
                hosts[host_name] = {
                    'ip': host_name,
                    'hostname': '',
                    'vulnerabilities': []
                }
            
            # Get hostname if available
            for tag in report_host.findall('.//tag'):
                if tag.get('name') == 'host-fqdn':
                    hosts[host_name]['hostname'] = tag.text
            
            # Parse each ReportItem (vulnerability)
            for item in report_host.findall('.//ReportItem'):
                port = item.get('port', '0')
                service = item.get('svc_name', 'unknown')
                plugin_name = item.get('pluginName', '')
                severity = item.get('severity', '0')
                
                # Map Nessus severity to our severity levels
                severity_map = {
                    '0': 'INFO',
                    '1': 'LOW',
                    '2': 'MEDIUM',
                    '3': 'HIGH',
                    '4': 'CRITICAL'
                }
                severity_text = severity_map.get(severity, 'UNKNOWN')
                
                # Skip informational findings
                if severity_text in ['INFO', 'UNKNOWN']:
                    continue
                
                # Extract CVE if present
                cve = None
                cve_elem = item.find('cve')
                if cve_elem is not None and cve_elem.text:
                    cve = cve_elem.text
                
                # Extract description
                description = plugin_name
                synopsis = item.find('synopsis')
                if synopsis is not None and synopsis.text:
                    description = synopsis.text
                
                # Extract CVSS score
                cvss = 0.0
                cvss_elem = item.find('cvss_base_score')
                if cvss_elem is not None and cvss_elem.text:
                    try:
                        cvss = float(cvss_elem.text)
                    except:
                        pass
                
                vuln = {
                    'port': int(port) if port.isdigit() else 0,
                    'service': service,
                    'cve': cve if cve else f'NESSUS-{item.get("pluginID", "UNKNOWN")}',
                    'description': description[:200],  # Truncate long descriptions
                    'severity': severity_text,
                    'cvss': cvss
                }
                
                hosts[host_name]['vulnerabilities'].append(vuln)
        
        return list(hosts.values())
    
    except Exception as e:
        print(f"Error parsing Nessus file: {e}")
        return []


def main():
    """Parse zephinzer Nessus file."""
    
    nessus_file = 'datasets/comat-ceh-report/nessus/Target_Scan_d2cm6c.nessus'
    
    if not os.path.exists(nessus_file):
        print(f"Nessus file not found: {nessus_file}")
        return
    
    hosts = parse_nessus_file(nessus_file)
    
    if not hosts:
        print("No data extracted from Nessus file")
        return
    
    print(f"\n Extracted data from {len(hosts)} hosts")
    
    # Summary
    total_vulns = 0
    for host in hosts:
        vulns = host['vulnerabilities']
        total_vulns += len(vulns)
        
        critical = sum(1 for v in vulns if v['severity'] == 'CRITICAL')
        high = sum(1 for v in vulns if v['severity'] == 'HIGH')
        medium = sum(1 for v in vulns if v['severity'] == 'MEDIUM')
        low = sum(1 for v in vulns if v['severity'] == 'LOW')
        
        print(f"\nHost: {host['ip']}")
        print(f"  Total vulnerabilities: {len(vulns)}")
        print(f"  Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}")
    
    # Create baseline
    baseline = {
        'description': 'Baseline from zephinzer/comat-ceh-report Nessus scan',
        'source': 'Nessus professional vulnerability scanner',
        'created': '2026-03-14',
        'nessus_file': os.path.basename(nessus_file),
        'hosts': hosts
    }
    
    # Save baseline
    output_path = 'data/baseline/zephinzer_nessus_baseline.json'
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(baseline, f, indent=2)
    
    print(f"\n Baseline created: {output_path}")
    print(f"  Total hosts: {len(hosts)}")
    print(f"  Total vulnerabilities: {total_vulns}")


if __name__ == '__main__':
    main()
