#!/usr/bin/env python3
"""
Analyze all 11 InfoSecWarrior targets and select the best ones for validation.
"""

import os
import json
import xml.etree.ElementTree as ET
from collections import defaultdict


def analyze_target(target_dir, target_name):
    """Analyze a single target for completeness and vulnerability potential."""
    
    # Find nmap XML file
    xml_files = [f for f in os.listdir(target_dir) if f.endswith('.xml')]
    if not xml_files:
        return None
    
    xml_path = os.path.join(target_dir, xml_files[0])
    
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        analysis = {
            'name': target_name,
            'xml_file': xml_files[0],
            'hosts': 0,
            'ports': 0,
            'services': [],
            'versions': [],
            'scripts': 0,
            'tool_outputs': [],
            'vulnerability_indicators': 0,
            'score': 0
        }
        
        # Parse nmap data
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                analysis['hosts'] += 1
                
                # Get IP
                addr = host.find('address')
                if addr is not None:
                    analysis['ip'] = addr.get('addr')
                
                # Count ports and services
                ports_elem = host.find('ports')
                if ports_elem:
                    for port in ports_elem.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            analysis['ports'] += 1
                            
                            # Get service info
                            service = port.find('service')
                            if service is not None:
                                svc_name = service.get('name', 'unknown')
                                product = service.get('product', '')
                                version = service.get('version', '')
                                
                                analysis['services'].append(svc_name)
                                
                                if version:
                                    analysis['versions'].append(f"{product} {version}")
                                
                                # Check for vulnerable services
                                vuln_services = ['ftp', 'telnet', 'smb', 'microsoft-ds', 
                                               'netbios-ssn', 'mysql', 'postgresql', 
                                               'vnc', 'nfs', 'rpcbind', 'exec', 'login', 
                                               'shell', 'java-rmi', 'irc', 'ajp13']
                                
                                if svc_name in vuln_services:
                                    analysis['vulnerability_indicators'] += 1
                            
                            # Count NSE scripts
                            scripts = port.findall('script')
                            analysis['scripts'] += len(scripts)
                            
                            # Check for vulnerability indicators in scripts
                            for script in scripts:
                                script_id = script.get('id', '')
                                if any(keyword in script_id for keyword in 
                                      ['vuln', 'anon', 'default', 'brute', 'enum']):
                                    analysis['vulnerability_indicators'] += 1
        
        # Check for tool outputs
        for file in os.listdir(target_dir):
            if 'nikto' in file:
                analysis['tool_outputs'].append('nikto')
            elif 'nuclei' in file:
                analysis['tool_outputs'].append('nuclei')
            elif 'dirsearch' in file:
                analysis['tool_outputs'].append('dirsearch')
        
        analysis['tool_outputs'] = list(set(analysis['tool_outputs']))
        analysis['services'] = list(set(analysis['services']))
        
        # Calculate score
        score = 0
        score += analysis['ports'] * 2  # More ports = more attack surface
        score += len(analysis['services']) * 3  # Service diversity
        score += len(analysis['versions']) * 2  # Version info helps CVE mapping
        score += analysis['scripts'] * 1  # NSE scripts provide detail
        score += len(analysis['tool_outputs']) * 5  # Tool outputs = baseline data
        score += analysis['vulnerability_indicators'] * 10  # Known vuln services
        
        analysis['score'] = score
        
        return analysis
    
    except Exception as e:
        print(f"Error analyzing {target_name}: {e}")
        return None


def main():
    """Analyze all targets and select the best ones."""
    
    base_dir = 'datasets/vulnerable-box-resources/Infosecwarrior'
    
    print("\n" + "="*60)
    print("ANALYZING ALL 11 INFOSECWARRIOR TARGETS")
    print("="*60)
    
    targets = []
    
    for target_dir_name in sorted(os.listdir(base_dir)):
        target_path = os.path.join(base_dir, target_dir_name)
        
        if not os.path.isdir(target_path):
            continue
        
        print(f"\nAnalyzing: {target_dir_name}")
        
        analysis = analyze_target(target_path, target_dir_name)
        
        if analysis:
            targets.append(analysis)
            print(f"  ✓ Hosts: {analysis['hosts']}, Ports: {analysis['ports']}, "
                  f"Services: {len(analysis['services'])}, Score: {analysis['score']}")
            print(f"    Vulnerable services: {analysis['vulnerability_indicators']}")
            print(f"    Tool outputs: {', '.join(analysis['tool_outputs']) if analysis['tool_outputs'] else 'None'}")
            print(f"    Key services: {', '.join(analysis['services'][:5])}")
    
    # Sort by score
    targets.sort(key=lambda x: x['score'], reverse=True)
    
    # Select top 5
    print("\n" + "="*60)
    print("TOP 5 TARGETS (RECOMMENDED)")
    print("="*60)
    
    selected = targets[:5]
    
    for i, target in enumerate(selected, 1):
        print(f"\n{i}. {target['name']} (Score: {target['score']})")
        print(f"   IP: {target.get('ip', 'N/A')}")
        print(f"   Ports: {target['ports']}")
        print(f"   Services: {', '.join(target['services'][:8])}")
        print(f"   Vulnerable indicators: {target['vulnerability_indicators']}")
        print(f"   Tool outputs: {', '.join(target['tool_outputs'])}")
        print(f"   Versions found: {len(target['versions'])}")
    
    # Categorize by type
    print("\n" + "="*60)
    print("DIVERSITY ANALYSIS")
    print("="*60)
    
    service_coverage = defaultdict(list)
    for target in selected:
        for service in target['services']:
            service_coverage[service].append(target['name'])
    
    print(f"\nUnique services across top 5: {len(service_coverage)}")
    print("\nService coverage:")
    for service, target_list in sorted(service_coverage.items()):
        print(f"  {service}: {len(target_list)} targets")
    
    # Save results
    output = {
        'all_targets': targets,
        'selected_top_5': selected,
        'service_coverage': {k: v for k, v in service_coverage.items()}
    }
    
    output_file = 'datasets/target_selection.json'
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n✓ Analysis saved to: {output_file}")
    
    # Recommendations
    print("\n" + "="*60)
    print("RECOMMENDATIONS")
    print("="*60)
    
    print("\nFor comprehensive validation, use these 5 targets:")
    for i, target in enumerate(selected, 1):
        print(f"  {i}. {target['name']}")
    
    print("\nWhy these 5:")
    print("  ✓ Highest vulnerability indicators")
    print("  ✓ Most diverse service coverage")
    print("  ✓ Have tool outputs for baseline creation")
    print("  ✓ Version information for CVE mapping")
    
    print("\nNext steps:")
    print("  1. Create baselines for these 5 targets")
    print("  2. Test pipeline on each target")
    print("  3. Compare evaluation metrics")
    print("  4. Use for AI/ML training (3 train, 1 validate, 1 test)")
    
    return selected


if __name__ == '__main__':
    main()
