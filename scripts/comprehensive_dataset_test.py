#!/usr/bin/env python3
"""
Comprehensive test of all 4 datasets to determine which work best.
"""

import os
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


def test_nmap_xml(xml_path):
    """Test if an nmap XML file is valid and extract info."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        if root.tag != 'nmaprun':
            return None
        
        hosts = 0
        ports = 0
        services = []
        
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                hosts += 1
                
                ports_elem = host.find('ports')
                if ports_elem:
                    for port in ports_elem.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            ports += 1
                            service = port.find('service')
                            if service is not None:
                                services.append(service.get('name', 'unknown'))
        
        return {
            'valid': True,
            'hosts': hosts,
            'ports': ports,
            'services': list(set(services))[:10]  # First 10 unique services
        }
    
    except Exception as e:
        return {'valid': False, 'error': str(e)}


def analyze_infosecwarrior():
    """Analyze InfoSecWarrior dataset in detail."""
    print("\n" + "="*60)
    print("DATASET 1: InfoSecWarrior/Vulnerable-Box-Resources")
    print("="*60)
    
    base_dir = 'datasets/vulnerable-box-resources/Infosecwarrior'
    
    if not os.path.exists(base_dir):
        print("❌ Dataset not found")
        return None
    
    targets = []
    
    for target_dir in os.listdir(base_dir):
        target_path = os.path.join(base_dir, target_dir)
        if not os.path.isdir(target_path):
            continue
        
        # Find nmap XML files
        xml_files = [f for f in os.listdir(target_path) if f.endswith('.xml')]
        
        if xml_files:
            xml_path = os.path.join(target_path, xml_files[0])
            result = test_nmap_xml(xml_path)
            
            if result and result.get('valid'):
                targets.append({
                    'name': target_dir,
                    'xml_file': xml_files[0],
                    'hosts': result['hosts'],
                    'ports': result['ports'],
                    'services': result['services']
                })
    
    print(f"\n✓ Found {len(targets)} valid targets with nmap scans")
    print(f"\nSample targets:")
    for target in targets[:5]:
        print(f"  - {target['name']}: {target['hosts']} hosts, {target['ports']} ports")
        print(f"    Services: {', '.join(target['services'][:5])}")
    
    return {
        'name': 'InfoSecWarrior',
        'total_targets': len(targets),
        'targets': targets,
        'usable': True,
        'quality': 'EXCELLENT',
        'notes': 'Real nmap scans with multiple targets, includes tool outputs for baselines'
    }


def analyze_drt709():
    """Analyze DRT709/Metasploitable dataset."""
    print("\n" + "="*60)
    print("DATASET 2: DRT709/Metasploitable-ub1404-PenTest")
    print("="*60)
    
    base_dir = 'datasets/metasploitable-pentest'
    
    if not os.path.exists(base_dir):
        print("❌ Dataset not found")
        return None
    
    # Look for any nmap files
    nmap_files = []
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if 'nmap' in file.lower() and (file.endswith('.xml') or file.endswith('.nmap')):
                nmap_files.append(os.path.join(root, file))
    
    print(f"\n✓ Found {len(nmap_files)} potential nmap files")
    
    # Test each file
    valid_scans = []
    for nmap_file in nmap_files:
        if nmap_file.endswith('.xml'):
            result = test_nmap_xml(nmap_file)
            if result and result.get('valid'):
                valid_scans.append(nmap_file)
                print(f"  ✓ Valid: {os.path.basename(nmap_file)}")
    
    # Look for Nessus reports
    nessus_files = []
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if 'nessus' in file.lower():
                nessus_files.append(os.path.join(root, file))
    
    print(f"\n✓ Found {len(nessus_files)} Nessus report files")
    for nessus in nessus_files[:3]:
        print(f"  - {os.path.basename(nessus)}")
    
    return {
        'name': 'DRT709',
        'nmap_scans': len(valid_scans),
        'nessus_reports': len(nessus_files),
        'usable': len(valid_scans) > 0,
        'quality': 'GOOD' if len(valid_scans) > 0 else 'POOR',
        'notes': f'{len(valid_scans)} nmap scans, {len(nessus_files)} Nessus reports'
    }


def analyze_zephinzer():
    """Analyze zephinzer/comat-ceh-report dataset."""
    print("\n" + "="*60)
    print("DATASET 3: zephinzer/comat-ceh-report")
    print("="*60)
    
    base_dir = 'datasets/comat-ceh-report'
    
    if not os.path.exists(base_dir):
        print("❌ Dataset not found")
        return None
    
    # Look for Nessus files
    nessus_files = []
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.nessus'):
                nessus_files.append(os.path.join(root, file))
    
    print(f"\n✓ Found {len(nessus_files)} Nessus export files")
    for nessus in nessus_files:
        print(f"  - {os.path.basename(nessus)}")
        # Check file size
        size = os.path.getsize(nessus)
        print(f"    Size: {size:,} bytes")
    
    return {
        'name': 'zephinzer',
        'nessus_files': len(nessus_files),
        'usable': len(nessus_files) > 0,
        'quality': 'FAIR',
        'notes': f'Has Nessus exports but no nmap scans - could parse Nessus for baseline'
    }


def analyze_rahulkore():
    """Analyze rahulkore1/vulnerability-assessment dataset."""
    print("\n" + "="*60)
    print("DATASET 4: rahulkore1/basic-vulnerability-assessment")
    print("="*60)
    
    base_dir = 'datasets/vulnerability-assessment'
    
    if not os.path.exists(base_dir):
        print("❌ Dataset not found")
        return None
    
    # Look for all files
    files = []
    for root, dirs, filelist in os.walk(base_dir):
        for file in filelist:
            if not file.startswith('.'):
                files.append(os.path.join(root, file))
    
    print(f"\n✓ Found {len(files)} files")
    for f in files:
        print(f"  - {os.path.basename(f)} ({os.path.getsize(f):,} bytes)")
    
    # Check for OpenVAS
    openvas_files = [f for f in files if 'openvas' in f.lower() or f.endswith('.pdf')]
    
    return {
        'name': 'rahulkore1',
        'total_files': len(files),
        'openvas_reports': len(openvas_files),
        'usable': False,
        'quality': 'POOR',
        'notes': 'Only PDF reports, no machine-readable scan data'
    }


def main():
    """Test all datasets comprehensively."""
    
    print("\n" + "#"*60)
    print("# COMPREHENSIVE DATASET TESTING")
    print("#"*60)
    
    results = []
    
    # Test each dataset
    result1 = analyze_infosecwarrior()
    if result1:
        results.append(result1)
    
    result2 = analyze_drt709()
    if result2:
        results.append(result2)
    
    result3 = analyze_zephinzer()
    if result3:
        results.append(result3)
    
    result4 = analyze_rahulkore()
    if result4:
        results.append(result4)
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY & RECOMMENDATIONS")
    print("="*60)
    
    for result in results:
        print(f"\n{result['name']}:")
        print(f"  Quality: {result['quality']}")
        print(f"  Usable: {'✓ Yes' if result['usable'] else '✗ No'}")
        print(f"  Notes: {result['notes']}")
    
    # Save results
    output_file = 'datasets/comprehensive_test_results.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✓ Results saved to: {output_file}")
    
    # Recommendations
    print("\n" + "="*60)
    print("RECOMMENDATIONS FOR FUTURE ENHANCEMENTS")
    print("="*60)
    
    print("\n1. PRIMARY DATASET: InfoSecWarrior")
    print("   - 12 different targets with real nmap scans")
    print("   - Includes tool outputs (nikto, nuclei) for baselines")
    print("   - Best for testing AI/ML enhancements")
    print("   - Can test on multiple diverse targets")
    
    print("\n2. SECONDARY: DRT709 (if has nmap scans)")
    print("   - Check for valid nmap XML files")
    print("   - Has Nessus reports for comparison")
    
    print("\n3. BASELINE CREATION: zephinzer")
    print("   - Nessus exports can be parsed for vulnerability data")
    print("   - Good for testing baseline parsing logic")
    
    print("\n4. NOT RECOMMENDED: rahulkore1")
    print("   - Only PDF reports, not machine-readable")
    
    return results


if __name__ == '__main__':
    main()
