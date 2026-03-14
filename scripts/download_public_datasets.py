#!/usr/bin/env python3
"""
Download and test public vulnerability scan datasets from GitHub.
Based on datasets identified in the project plan.
"""

import os
import subprocess
import json
from pathlib import Path


def clone_repo(repo_url, target_dir):
    """Clone a GitHub repository."""
    print(f"\n{'='*60}")
    print(f"Cloning: {repo_url}")
    print(f"Target: {target_dir}")
    print('='*60)
    
    if os.path.exists(target_dir):
        print(f"  Directory already exists: {target_dir}")
        return True
    
    try:
        result = subprocess.run(
            ['git', 'clone', repo_url, target_dir],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            print(f" Successfully cloned")
            return True
        else:
            print(f" Clone failed: {result.stderr}")
            return False
    
    except Exception as e:
        print(f" Error: {e}")
        return False


def analyze_repo(repo_path, repo_name):
    """Analyze repository contents for nmap scans and reports."""
    print(f"\n{'='*60}")
    print(f"Analyzing: {repo_name}")
    print('='*60)
    
    if not os.path.exists(repo_path):
        print(f" Repository not found: {repo_path}")
        return None
    
    analysis = {
        'name': repo_name,
        'path': repo_path,
        'nmap_xml': [],
        'nmap_text': [],
        'nessus': [],
        'openvas': [],
        'other': []
    }
    
    # Walk through repository
    for root, dirs, files in os.walk(repo_path):
        # Skip .git directory
        if '.git' in root:
            continue
        
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, repo_path)
            
            # Categorize files
            if file.endswith('.xml'):
                # Check if it's nmap XML
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1000)
                        if 'nmaprun' in content or 'nmap' in content.lower():
                            analysis['nmap_xml'].append(rel_path)
                        elif 'nessus' in content.lower():
                            analysis['nessus'].append(rel_path)
                        else:
                            analysis['other'].append(rel_path)
                except:
                    pass
            
            elif file.endswith(('.nmap', '.gnmap')):
                analysis['nmap_text'].append(rel_path)
            
            elif 'nessus' in file.lower():
                analysis['nessus'].append(rel_path)
            
            elif 'openvas' in file.lower() or file.endswith('.ovas'):
                analysis['openvas'].append(rel_path)
            
            elif file.endswith(('.html', '.pdf', '.txt', '.json')):
                # Check content for vulnerability reports
                if any(keyword in file.lower() for keyword in ['vuln', 'scan', 'report', 'assessment']):
                    analysis['other'].append(rel_path)
    
    # Print summary
    print(f"\n Analysis Results:")
    print(f"  Nmap XML files:    {len(analysis['nmap_xml'])}")
    print(f"  Nmap text files:   {len(analysis['nmap_text'])}")
    print(f"  Nessus reports:    {len(analysis['nessus'])}")
    print(f"  OpenVAS reports:   {len(analysis['openvas'])}")
    print(f"  Other files:       {len(analysis['other'])}")
    
    if analysis['nmap_xml']:
        print(f"\n  Sample Nmap XML files:")
        for f in analysis['nmap_xml'][:3]:
            print(f"    - {f}")
    
    if analysis['nessus']:
        print(f"\n  Sample Nessus files:")
        for f in analysis['nessus'][:3]:
            print(f"    - {f}")
    
    if analysis['openvas']:
        print(f"\n  Sample OpenVAS files:")
        for f in analysis['openvas'][:3]:
            print(f"    - {f}")
    
    return analysis


def main():
    """Test all datasets from the project plan."""
    
    # Create datasets directory
    datasets_dir = 'datasets'
    os.makedirs(datasets_dir, exist_ok=True)
    
    print("\n" + "="*60)
    print("  TESTING PUBLIC DATASETS FROM PROJECT PLAN")
    print("="*60)
    
    # Dataset 1: DRT709/Metasploitable-ub1404-PenTest
    dataset1 = {
        'url': 'https://github.com/DRT709/Metasploitable-ub1404-PenTest.git',
        'dir': os.path.join(datasets_dir, 'metasploitable-pentest'),
        'name': 'DRT709/Metasploitable-ub1404-PenTest',
        'description': 'Nmap outputs (XML/HTML/PDF) plus Nessus reports'
    }
    
    # Dataset 2: zephinzer/comat-ceh-report
    dataset2 = {
        'url': 'https://github.com/zephinzer/comat-ceh-report.git',
        'dir': os.path.join(datasets_dir, 'comat-ceh-report'),
        'name': 'zephinzer/comat-ceh-report',
        'description': 'Nessus export artifacts'
    }
    
    # Dataset 3: rahulkore1/-basic-vulnerability-assessment
    dataset3 = {
        'url': 'https://github.com/rahulkore1/-basic-vulnerability-assessment.git',
        'dir': os.path.join(datasets_dir, 'vulnerability-assessment'),
        'name': 'rahulkore1/basic-vulnerability-assessment',
        'description': 'Nmap plus OpenVAS report outputs (Metasploitable 2)'
    }
    
    # Dataset 4: InfoSecWarrior/Vulnerable-Box-Resources (backup)
    dataset4 = {
        'url': 'https://github.com/InfoSecWarrior/Vulnerable-Box-Resources.git',
        'dir': os.path.join(datasets_dir, 'vulnerable-box-resources'),
        'name': 'InfoSecWarrior/Vulnerable-Box-Resources',
        'description': 'Large collection of Nmap outputs plus tool outputs'
    }
    
    datasets = [dataset1, dataset2, dataset3, dataset4]
    results = []
    
    # Test each dataset
    for dataset in datasets:
        print(f"\n\n{'#'*60}")
        print(f"# DATASET: {dataset['name']}")
        print(f"# {dataset['description']}")
        print('#'*60)
        
        # Clone repository
        success = clone_repo(dataset['url'], dataset['dir'])
        
        if success:
            # Analyze contents
            analysis = analyze_repo(dataset['dir'], dataset['name'])
            if analysis:
                analysis['description'] = dataset['description']
                results.append(analysis)
        else:
            print(f"  Skipping analysis due to clone failure")
    
    # Save results
    results_file = 'datasets/analysis_results.json'
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n\n{'='*60}")
    print("  SUMMARY")
    print('='*60)
    
    for result in results:
        total_nmap = len(result['nmap_xml']) + len(result['nmap_text'])
        total_reports = len(result['nessus']) + len(result['openvas'])
        
        print(f"\n{result['name']}:")
        print(f"  Nmap scans: {total_nmap}")
        print(f"  Benchmark reports: {total_reports}")
        
        if total_nmap > 0 and total_reports > 0:
            print(f"   GOOD - Has both nmap scans and benchmark reports")
        elif total_nmap > 0:
            print(f"    Has nmap scans but no benchmark reports")
        elif total_reports > 0:
            print(f"    Has benchmark reports but no nmap scans")
        else:
            print(f"   Missing both nmap scans and reports")
    
    print(f"\n Analysis complete. Results saved to: {results_file}")
    
    # Recommend best dataset
    print(f"\n{'='*60}")
    print("  RECOMMENDATION")
    print('='*60)
    
    best = None
    best_score = 0
    
    for result in results:
        score = len(result['nmap_xml']) * 2 + len(result['nmap_text']) + len(result['nessus']) + len(result['openvas'])
        if score > best_score:
            best_score = score
            best = result
    
    if best:
        print(f"\nBest dataset: {best['name']}")
        print(f"  Nmap XML: {len(best['nmap_xml'])}")
        print(f"  Nmap text: {len(best['nmap_text'])}")
        print(f"  Nessus: {len(best['nessus'])}")
        print(f"  OpenVAS: {len(best['openvas'])}")
        print(f"\nNext steps:")
        print(f"  1. Review files in: {best['path']}")
        print(f"  2. Copy nmap scans to: data/raw/")
        print(f"  3. Parse benchmark reports to create baseline")
    
    return results


if __name__ == '__main__':
    main()
