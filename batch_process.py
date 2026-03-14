#!/usr/bin/env python3
"""
Batch processing script for multiple nmap scans.
Generates individual reports plus a combined summary report.
"""
import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Dict

from src.parser import NmapParser
from src.processor import DataProcessor
from src.analyzer import VulnerabilityAnalyzer
from src.reporter import ReportGenerator
from src.summary_reporter import SummaryReportGenerator


def find_scan_files(directory: str) -> List[str]:
    """Find all XML scan files in subdirectories."""
    scan_files = []
    
    for target_dir in Path(directory).iterdir():
        if target_dir.is_dir():
            # Prefer version scan files
            version_scans = list(target_dir.glob("*version-scan*.xml"))
            if version_scans:
                scan_files.append(str(version_scans[0]))
            else:
                # Fallback to any XML file
                xml_files = list(target_dir.glob("*.xml"))
                if xml_files:
                    scan_files.append(str(xml_files[0]))
    
    return sorted(scan_files)


def process_single_scan(scan_file: str, use_ai: bool = False) -> Dict:
    """Process a single scan file and return the analysis data."""
    parser = NmapParser()
    processor = DataProcessor()
    analyzer = VulnerabilityAnalyzer(use_ai=use_ai)
    reporter = ReportGenerator()
    
    # Parse
    if scan_file.endswith('.xml'):
        scan_data = parser.parse_xml(scan_file)
    else:
        scan_data = parser.parse_text(scan_file)
    
    # Process
    processed_data = processor.process(scan_data)
    
    # Analyze
    analysis_data = analyzer.analyze(processed_data)
    
    # Generate individual report
    report_paths = reporter.generate(analysis_data, 'data/reports')
    
    # Return the full report data for summary
    return {
        'analysis': analysis_data,
        'scan_file': scan_file,
        'report_paths': report_paths
    }


def main():
    parser = argparse.ArgumentParser(
        description='Batch process multiple nmap scans and generate summary report'
    )
    parser.add_argument('directory', help='Directory containing scan subdirectories')
    parser.add_argument('--ai', action='store_true', help='Enable AI-powered analysis')
    parser.add_argument('--output', default='data/reports', help='Output directory for reports')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"Error: Directory not found: {args.directory}")
        return 1
    
    # Find all scan files
    scan_files = find_scan_files(args.directory)
    
    if not scan_files:
        print(f"Error: No scan files found in {args.directory}")
        return 1
    
    print("=" * 60)
    print("  BATCH PROCESSING")
    print("=" * 60)
    print(f"\nFound {len(scan_files)} targets to process\n")
    
    # Process each scan
    all_reports = []
    successful = 0
    
    for i, scan_file in enumerate(scan_files, 1):
        target_name = Path(scan_file).parent.name
        print(f"[{i}/{len(scan_files)}] Processing: {target_name}")
        print(f"  Scan: {Path(scan_file).name}")
        
        try:
            report_data = process_single_scan(scan_file, use_ai=args.ai)
            all_reports.append(report_data)
            successful += 1
            print("  Status: SUCCESS\n")
        except Exception as e:
            print(f"  Status: FAILED - {e}\n")
    
    # Generate summary report
    if all_reports:
        print("=" * 60)
        print("  GENERATING SUMMARY REPORT")
        print("=" * 60)
        
        summary_generator = SummaryReportGenerator()
        summary_paths = summary_generator.generate(all_reports, args.output)
        
        print(f"\nSummary JSON: {summary_paths['json']}")
        print(f"Summary HTML: {summary_paths['html']}")
    
    print("\n" + "=" * 60)
    print(f"  BATCH COMPLETE: Processed {successful}/{len(scan_files)} targets")
    print("=" * 60)
    print(f"Reports saved to: {args.output}\n")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
