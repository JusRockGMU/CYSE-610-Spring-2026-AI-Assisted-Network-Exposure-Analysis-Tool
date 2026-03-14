#!/usr/bin/env python3
import argparse
import os
import sys
from datetime import datetime
from typing import Dict
from dotenv import load_dotenv

from src.parser import NmapParser
from src.processor import DataProcessor
from src.analyzer import VulnerabilityAnalyzer
from src.reporter import ReportGenerator
from src.evaluator import VulnerabilityEvaluator


class VulnerabilityPipeline:
    """Main pipeline orchestrator for vulnerability analysis."""
    
    def __init__(self, use_ai: bool = False, verbose: bool = False):
        self.use_ai = use_ai
        self.verbose = verbose
        self.parser = NmapParser()
        self.processor = DataProcessor()
        self.analyzer = VulnerabilityAnalyzer(use_ai=use_ai)
        self.reporter = ReportGenerator()
        self.evaluator = VulnerabilityEvaluator()
    
    def log(self, message: str):
        """Print log message if verbose mode enabled."""
        if self.verbose:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
    
    def run(self, input_path: str, output_dir: str = 'data/reports', 
            baseline_path: str = None, evaluate: bool = False) -> Dict:
        """
        Run the complete vulnerability analysis pipeline.
        
        Args:
            input_path: Path to nmap scan file
            output_dir: Directory for output reports
            baseline_path: Path to baseline vulnerability data (optional)
            evaluate: Whether to run evaluation against baseline
            
        Returns:
            Dictionary with pipeline results
        """
        print("\n" + "="*60)
        print("  AI-ASSISTED NETWORK EXPOSURE ANALYSIS")
        print("="*60 + "\n")
        
        self.log("Starting pipeline...")
        
        print("📥 Step 1: Parsing nmap scan data...")
        if input_path.endswith('.xml'):
            scan_data = self.parser.parse_xml(input_path)
        else:
            scan_data = self.parser.parse_text(input_path)
        
        summary = self.parser.get_summary()
        print(f"   ✓ Parsed {summary['total_hosts']} hosts with {summary['total_open_ports']} open ports")
        
        print("\n🔧 Step 2: Processing and normalizing data...")
        processed_data = self.processor.process(scan_data)
        
        processed_path = os.path.join('data/processed', f'processed_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        self.processor.save_json(processed_path)
        
        stats = self.processor.get_statistics()
        print(f"   ✓ Processed {stats['total_hosts']} hosts, {stats['total_services']} services")
        print(f"   ✓ Identified {stats['critical_services']} critical services")
        
        print("\n🔍 Step 3: Analyzing vulnerabilities...")
        analysis_data = self.analyzer.analyze(processed_data)
        
        summary = analysis_data['summary']
        print(f"   ✓ Found {summary['total_vulnerabilities']} vulnerabilities")
        print(f"   ✓ Critical: {summary['critical_count']}, High: {summary['high_count']}, " +
              f"Medium: {summary['medium_count']}, Low: {summary['low_count']}")
        
        print("\n📊 Step 4: Generating reports...")
        report_paths = self.reporter.generate(analysis_data, output_dir)
        
        print(f"   ✓ JSON report: {report_paths['json']}")
        print(f"   ✓ HTML report: {report_paths['html']}")
        
        results = {
            'scan_data': scan_data,
            'processed_data': processed_data,
            'analysis_data': analysis_data,
            'report_paths': report_paths
        }
        
        if evaluate and baseline_path:
            print("\n📈 Step 5: Evaluating against baseline...")
            try:
                self.evaluator.load_baseline(baseline_path)
                evaluation = self.evaluator.evaluate(analysis_data)
                
                print(self.evaluator.generate_report())
                
                eval_path = os.path.join(output_dir, f'evaluation_{report_paths["timestamp"]}.json')
                self.evaluator.save_evaluation(eval_path)
                print(f"   ✓ Evaluation saved: {eval_path}")
                
                results['evaluation'] = evaluation
            except Exception as e:
                print(f"   ⚠ Evaluation failed: {e}")
        
        print("\n" + "="*60)
        print("  ✅ PIPELINE COMPLETE")
        print("="*60 + "\n")
        
        return results


def run_demo():
    """Run demo with sample data."""
    print("\n" + "="*60)
    print("  DEMO MODE - Creating Sample Data")
    print("="*60 + "\n")
    
    demo_scan = """<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1710432000" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <hostnames>
      <hostname name="vulnerable-server.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp" product="vsftpd" version="2.3.4"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.29"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 3.X" accuracy="95"/>
    </os>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.101" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    
    os.makedirs('data/raw', exist_ok=True)
    demo_path = 'data/raw/demo_scan.xml'
    
    with open(demo_path, 'w') as f:
        f.write(demo_scan)
    
    print(f"✓ Created demo scan file: {demo_path}\n")
    
    pipeline = VulnerabilityPipeline(use_ai=False, verbose=True)
    pipeline.run(demo_path)


def main():
    """Main entry point."""
    load_dotenv()
    
    parser = argparse.ArgumentParser(
        description='AI-Assisted Network Exposure Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input data/raw/scan.xml
  %(prog)s --input data/raw/scan.xml --baseline data/baseline/known_vulns.json --evaluate
  %(prog)s --demo
  %(prog)s --input data/raw/scan.xml --ai --verbose
        """
    )
    
    parser.add_argument('--input', '-i', 
                       help='Path to nmap scan file (XML or text)')
    parser.add_argument('--output', '-o', 
                       default='data/reports',
                       help='Output directory for reports (default: data/reports)')
    parser.add_argument('--baseline', '-b',
                       help='Path to baseline vulnerability data for evaluation')
    parser.add_argument('--evaluate', '-e',
                       action='store_true',
                       help='Evaluate results against baseline')
    parser.add_argument('--ai',
                       action='store_true',
                       help='Enable AI-powered analysis using Claude')
    parser.add_argument('--demo',
                       action='store_true',
                       help='Run demo with sample data')
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.demo:
        run_demo()
        return 0
    
    if not args.input:
        parser.print_help()
        print("\nError: --input is required (or use --demo)")
        return 1
    
    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}")
        return 1
    
    if args.evaluate and not args.baseline:
        print("Error: --baseline is required when using --evaluate")
        return 1
    
    try:
        pipeline = VulnerabilityPipeline(use_ai=args.ai, verbose=args.verbose)
        pipeline.run(
            input_path=args.input,
            output_dir=args.output,
            baseline_path=args.baseline,
            evaluate=args.evaluate
        )
        return 0
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
