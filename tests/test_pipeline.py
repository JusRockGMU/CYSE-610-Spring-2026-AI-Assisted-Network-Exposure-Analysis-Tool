import pytest
import os
import sys
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.parser import NmapParser
from src.processor import DataProcessor
from src.analyzer import VulnerabilityAnalyzer
from src.reporter import ReportGenerator
from src.evaluator import VulnerabilityEvaluator


def test_parser_xml():
    """Test nmap XML parsing."""
    parser = NmapParser()
    
    sample_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1710432000">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    
    test_file = '/tmp/test_scan.xml'
    with open(test_file, 'w') as f:
        f.write(sample_xml)
    
    data = parser.parse_xml(test_file)
    
    assert 'hosts' in data
    assert len(data['hosts']) == 1
    assert data['hosts'][0]['addresses'][0]['addr'] == '192.168.1.1'
    assert len(data['hosts'][0]['ports']) == 1
    
    os.remove(test_file)


def test_processor():
    """Test data processing."""
    processor = DataProcessor()
    
    sample_data = {
        'hosts': [{
            'status': 'up',
            'addresses': [{'addr': '192.168.1.1', 'addrtype': 'ipv4'}],
            'hostnames': [],
            'ports': [{
                'port': 23,
                'protocol': 'tcp',
                'state': 'open',
                'service': {'name': 'telnet'}
            }],
            'os': {}
        }]
    }
    
    processed = processor.process(sample_data)
    
    assert 'hosts' in processed
    assert len(processed['hosts']) == 1
    assert processed['hosts'][0]['ip'] == '192.168.1.1'
    assert len(processed['hosts'][0]['services']) == 1
    assert processed['hosts'][0]['services'][0]['risk_level'] == 'critical'


def test_analyzer():
    """Test vulnerability analysis."""
    analyzer = VulnerabilityAnalyzer(use_ai=False)
    
    processed_data = {
        'hosts': [{
            'ip': '192.168.1.1',
            'hostname': '',
            'os': {'name': 'Linux', 'accuracy': 90},
            'services': [{
                'port': 23,
                'protocol': 'tcp',
                'service_name': 'telnet',
                'product': '',
                'version': '',
                'risk_level': 'critical',
                'features': {}
            }]
        }]
    }
    
    analysis = analyzer.analyze(processed_data)
    
    assert 'summary' in analysis
    assert 'hosts' in analysis
    assert analysis['summary']['total_vulnerabilities'] > 0
    assert analysis['summary']['critical_count'] > 0


def test_evaluator():
    """Test evaluation against baseline."""
    evaluator = VulnerabilityEvaluator()
    
    baseline = {
        'hosts': [{
            'ip': '192.168.1.1',
            'vulnerabilities': [{
                'port': 23,
                'service': 'telnet'
            }]
        }]
    }
    
    analysis = {
        'hosts': [{
            'ip': '192.168.1.1',
            'vulnerabilities': [{
                'port': 23,
                'service': 'telnet'
            }]
        }]
    }
    
    evaluation = evaluator.evaluate(analysis, baseline)
    
    assert 'metrics' in evaluation
    assert evaluation['metrics']['precision'] == 1.0
    assert evaluation['metrics']['recall'] == 1.0
    assert evaluation['metrics']['f1_score'] == 1.0


def test_end_to_end():
    """Test complete pipeline."""
    sample_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1710432000">
  <host>
    <status state="up"/>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    
    test_file = '/tmp/test_e2e.xml'
    with open(test_file, 'w') as f:
        f.write(sample_xml)
    
    parser = NmapParser()
    processor = DataProcessor()
    analyzer = VulnerabilityAnalyzer(use_ai=False)
    
    scan_data = parser.parse_xml(test_file)
    processed_data = processor.process(scan_data)
    analysis_data = analyzer.analyze(processed_data)
    
    assert analysis_data['summary']['total_vulnerabilities'] >= 2
    assert analysis_data['summary']['critical_count'] >= 1
    
    os.remove(test_file)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
