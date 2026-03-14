import json
import os
from datetime import datetime
from typing import Dict
from jinja2 import Template


class ReportGenerator:
    """Generate vulnerability reports in JSON and HTML formats."""
    
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Vulnerability Analysis Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #3498db;
        }
        h3 {
            color: #555;
            margin-top: 20px;
            margin-bottom: 10px;
        }
        .header {
            border-bottom: 3px solid #3498db;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .subtitle {
            color: #7f8c8d;
            font-size: 1.1em;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .summary-card.critical {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        .summary-card.high {
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }
        .summary-card.medium {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }
        .summary-card.low {
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        }
        .summary-card h3 {
            color: white;
            margin: 0;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .summary-card .number {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        .host-card {
            background: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .host-card.high-risk {
            border-left-color: #e74c3c;
            background: #fff5f5;
        }
        .host-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .host-ip {
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
        }
        .risk-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .risk-badge.critical {
            background: #e74c3c;
            color: white;
        }
        .risk-badge.high {
            background: #e67e22;
            color: white;
        }
        .risk-badge.medium {
            background: #f39c12;
            color: white;
        }
        .risk-badge.low {
            background: #27ae60;
            color: white;
        }
        .vulnerability {
            background: white;
            border: 1px solid #ddd;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 10px;
        }
        .vuln-title {
            font-weight: bold;
            color: #2c3e50;
            flex: 1;
        }
        .cvss-score {
            background: #34495e;
            color: white;
            padding: 3px 10px;
            border-radius: 4px;
            font-weight: bold;
            margin-left: 10px;
        }
        .vuln-details {
            color: #555;
            margin: 10px 0;
        }
        .vuln-recommendation {
            background: #e8f5e9;
            border-left: 3px solid #4caf50;
            padding: 10px;
            margin-top: 10px;
            font-style: italic;
        }
        .port-info {
            display: inline-block;
            background: #ecf0f1;
            padding: 3px 8px;
            border-radius: 3px;
            font-family: monospace;
            margin-right: 10px;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .no-vulns {
            text-align: center;
            padding: 40px;
            color: #27ae60;
            font-size: 1.2em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Network Vulnerability Analysis Report</h1>
            <p class="subtitle">Generated on {{ timestamp }}</p>
        </div>

        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="summary-card">
                <h3>Total Hosts</h3>
                <div class="number">{{ summary.total_hosts }}</div>
            </div>
            <div class="summary-card critical">
                <h3>Critical</h3>
                <div class="number">{{ summary.critical_count }}</div>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <div class="number">{{ summary.high_count }}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <div class="number">{{ summary.medium_count }}</div>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <div class="number">{{ summary.low_count }}</div>
            </div>
        </div>

        <h2>Detailed Findings</h2>
        {% if hosts %}
            {% for host in hosts %}
            <div class="host-card {% if host.risk_score > 15 %}high-risk{% endif %}">
                <div class="host-header">
                    <div>
                        <div class="host-ip">{{ host.ip }}</div>
                        {% if host.hostname %}
                        <div style="color: #7f8c8d;">{{ host.hostname }}</div>
                        {% endif %}
                        {% if host.os.name != 'unknown' %}
                        <div style="color: #7f8c8d; font-size: 0.9em;">OS: {{ host.os.name }}</div>
                        {% endif %}
                    </div>
                    <div class="risk-badge {% if host.risk_score > 20 %}critical{% elif host.risk_score > 15 %}high{% elif host.risk_score > 10 %}medium{% else %}low{% endif %}">
                        Risk Score: {{ host.risk_score }}
                    </div>
                </div>

                {% if host.vulnerabilities %}
                <h3>Vulnerabilities ({{ host.vulnerabilities|length }})</h3>
                {% for vuln in host.vulnerabilities %}
                <div class="vulnerability">
                    <div class="vuln-header">
                        <div class="vuln-title">
                            <span class="port-info">Port {{ vuln.port }}</span>
                            {{ vuln.description }}
                        </div>
                        <span class="cvss-score">CVSS: {{ vuln.cvss }}</span>
                    </div>
                    <div class="vuln-details">
                        <strong>Service:</strong> {{ vuln.service }}
                        {% if vuln.product %}
                        | <strong>Product:</strong> {{ vuln.product }}
                        {% endif %}
                        {% if vuln.version %}
                        {{ vuln.version }}
                        {% endif %}
                        <br>
                        <strong>CVE:</strong> {{ vuln.cve }} | <strong>Severity:</strong> 
                        <span class="risk-badge {{ vuln.severity|lower }}">{{ vuln.severity }}</span>
                    </div>
                    <div class="vuln-recommendation">
                        <strong> Recommendation:</strong> {{ vuln.recommendation }}
                    </div>
                </div>
                {% endfor %}
                {% else %}
                <p style="color: #27ae60; padding: 10px;"> No vulnerabilities detected</p>
                {% endif %}
            </div>
            {% endfor %}
        {% else %}
            <div class="no-vulns">
                 No hosts with vulnerabilities detected
            </div>
        {% endif %}

        <div class="footer">
            <p>AI-Assisted Network Exposure Analysis Tool</p>
            <p>CYSE 610 - Network Security Project</p>
        </div>
    </div>
</body>
</html>
    """
    
    def __init__(self):
        self.report_data = {}
    
    def generate(self, analysis_data: Dict, output_dir: str) -> Dict:
        """
        Generate reports in multiple formats.
        
        Args:
            analysis_data: Analysis results
            output_dir: Directory to save reports
            
        Returns:
            Dictionary with paths to generated reports
        """
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Get host identifier for unique filename
        host_id = 'unknown'
        hosts = analysis_data.get('hosts', [])
        if hosts:
            first_host = hosts[0]
            host_id = first_host.get('ip', 'unknown').replace('.', '_')
            if not host_id or host_id == 'unknown':
                host_id = first_host.get('hostname', 'unknown').replace('.', '_')
        
        json_path = os.path.join(output_dir, f'vulnerability_report_{host_id}_{timestamp}.json')
        html_path = os.path.join(output_dir, f'vulnerability_report_{host_id}_{timestamp}.html')
        
        self._generate_json(analysis_data, json_path)
        self._generate_html(analysis_data, html_path)
        
        return {
            'json': json_path,
            'html': html_path,
            'timestamp': timestamp
        }
    
    def _generate_json(self, analysis_data: Dict, output_path: str):
        """Generate JSON report."""
        report = {
            'generated_at': datetime.now().isoformat(),
            'analysis': analysis_data
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.report_data = report
    
    def _generate_html(self, analysis_data: Dict, output_path: str):
        """Generate HTML report."""
        template = Template(self.HTML_TEMPLATE)
        
        html_content = template.render(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            summary=analysis_data.get('summary', {}),
            hosts=analysis_data.get('hosts', [])
        )
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def get_summary(self) -> Dict:
        """Get report summary."""
        if not self.report_data:
            return {}
        
        analysis = self.report_data.get('analysis', {})
        summary = analysis.get('summary', {})
        
        return {
            'total_vulnerabilities': summary.get('total_vulnerabilities', 0),
            'critical_count': summary.get('critical_count', 0),
            'high_count': summary.get('high_count', 0),
            'hosts_analyzed': summary.get('total_hosts', 0)
        }
