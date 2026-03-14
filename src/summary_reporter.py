import json
import os
from datetime import datetime
from typing import Dict, List
from jinja2 import Template


class SummaryReportGenerator:
    """Generate summary reports for batch processing results."""
    
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Batch Vulnerability Analysis Summary</title>
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
            max-width: 1400px;
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
        .subtitle {
            color: #7f8c8d;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 2px solid #e9ecef;
        }
        .summary-card h3 {
            color: #6c757d;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        .summary-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
        }
        .summary-card.critical { border-color: #dc3545; }
        .summary-card.critical .number { color: #dc3545; }
        .summary-card.high { border-color: #fd7e14; }
        .summary-card.high .number { color: #fd7e14; }
        .summary-card.medium { border-color: #ffc107; }
        .summary-card.medium .number { color: #ffc107; }
        .summary-card.low { border-color: #28a745; }
        .summary-card.low .number { color: #28a745; }
        
        .host-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .host-table th {
            background: #2c3e50;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        .host-table td {
            padding: 12px;
            border-bottom: 1px solid #e9ecef;
        }
        .host-table tr:hover {
            background: #f8f9fa;
        }
        .risk-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .risk-badge.critical { background: #dc3545; color: white; }
        .risk-badge.high { background: #fd7e14; color: white; }
        .risk-badge.medium { background: #ffc107; color: #333; }
        .risk-badge.low { background: #28a745; color: white; }
        
        .chart-container {
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #3498db;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Batch Vulnerability Analysis Summary</h1>
        <p class="subtitle">Generated on {{ timestamp }} | {{ total_hosts }} hosts analyzed</p>

        <h2>Overall Statistics</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Hosts</h3>
                <div class="number">{{ total_hosts }}</div>
            </div>
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <div class="number">{{ total_vulnerabilities }}</div>
            </div>
            <div class="summary-card critical">
                <h3>Critical</h3>
                <div class="number">{{ critical_count }}</div>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <div class="number">{{ high_count }}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <div class="number">{{ medium_count }}</div>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <div class="number">{{ low_count }}</div>
            </div>
        </div>

        <h2>Host Summary</h2>
        <table class="host-table">
            <thead>
                <tr>
                    <th>Host IP</th>
                    <th>Hostname</th>
                    <th>Open Ports</th>
                    <th>Vulnerabilities</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Low</th>
                    <th>Risk Score</th>
                </tr>
            </thead>
            <tbody>
                {% for host in hosts %}
                <tr>
                    <td><strong>{{ host.ip }}</strong></td>
                    <td>{{ host.hostname or 'N/A' }}</td>
                    <td>{{ host.open_ports }}</td>
                    <td>{{ host.total_vulns }}</td>
                    <td>{{ host.critical }}</td>
                    <td>{{ host.high }}</td>
                    <td>{{ host.medium }}</td>
                    <td>{{ host.low }}</td>
                    <td>
                        <span class="risk-badge {% if host.risk_score > 20 %}critical{% elif host.risk_score > 15 %}high{% elif host.risk_score > 10 %}medium{% else %}low{% endif %}">
                            {{ host.risk_score }}
                        </span>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Top Vulnerabilities by Frequency</h2>
        <table class="host-table">
            <thead>
                <tr>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>Occurrences</th>
                    <th>Affected Hosts</th>
                </tr>
            </thead>
            <tbody>
                {% for vuln in top_vulnerabilities %}
                <tr>
                    <td>{{ vuln.description }}</td>
                    <td><span class="risk-badge {{ vuln.severity|lower }}">{{ vuln.severity }}</span></td>
                    <td>{{ vuln.count }}</td>
                    <td>{{ vuln.hosts|join(', ') }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
    """
    
    def generate(self, reports_data: List[Dict], output_dir: str) -> Dict:
        """
        Generate summary report from multiple scan results.
        
        Args:
            reports_data: List of individual report data
            output_dir: Directory to save summary report
            
        Returns:
            Dictionary with paths to generated summary reports
        """
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Aggregate data
        summary_data = self._aggregate_data(reports_data)
        
        # Generate reports
        json_path = os.path.join(output_dir, f'batch_summary_{timestamp}.json')
        html_path = os.path.join(output_dir, f'batch_summary_{timestamp}.html')
        
        self._generate_json(summary_data, json_path)
        self._generate_html(summary_data, html_path)
        
        return {
            'json': json_path,
            'html': html_path,
            'timestamp': timestamp
        }
    
    def _aggregate_data(self, reports_data: List[Dict]) -> Dict:
        """Aggregate data from multiple reports."""
        total_hosts = len(reports_data)
        total_vulnerabilities = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        hosts_summary = []
        vulnerability_tracker = {}
        
        for report in reports_data:
            analysis = report.get('analysis', {})
            summary = analysis.get('summary', {})
            hosts = analysis.get('hosts', [])
            
            # Aggregate totals
            total_vulnerabilities += summary.get('total_vulnerabilities', 0)
            critical_count += summary.get('critical_count', 0)
            high_count += summary.get('high_count', 0)
            medium_count += summary.get('medium_count', 0)
            low_count += summary.get('low_count', 0)
            
            # Process each host
            for host in hosts:
                host_ip = host.get('ip', 'unknown')
                host_vulns = host.get('vulnerabilities', [])
                
                # Count vulnerabilities by severity for this host
                host_critical = sum(1 for v in host_vulns if v.get('severity') == 'CRITICAL')
                host_high = sum(1 for v in host_vulns if v.get('severity') == 'HIGH')
                host_medium = sum(1 for v in host_vulns if v.get('severity') == 'MEDIUM')
                host_low = sum(1 for v in host_vulns if v.get('severity') == 'LOW')
                
                hosts_summary.append({
                    'ip': host_ip,
                    'hostname': host.get('hostname', ''),
                    'open_ports': len(host.get('vulnerabilities', [])),
                    'total_vulns': len(host_vulns),
                    'critical': host_critical,
                    'high': host_high,
                    'medium': host_medium,
                    'low': host_low,
                    'risk_score': host.get('risk_score', 0)
                })
                
                # Track vulnerability frequencies
                for vuln in host_vulns:
                    vuln_key = f"{vuln.get('cve', 'UNKNOWN')}_{vuln.get('description', '')}"
                    if vuln_key not in vulnerability_tracker:
                        vulnerability_tracker[vuln_key] = {
                            'description': vuln.get('description', 'Unknown'),
                            'severity': vuln.get('severity', 'UNKNOWN'),
                            'cve': vuln.get('cve', 'UNKNOWN'),
                            'count': 0,
                            'hosts': []
                        }
                    vulnerability_tracker[vuln_key]['count'] += 1
                    if host_ip not in vulnerability_tracker[vuln_key]['hosts']:
                        vulnerability_tracker[vuln_key]['hosts'].append(host_ip)
        
        # Sort hosts by risk score
        hosts_summary.sort(key=lambda x: x['risk_score'], reverse=True)
        
        # Get top vulnerabilities
        top_vulnerabilities = sorted(
            vulnerability_tracker.values(),
            key=lambda x: x['count'],
            reverse=True
        )[:10]
        
        return {
            'total_hosts': total_hosts,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'hosts': hosts_summary,
            'top_vulnerabilities': top_vulnerabilities,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def _generate_json(self, summary_data: Dict, output_path: str):
        """Generate JSON summary report."""
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': summary_data
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
    
    def _generate_html(self, summary_data: Dict, output_path: str):
        """Generate HTML summary report."""
        template = Template(self.HTML_TEMPLATE)
        
        html_content = template.render(**summary_data)
        
        with open(output_path, 'w') as f:
            f.write(html_content)
