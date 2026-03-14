import os
import json
from typing import Dict, List, Optional
from anthropic import Anthropic


class VulnerabilityAnalyzer:
    """Analyze processed scan data for vulnerabilities using rule-based and AI methods."""
    
    VULNERABILITY_DATABASE = {
        'ftp': {
            'default': {
                'cve': 'CVE-2011-2523',
                'description': 'FTP service - vsftpd 2.3.4 backdoor or plaintext credentials',
                'severity': 'CRITICAL',
                'cvss': 10.0,
                'recommendation': 'Replace FTP with SFTP or FTPS, update vsftpd'
            }
        },
        'telnet': {
            'default': {
                'cve': 'CWE-319',
                'description': 'Telnet transmits all data in plaintext',
                'severity': 'CRITICAL',
                'cvss': 9.8,
                'recommendation': 'Replace Telnet with SSH'
            }
        },
        'smb': {
            'default': {
                'cve': 'CVE-2007-2447',
                'description': 'Samba username map script command execution',
                'severity': 'CRITICAL',
                'cvss': 10.0,
                'recommendation': 'Update Samba, disable SMBv1, enable SMBv3 with encryption'
            }
        },
        'netbios-ssn': {
            'default': {
                'cve': 'CVE-2007-2447',
                'description': 'Samba username map script command execution',
                'severity': 'CRITICAL',
                'cvss': 10.0,
                'recommendation': 'Update Samba to latest version'
            }
        },
        'microsoft-ds': {
            'default': {
                'cve': 'CVE-2007-2447',
                'description': 'Samba username map script command execution',
                'severity': 'CRITICAL',
                'cvss': 10.0,
                'recommendation': 'Update Samba, disable SMBv1'
            }
        },
        'rdp': {
            'default': {
                'cve': 'CVE-2019-0708',
                'description': 'BlueKeep RDP vulnerability',
                'severity': 'CRITICAL',
                'cvss': 9.8,
                'recommendation': 'Apply security patches, use Network Level Authentication'
            }
        },
        'vnc': {
            'default': {
                'cve': 'CVE-2006-2369',
                'description': 'VNC authentication bypass vulnerability',
                'severity': 'HIGH',
                'cvss': 7.5,
                'recommendation': 'Use strong passwords, enable encryption, restrict access'
            }
        },
        'exec': {
            'default': {
                'cve': 'CVE-1999-0651',
                'description': 'R-services (rexec) allow remote command execution',
                'severity': 'CRITICAL',
                'cvss': 10.0,
                'recommendation': 'Disable rexec, use SSH instead'
            }
        },
        'login': {
            'default': {
                'cve': 'CVE-1999-0651',
                'description': 'R-services (rlogin) allow remote authentication bypass',
                'severity': 'CRITICAL',
                'cvss': 10.0,
                'recommendation': 'Disable rlogin, use SSH instead'
            }
        },
        'shell': {
            'default': {
                'cve': 'CVE-1999-0651',
                'description': 'R-services (rsh) allow remote shell access',
                'severity': 'CRITICAL',
                'cvss': 10.0,
                'recommendation': 'Disable rsh, use SSH instead'
            }
        },
        'mysql': {
            'default': {
                'cve': 'CVE-2012-2122',
                'description': 'MySQL authentication bypass vulnerability',
                'severity': 'CRITICAL',
                'cvss': 9.0,
                'recommendation': 'Update MySQL, use strong authentication, restrict network access'
            }
        },
        'postgresql': {
            'default': {
                'cve': 'CVE-2013-1899',
                'description': 'PostgreSQL privilege escalation vulnerability',
                'severity': 'HIGH',
                'cvss': 6.5,
                'recommendation': 'Update PostgreSQL, restrict database access'
            }
        },
        'java-rmi': {
            'default': {
                'cve': 'CVE-2011-3556',
                'description': 'Java RMI registry remote code execution',
                'severity': 'HIGH',
                'cvss': 7.5,
                'recommendation': 'Update Java, restrict RMI access, use authentication'
            }
        },
        'bindshell': {
            'default': {
                'cve': 'CVE-2004-2687',
                'description': 'Ingreslock backdoor allows root shell access',
                'severity': 'CRITICAL',
                'cvss': 10.0,
                'recommendation': 'Remove backdoor, reinstall system from trusted source'
            }
        },
        'nfs': {
            'default': {
                'cve': 'CVE-2004-0175',
                'description': 'NFS export misconfiguration allows unauthorized file access',
                'severity': 'HIGH',
                'cvss': 7.5,
                'recommendation': 'Configure NFS exports properly, use NFSv4 with Kerberos'
            }
        },
        'irc': {
            'default': {
                'cve': 'CVE-2010-2075',
                'description': 'UnrealIRCd backdoor command execution',
                'severity': 'CRITICAL',
                'cvss': 10.0,
                'recommendation': 'Update UnrealIRCd, verify software integrity'
            }
        },
        'ajp13': {
            'default': {
                'cve': 'CVE-2020-1938',
                'description': 'Apache Tomcat AJP Ghostcat vulnerability',
                'severity': 'HIGH',
                'cvss': 7.5,
                'recommendation': 'Update Tomcat, restrict AJP connector access'
            }
        },
        'x11': {
            'default': {
                'cve': 'CVE-2004-0419',
                'description': 'X11 allows remote display access',
                'severity': 'HIGH',
                'cvss': 7.5,
                'recommendation': 'Disable X11 forwarding, use SSH tunneling if needed'
            }
        }
    }
    
    def __init__(self, use_ai: bool = False):
        self.use_ai = use_ai
        self.anthropic_client = None
        
        if use_ai:
            api_key = os.getenv('ANTHROPIC_API_KEY')
            if api_key:
                self.anthropic_client = Anthropic(api_key=api_key)
            else:
                print("Warning: ANTHROPIC_API_KEY not set. AI analysis disabled.")
                self.use_ai = False
    
    def analyze(self, processed_data: Dict) -> Dict:
        """
        Analyze processed data for vulnerabilities.
        
        Args:
            processed_data: Processed scan data
            
        Returns:
            Analysis results with identified vulnerabilities
        """
        analysis = {
            'metadata': processed_data.get('metadata', {}),
            'summary': {
                'total_hosts': 0,
                'total_vulnerabilities': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0
            },
            'hosts': []
        }
        
        for host in processed_data.get('hosts', []):
            host_analysis = self._analyze_host(host)
            analysis['hosts'].append(host_analysis)
            
            analysis['summary']['total_hosts'] += 1
            analysis['summary']['total_vulnerabilities'] += len(host_analysis['vulnerabilities'])
            
            for vuln in host_analysis['vulnerabilities']:
                severity = vuln['severity'].lower()
                if severity == 'critical':
                    analysis['summary']['critical_count'] += 1
                elif severity == 'high':
                    analysis['summary']['high_count'] += 1
                elif severity == 'medium':
                    analysis['summary']['medium_count'] += 1
                else:
                    analysis['summary']['low_count'] += 1
        
        analysis['hosts'] = sorted(
            analysis['hosts'],
            key=lambda x: x['risk_score'],
            reverse=True
        )
        
        return analysis
    
    def _analyze_host(self, host: Dict) -> Dict:
        """Analyze individual host for vulnerabilities."""
        host_analysis = {
            'ip': host.get('ip', 'unknown'),
            'hostname': host.get('hostname', ''),
            'os': host.get('os', {}),
            'vulnerabilities': [],
            'risk_score': 0
        }
        
        for service in host.get('services', []):
            vulns = self._analyze_service(service, host.get('ip', ''))
            host_analysis['vulnerabilities'].extend(vulns)
        
        host_analysis['risk_score'] = self._calculate_risk_score(host_analysis['vulnerabilities'])
        
        host_analysis['vulnerabilities'] = sorted(
            host_analysis['vulnerabilities'],
            key=lambda x: x['cvss'],
            reverse=True
        )
        
        return host_analysis
    
    def _analyze_service(self, service: Dict, ip: str) -> List[Dict]:
        """Analyze individual service for vulnerabilities."""
        vulnerabilities = []
        
        service_name = service.get('service_name', '').lower()
        port = service.get('port', 0)
        product = service.get('product', '')
        version = service.get('version', '')
        
        vuln = self._check_known_vulnerabilities(service_name, product, version, port)
        if vuln:
            vulnerabilities.append(vuln)
        
        config_vuln = self._check_misconfigurations(service, port)
        if config_vuln:
            vulnerabilities.append(config_vuln)
        
        return vulnerabilities
    
    def _check_known_vulnerabilities(self, service: str, product: str, version: str, port: int) -> Optional[Dict]:
        """Check for known vulnerabilities based on service/product/version."""
        service_key = None
        
        # Direct service name match
        if service in self.VULNERABILITY_DATABASE:
            service_key = service
        # Check for partial matches
        else:
            for db_service in self.VULNERABILITY_DATABASE.keys():
                if db_service in service or service in db_service:
                    service_key = db_service
                    break
        
        # Port-based fallback for common services
        if not service_key:
            port_service_map = {
                21: 'ftp',
                23: 'telnet',
                139: 'netbios-ssn',
                445: 'microsoft-ds',
                512: 'exec',
                513: 'login',
                514: 'shell',
                1099: 'java-rmi',
                1524: 'bindshell',
                2049: 'nfs',
                3306: 'mysql',
                3389: 'rdp',
                5432: 'postgresql',
                5900: 'vnc',
                6000: 'x11',
                6667: 'irc',
                8009: 'ajp13'
            }
            service_key = port_service_map.get(port)
        
        if service_key and service_key in self.VULNERABILITY_DATABASE:
            vuln_template = self.VULNERABILITY_DATABASE[service_key]['default']
            
            return {
                'port': port,
                'service': service,
                'product': product,
                'version': version,
                'cve': vuln_template['cve'],
                'description': vuln_template['description'],
                'severity': vuln_template['severity'],
                'cvss': vuln_template['cvss'],
                'recommendation': vuln_template['recommendation'],
                'category': 'known_vulnerability'
            }
        
        return None
    
    def _check_misconfigurations(self, service: Dict, port: int) -> Optional[Dict]:
        """Check for common misconfigurations."""
        service_name = service.get('service_name', '').lower()
        
        if port in [80, 8080] and 'http' in service_name:
            return {
                'port': port,
                'service': service_name,
                'product': service.get('product', ''),
                'version': service.get('version', ''),
                'cve': 'CONFIG-001',
                'description': 'Unencrypted HTTP service detected',
                'severity': 'MEDIUM',
                'cvss': 5.3,
                'recommendation': 'Implement HTTPS with valid SSL/TLS certificate',
                'category': 'misconfiguration'
            }
        
        if not service.get('version') and service.get('features', {}).get('is_common_port'):
            return {
                'port': port,
                'service': service_name,
                'product': service.get('product', ''),
                'version': 'unknown',
                'cve': 'INFO-001',
                'description': 'Service version not detected - potential information disclosure issue',
                'severity': 'LOW',
                'cvss': 3.1,
                'recommendation': 'Configure service banner to hide version information',
                'category': 'information_disclosure'
            }
        
        return None
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score for a host."""
        if not vulnerabilities:
            return 0.0
        
        total_score = sum(vuln.get('cvss', 0) for vuln in vulnerabilities)
        
        critical_multiplier = sum(1.5 for vuln in vulnerabilities if vuln.get('severity') == 'CRITICAL')
        
        risk_score = total_score + critical_multiplier
        
        return round(risk_score, 2)
    
    def analyze_with_ai(self, host_data: Dict) -> Optional[str]:
        """Use Claude AI for contextual vulnerability analysis."""
        if not self.use_ai or not self.anthropic_client:
            return None
        
        try:
            prompt = self._construct_ai_prompt(host_data)
            
            response = self.anthropic_client.messages.create(
                model="claude-3-5-haiku-20241022",
                max_tokens=1024,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            return response.content[0].text
        
        except Exception as e:
            print(f"AI analysis error: {e}")
            return None
    
    def _construct_ai_prompt(self, host_data: Dict) -> str:
        """Construct prompt for AI analysis."""
        services = host_data.get('services', [])
        service_list = '\n'.join([
            f"- Port {s['port']}/{s['protocol']}: {s['service_name']} {s.get('product', '')} {s.get('version', '')}"
            for s in services
        ])
        
        prompt = f"""Analyze this network host for security vulnerabilities:

IP: {host_data.get('ip', 'unknown')}
OS: {host_data.get('os', {}).get('name', 'unknown')}

Open Services:
{service_list}

Provide:
1. Top 3 security concerns
2. Potential attack vectors
3. Priority remediation steps

Keep response concise and actionable."""
        
        return prompt
