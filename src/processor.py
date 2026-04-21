import json
from typing import Dict, List
import os


class DataProcessor:
    """Process and normalize parsed nmap data for analysis."""
    
    HIGH_RISK_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        135: 'MS RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        1433: 'MS SQL',
        1521: 'Oracle',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP Proxy',
        27017: 'MongoDB'
    }
    
    CRITICAL_SERVICES = ['telnet', 'ftp', 'rlogin', 'rsh', 'smb', 'netbios']
    
    def __init__(self):
        self.processed_data = {}
    
    def process(self, scan_data: Dict) -> Dict:
        """
        Process and normalize scan data.
        
        Args:
            scan_data: Raw parsed scan data
            
        Returns:
            Processed and normalized data
        """
        print("\n" + "="*80)
        print("🔧 PROCESSOR.PROCESS() CALLED")
        print(f"   Input hosts: {len(scan_data.get('hosts', []))}")
        print("="*80 + "\n")
        
        processed = {
            'metadata': {
                'scan_time': scan_data.get('scan_time', ''),
                'scanner': scan_data.get('scanner', 'nmap'),
                'version': scan_data.get('version', '')
            },
            'hosts': []
        }
        
        for host in scan_data.get('hosts', []):
            processed_host = self._process_host(host)
            if processed_host:
                processed['hosts'].append(processed_host)
        
        self.processed_data = processed
        return processed
    
    def _process_host(self, host: Dict) -> Dict:
        """Process individual host data."""
        ip_address = self._extract_ip(host)
        hostname = self._extract_hostname(host)
        
        processed_host = {
            'ip': ip_address,
            'hostname': hostname,
            'status': host.get('status', 'unknown'),
            'os': self._extract_os(host),
            'services': [],
            'risk_summary': {
                'critical_ports': 0,
                'high_risk_services': 0,
                'total_open_ports': 0
            }
        }
        
        for port in host.get('ports', []):
            service = self._process_service(port, ip_address)
            if service:
                processed_host['services'].append(service)
                
                if service['risk_level'] in ['critical', 'high']:
                    processed_host['risk_summary']['critical_ports'] += 1
                if service['service_name'] in self.CRITICAL_SERVICES:
                    processed_host['risk_summary']['high_risk_services'] += 1
        
        processed_host['risk_summary']['total_open_ports'] = len(processed_host['services'])
        
        # Debug: Show what processor is outputting
        print(f"\nPROCESSOR OUTPUT for {ip_address}:")
        print(f"  Total services: {len(processed_host['services'])}")
        smb_services = [s for s in processed_host['services'] if s.get('port') in [139, 445]]
        print(f"  SMB services (139, 445): {len(smb_services)}")
        for s in processed_host['services']:
            port = s.get('port')
            name = s.get('service_name')
            marker = "🔥 SMB" if port in [139, 445] else ""
            print(f"    Port {port}: {name} {marker}")
        
        return processed_host
    
    def _process_service(self, port: Dict, ip: str) -> Dict:
        """Process individual service/port data."""
        port_num = port.get('port', 0)
        protocol = port.get('protocol', 'tcp')
        service_info = port.get('service', {})
        
        service_name = service_info.get('name', 'unknown')
        product = service_info.get('product', '')
        version = service_info.get('version', '')
        cpe_list = service_info.get('cpe', [])  # Extract CPE data
        
        service = {
            'port': port_num,
            'protocol': protocol,
            'state': port.get('state', 'unknown'),
            'service_name': service_name,
            'product': product,
            'version': version,
            'cpe': cpe_list,  # Preserve CPE for vulnerability matching
            'banner': self._construct_banner(service_info),
            'risk_level': self._assess_port_risk(port_num, service_name),
            'features': self._extract_features(port_num, service_name, product, version)
        }
        
        return service
    
    def _extract_ip(self, host: Dict) -> str:
        """Extract IP address from host data."""
        addresses = host.get('addresses', [])
        for addr in addresses:
            if addr.get('addrtype') == 'ipv4':
                return addr.get('addr', 'unknown')
        return addresses[0].get('addr', 'unknown') if addresses else 'unknown'
    
    def _extract_hostname(self, host: Dict) -> str:
        """Extract hostname from host data."""
        hostnames = host.get('hostnames', [])
        if hostnames:
            return hostnames[0].get('name', '')
        return ''
    
    def _extract_os(self, host: Dict) -> Dict:
        """Extract OS information."""
        os_data = host.get('os', {})
        matches = os_data.get('matches', [])
        
        if matches:
            best_match = max(matches, key=lambda x: x.get('accuracy', 0))
            return {
                'name': best_match.get('name', 'unknown'),
                'accuracy': best_match.get('accuracy', 0),
                'matches': matches  # Preserve full matches for analyzer
            }
        
        return {'name': 'unknown', 'accuracy': 0, 'matches': []}
    
    def _construct_banner(self, service_info: Dict) -> str:
        """Construct service banner string."""
        parts = []
        if service_info.get('product'):
            parts.append(service_info['product'])
        if service_info.get('version'):
            parts.append(service_info['version'])
        if service_info.get('extrainfo'):
            parts.append(service_info['extrainfo'])
        
        return ' '.join(parts) if parts else ''
    
    def _assess_port_risk(self, port: int, service: str) -> str:
        """Assess risk level of a port/service."""
        if service.lower() in self.CRITICAL_SERVICES:
            return 'critical'
        
        if port in [21, 23, 445, 3389, 5900]:
            return 'critical'
        
        if port in self.HIGH_RISK_PORTS:
            return 'high'
        
        if port < 1024:
            return 'medium'
        
        return 'low'
    
    def _extract_features(self, port: int, service: str, product: str, version: str) -> Dict:
        """Extract features for analysis."""
        features = {
            'is_common_port': port in self.HIGH_RISK_PORTS,
            'is_privileged': port < 1024,
            'has_version': bool(version),
            'has_product': bool(product),
            'service_category': self._categorize_service(service)
        }
        
        return features
    
    def _categorize_service(self, service: str) -> str:
        """Categorize service type."""
        service_lower = service.lower()
        
        if service_lower in ['http', 'https', 'http-proxy']:
            return 'web'
        elif service_lower in ['ssh', 'telnet', 'rlogin']:
            return 'remote_access'
        elif service_lower in ['ftp', 'sftp', 'tftp']:
            return 'file_transfer'
        elif service_lower in ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb', 'redis']:
            return 'database'
        elif service_lower in ['smtp', 'pop3', 'imap']:
            return 'email'
        elif service_lower in ['smb', 'netbios', 'cifs']:
            return 'file_sharing'
        elif service_lower in ['dns']:
            return 'dns'
        else:
            return 'other'
    
    def save_json(self, output_path: str):
        """Save processed data to JSON file."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(self.processed_data, f, indent=2)
    
    def get_statistics(self) -> Dict:
        """Get processing statistics."""
        if not self.processed_data:
            return {}
        
        total_hosts = len(self.processed_data.get('hosts', []))
        total_services = sum(len(host.get('services', [])) for host in self.processed_data.get('hosts', []))
        critical_count = sum(
            host.get('risk_summary', {}).get('critical_ports', 0) 
            for host in self.processed_data.get('hosts', [])
        )
        
        return {
            'total_hosts': total_hosts,
            'total_services': total_services,
            'critical_services': critical_count
        }
