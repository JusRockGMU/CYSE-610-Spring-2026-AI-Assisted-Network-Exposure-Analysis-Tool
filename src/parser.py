import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
import json
import os


class NmapParser:
    """Parse nmap scan output (XML format) and extract relevant information."""
    
    def __init__(self):
        self.scan_data = {}
    
    def parse_xml(self, xml_path: str) -> Dict:
        """
        Parse nmap XML output file.
        
        Args:
            xml_path: Path to nmap XML file
            
        Returns:
            Dictionary containing parsed scan data
        """
        if not os.path.exists(xml_path):
            raise FileNotFoundError(f"Scan file not found: {xml_path}")
        
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        scan_info = {
            'scan_time': root.get('start', ''),
            'scanner': root.get('scanner', 'nmap'),
            'version': root.get('version', ''),
            'hosts': []
        }
        
        for host in root.findall('host'):
            host_data = self._parse_host(host)
            if host_data:
                scan_info['hosts'].append(host_data)
        
        self.scan_data = scan_info
        return scan_info
    
    def _parse_host(self, host_elem) -> Optional[Dict]:
        """Parse individual host element."""
        status = host_elem.find('status')
        if status is None or status.get('state') != 'up':
            return None
        
        host_data = {
            'status': 'up',
            'addresses': [],
            'hostnames': [],
            'ports': [],
            'os': {}
        }
        
        for addr in host_elem.findall('address'):
            host_data['addresses'].append({
                'addr': addr.get('addr'),
                'addrtype': addr.get('addrtype')
            })
        
        hostnames = host_elem.find('hostnames')
        if hostnames is not None:
            for hostname in hostnames.findall('hostname'):
                host_data['hostnames'].append({
                    'name': hostname.get('name'),
                    'type': hostname.get('type')
                })
        
        ports = host_elem.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_data = self._parse_port(port)
                if port_data:
                    host_data['ports'].append(port_data)
        
        os_elem = host_elem.find('os')
        if os_elem is not None:
            host_data['os'] = self._parse_os(os_elem)
        
        return host_data
    
    def _parse_port(self, port_elem) -> Optional[Dict]:
        """Parse individual port element."""
        state = port_elem.find('state')
        if state is None or state.get('state') != 'open':
            return None
        
        port_data = {
            'port': int(port_elem.get('portid')),
            'protocol': port_elem.get('protocol'),
            'state': state.get('state'),
            'service': {}
        }
        
        service = port_elem.find('service')
        if service is not None:
            port_data['service'] = {
                'name': service.get('name', ''),
                'product': service.get('product', ''),
                'version': service.get('version', ''),
                'extrainfo': service.get('extrainfo', ''),
                'ostype': service.get('ostype', '')
            }
        
        scripts = []
        for script in port_elem.findall('script'):
            scripts.append({
                'id': script.get('id'),
                'output': script.get('output', '')
            })
        if scripts:
            port_data['scripts'] = scripts
        
        return port_data
    
    def _parse_os(self, os_elem) -> Dict:
        """Parse OS detection information."""
        os_data = {
            'matches': []
        }
        
        for osmatch in os_elem.findall('osmatch'):
            os_data['matches'].append({
                'name': osmatch.get('name'),
                'accuracy': int(osmatch.get('accuracy', 0))
            })
        
        return os_data
    
    def parse_text(self, text_path: str) -> Dict:
        """
        Parse nmap text output (basic parsing).
        
        Args:
            text_path: Path to nmap text file
            
        Returns:
            Dictionary containing parsed scan data
        """
        if not os.path.exists(text_path):
            raise FileNotFoundError(f"Scan file not found: {text_path}")
        
        with open(text_path, 'r') as f:
            content = f.read()
        
        scan_info = {
            'scan_time': '',
            'scanner': 'nmap',
            'version': '',
            'hosts': []
        }
        
        current_host = None
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if 'Nmap scan report for' in line:
                if current_host:
                    scan_info['hosts'].append(current_host)
                
                ip = line.split('for')[-1].strip()
                current_host = {
                    'status': 'up',
                    'addresses': [{'addr': ip, 'addrtype': 'ipv4'}],
                    'hostnames': [],
                    'ports': [],
                    'os': {}
                }
            
            elif current_host and '/' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split('/')
                    if len(port_proto) == 2:
                        try:
                            port_num = int(port_proto[0])
                            protocol = port_proto[1]
                            state = parts[1]
                            service = parts[2] if len(parts) > 2 else ''
                            
                            current_host['ports'].append({
                                'port': port_num,
                                'protocol': protocol,
                                'state': state,
                                'service': {'name': service}
                            })
                        except ValueError:
                            continue
        
        if current_host:
            scan_info['hosts'].append(current_host)
        
        self.scan_data = scan_info
        return scan_info
    
    def save_json(self, output_path: str):
        """Save parsed data to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(self.scan_data, f, indent=2)
    
    def get_summary(self) -> Dict:
        """Get summary statistics of the scan."""
        if not self.scan_data:
            return {}
        
        total_hosts = len(self.scan_data.get('hosts', []))
        total_ports = sum(len(host.get('ports', [])) for host in self.scan_data.get('hosts', []))
        
        return {
            'total_hosts': total_hosts,
            'total_open_ports': total_ports,
            'scan_time': self.scan_data.get('scan_time', 'unknown')
        }
