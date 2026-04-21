import os
import json
from typing import Dict, List, Optional
from anthropic import Anthropic
from .nvd_client import NVDClient


class VulnerabilityAnalyzer:
    """Analyze processed scan data for vulnerabilities using rule-based and AI methods."""
    
    # All vulnerability detection now uses NVD API automation
    # No hardcoded rules - rely on context-aware NVD queries with KEV prioritization
    VULNERABILITY_DATABASE = {}
    
    def __init__(self, use_ai: bool = False, use_nvd: bool = True):
        """Initialize the analyzer with optional AI and NVD support."""
        self.use_ai = use_ai
        self.use_nvd = use_nvd
        self.anthropic_client = None
        self.nvd_client = None
        
        if use_ai:
            api_key = os.getenv('ANTHROPIC_API_KEY')
            if api_key:
                self.anthropic_client = Anthropic(api_key=api_key)
            else:
                print("Warning: ANTHROPIC_API_KEY not found. AI features disabled.")
        
        if use_nvd:
            # Initialize NVD client (can optionally use NVD_API_KEY env var for higher rate limits)
            nvd_api_key = os.getenv('NVD_API_KEY')
            self.nvd_client = NVDClient(api_key=nvd_api_key)
            print("NVD API integration enabled for real-time CVE lookups")
    
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
        
        # Extract OS context for better vulnerability detection
        os_context = self._extract_os_context(host.get('os', {}))
        
        services = host.get('services', [])
        print(f"\n{'='*80}")
        print(f"DEBUG: Analyzer received {len(services)} services for host {host.get('ip', 'unknown')}")
        print(f"{'='*80}")
        
        smb_services = [s for s in services if s.get('port') in [139, 445]]
        print(f"SMB services (139, 445): {len(smb_services)} found")
        
        for i, service in enumerate(services):
            port = service.get('port')
            name = service.get('service_name')
            marker = "🔥 SMB" if port in [139, 445] else ""
            print(f"DEBUG: Service {i+1}/{len(services)}: port={port}, name={name} {marker}")
        print(f"{'='*80}\n")
        
        for service in services:
            vulns = self._analyze_service(service, host.get('ip', ''), os_context)
            host_analysis['vulnerabilities'].extend(vulns)
        
        # Consolidate duplicate CVEs across multiple ports
        host_analysis['vulnerabilities'] = self._consolidate_vulnerabilities(host_analysis['vulnerabilities'])
        
        # Generate AI explanations for each vulnerability if AI is enabled
        if self.use_ai and self.anthropic_client:
            from .explainer import VulnerabilityExplainer
            explainer = VulnerabilityExplainer()
            
            for vuln in host_analysis['vulnerabilities']:
                try:
                    explanation = explainer.explain_vulnerability(vuln, host_analysis)
                    vuln['ai_explanation'] = explanation
                except Exception as e:
                    print(f"Failed to generate AI explanation: {e}")
                    vuln['ai_explanation'] = None
        
        host_analysis['risk_score'] = self._calculate_risk_score(host_analysis['vulnerabilities'])
        
        host_analysis['vulnerabilities'] = sorted(
            host_analysis['vulnerabilities'],
            key=lambda x: x['cvss'],
            reverse=True
        )
        
        return host_analysis
    
    def _extract_os_context(self, os_data: Dict) -> Dict:
        """Extract OS context for vulnerability detection."""
        context = {
            'os_name': None,
            'os_version': None,
            'os_family': None
        }
        
        matches = os_data.get('matches', [])
        if matches:
            # Use highest accuracy match
            best_match = matches[0]
            os_name = best_match.get('name', '')
            print(f"DEBUG: Detected OS: {os_name}")
            
            # Extract OS family and version
            if 'Windows 7' in os_name:
                context['os_name'] = 'Windows 7'
                context['os_family'] = 'Windows'
                if 'SP1' in os_name:
                    context['os_version'] = 'SP1'
            elif 'Windows Server 2008' in os_name:
                context['os_name'] = 'Windows Server 2008'
                context['os_family'] = 'Windows'
                if 'R2' in os_name:
                    context['os_version'] = 'R2'
            elif 'Windows 10' in os_name:
                context['os_name'] = 'Windows 10'
                context['os_family'] = 'Windows'
            elif 'Windows' in os_name:
                context['os_family'] = 'Windows'
            elif 'Linux' in os_name:
                context['os_family'] = 'Linux'
            elif 'Ubuntu' in os_name:
                context['os_name'] = 'Ubuntu'
                context['os_family'] = 'Linux'
            
            print(f"DEBUG: OS Context: {context}")
        else:
            print("DEBUG: No OS matches found in scan data")
        
        return context
    
    def _consolidate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Consolidate duplicate CVEs across multiple ports into single entries."""
        cve_map = {}
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve', 'UNKNOWN')
            
            if cve_id in cve_map:
                # CVE already exists, add this port to the list
                existing = cve_map[cve_id]
                if isinstance(existing['port'], list):
                    if vuln['port'] not in existing['port']:
                        existing['port'].append(vuln['port'])
                else:
                    # Convert single port to list
                    existing['port'] = [existing['port'], vuln['port']]
            else:
                # New CVE, add to map
                cve_map[cve_id] = vuln.copy()
        
        return list(cve_map.values())
    
    def _analyze_service(self, service: Dict, ip: str, os_context: Dict = None) -> List[Dict]:
        """Analyze individual service for vulnerabilities."""
        vulnerabilities = []
        
        service_name = service.get('service_name', '').lower()
        port = service.get('port', 0)
        product = service.get('product', '')
        version = service.get('version', '')
        
        print(f"DEBUG: Analyzing service - port={port}, service_name={service_name}, product={product}")
        
        # Pass full service data and OS context for better detection
        vuln = self._check_known_vulnerabilities(service_name, product, version, port, service, os_context)
        if vuln:
            vulnerabilities.append(vuln)
            print(f"DEBUG: Found vulnerability for port {port}: {vuln.get('cve', 'UNKNOWN')}")
        else:
            print(f"DEBUG: No vulnerability found for port {port}, service {service_name}")
        
        config_vuln = self._check_misconfigurations(service, port)
        if config_vuln:
            vulnerabilities.append(config_vuln)
        
        return vulnerabilities
    
    def _check_known_vulnerabilities(self, service: str, product: str, version: str, port: int, service_data: Dict = None, os_context: Dict = None) -> Optional[Dict]:
        """
        Check for known vulnerabilities using CPE-first approach:
        1. Try CPE-based matching (most precise)
        2. Fallback to keyword search if no CPE available
        3. Prioritize CISA KEV (actively exploited)
        4. Filter for relevance and impact
        """
        
        if not self.use_nvd or not self.nvd_client:
            # Fallback to hardcoded rules if NVD not available
            return self._check_hardcoded_vulnerabilities(service, product, version, port)
        
        nvd_cves = []
        
        # STRATEGY 1: Try CPE-based matching first (most precise)
        cpe_list = service_data.get('cpe', []) if service_data else []
        if cpe_list:
            print(f"DEBUG: Found {len(cpe_list)} CPE entries for port {port}")
            for cpe in cpe_list:
                # Only use application-level CPE (cpe:/a:... or cpe:2.3:a:...), not OS-level (cpe:/o:...)
                if 'cpe:/a:' in cpe or 'cpe:2.3:a:' in cpe:
                    print(f"DEBUG: Querying NVD with application CPE: {cpe}")
                    cpe_cves = self.nvd_client.search_cves_by_cpe(cpe)
                    nvd_cves.extend(cpe_cves)
                    if cpe_cves:
                        print(f"DEBUG: CPE query returned {len(cpe_cves)} CVEs - using precise matching")
                        # If CPE matching found results, use them (no need for keyword fallback)
                        break
        
        # STRATEGY 2: Fallback to keyword search if no CPE results
        if not nvd_cves:
            print(f"DEBUG: No CPE results, falling back to keyword search")
            search_keywords = self._build_search_keywords(service, product, os_context)
            
            for keyword in search_keywords:
                cves = self._lookup_nvd_by_keyword(keyword, version)
                nvd_cves.extend(cves)
        
        if nvd_cves:
            # Remove duplicates
            seen_cves = set()
            unique_cves = []
            for cve in nvd_cves:
                cve_id = cve.get('cve_id')
                if cve_id and cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    unique_cves.append(cve)
            
            # Prioritize and filter
            filtered_cves = self._prioritize_vulnerabilities(unique_cves, service, os_context, product)
            
            if filtered_cves:
                # Return highest priority vulnerability
                return self._format_nvd_vulnerability(filtered_cves[0], service, product, version, port, service_data)
        
        # Fallback to hardcoded rules
        return self._check_hardcoded_vulnerabilities(service, product, version, port)
    
    def _build_search_keywords(self, service: str, product: str, os_context: Dict = None) -> List[str]:
        """Build context-aware search keywords for better NVD matching."""
        keywords = []
        
        print(f"DEBUG: Building keywords for service={service}, product={product}, os_context={os_context}")
        
        # For Windows services, combine OS + service
        if os_context and os_context.get('os_family') == 'Windows':
            os_name = os_context.get('os_name', 'Windows')
            
            # SMB/NetBIOS services - search for OS-level SMB vulnerabilities
            if service in ['microsoft-ds', 'netbios-ssn', 'smb']:
                keywords.append(f"{os_name} SMB")
                keywords.append(f"{os_name} Server Message Block")
                if 'Windows 7' in os_name:
                    keywords.append("MS17-010")  # EternalBlue
                print(f"DEBUG: SMB service detected, added Windows SMB keywords")
            
            # RPC services
            elif service in ['msrpc', 'rpc']:
                keywords.append(f"{os_name} RPC")
                keywords.append(f"{os_name} Remote Procedure Call")
                print(f"DEBUG: RPC service detected, added Windows RPC keywords")
        
        # Product-based search (if specific product detected)
        if product and product != 'N/A':
            # Clean product name
            product_clean = product.split()[0:3]  # Take first few words
            keywords.append(' '.join(product_clean))
        
        # Service-based search
        if service and service not in ['unknown', 'tcpwrapped']:
            keywords.append(service)
        
        final_keywords = keywords if keywords else [product if product != 'N/A' else service]
        print(f"DEBUG: Final keywords: {final_keywords}")
        return final_keywords
    
    def _prioritize_vulnerabilities(self, cves: List[Dict], service: str, os_context: Dict = None, product: str = None) -> List[Dict]:
        """Prioritize CVEs by impact, exploitability, and relevance."""
        
        # Filter for relevance FIRST (remove irrelevant products)
        relevant_cves = self._filter_relevant_cves(cves, service, os_context, product)
        print(f"DEBUG: Filtered {len(cves)} CVEs -> {len(relevant_cves)} relevant CVEs")
        
        # Score each CVE
        scored_cves = []
        for cve in relevant_cves:
            score = 0
            
            # CISA KEV = highest priority (actively exploited)
            if cve.get('in_kev'):
                score += 1000
            
            # CVSS score
            cvss = cve.get('cvss_score', 0)
            score += cvss * 10
            
            # Recency (newer CVEs often more relevant)
            published = cve.get('published', '')
            if '2017' in published or '2018' in published or '2019' in published:
                score += 50  # Recent but not too old
            elif '2020' in published or '2021' in published or '2022' in published or '2023' in published or '2024' in published:
                score += 100  # Very recent
            
            # Severity
            severity = cve.get('severity', '').upper()
            if severity == 'CRITICAL':
                score += 200
            elif severity == 'HIGH':
                score += 100
            
            scored_cves.append((score, cve))
        
        # Sort by score (highest first)
        scored_cves.sort(key=lambda x: x[0], reverse=True)
        
        # Return ALL CVEs (no limit)
        print(f"DEBUG: Returning {len(scored_cves)} CVEs after prioritization (no filtering)")
        return [cve for score, cve in scored_cves]
    
    def _filter_relevant_cves(self, cves: List[Dict], service: str, os_context: Dict = None, product: str = None) -> List[Dict]:
        """Filter CVEs for relevance to the actual service/OS being analyzed."""
        if not cves:
            return []
        
        relevant = []
        
        # Define irrelevant product keywords that should be excluded
        irrelevant_keywords = [
            'universal media server', 'ums 7.', 'cyberpanel', 'kaseya',
            'samba', 'linux', 'unix', 'qemu', 'vnc server', 'postgresql',
            'mysql', 'mongodb', 'redis', 'elasticsearch', 'upnp', 'ssdp',
            'wordpress', 'joomla', 'drupal', 'proftpd', 'vsftpd', 'pureftpd'
        ]
        
        # For Windows services, filter out non-Windows CVEs
        if os_context and os_context.get('os_family') == 'Windows':
            for cve in cves:
                description = cve.get('description', '').lower()
                
                # FIRST: Skip CVEs that mention irrelevant products (hard exclude)
                is_irrelevant = any(keyword in description for keyword in irrelevant_keywords)
                if is_irrelevant:
                    continue
                
                # Service-specific filtering
                if service in ['netbios-ssn', 'microsoft-ds', 'smb']:
                    # SMB: Must mention Microsoft explicitly
                    if 'microsoft' not in description:
                        continue
                
                elif service in ['ftp', 'ftpd']:
                    # FTP: Must mention Microsoft for Microsoft FTP products
                    if 'microsoft' not in description:
                        continue
                
                elif service in ['http', 'https', 'www']:
                    # HTTP: Must mention IIS or Microsoft for Microsoft IIS
                    if product and 'iis' in product.lower():
                        # For IIS, require IIS or Internet Information Services in description
                        if 'iis' not in description and 'internet information' not in description and 'microsoft' not in description:
                            continue
                    else:
                        # Generic HTTP, require Microsoft
                        if 'microsoft' not in description:
                            continue
                
                elif service in ['msrpc', 'rpc']:
                    # RPC: Must mention Microsoft
                    if 'microsoft' not in description and 'windows' not in description:
                        continue
                
                else:
                    # Generic Windows service: require Windows or Microsoft
                    if 'microsoft' not in description and 'windows' not in description:
                        continue
                
                relevant.append(cve)
        else:
            # No OS context, return all
            relevant = cves
        
        return relevant if relevant else cves  # Fallback to all if filtering removes everything
    
    def _check_hardcoded_vulnerabilities(self, service: str, product: str, version: str, port: int) -> Optional[Dict]:
        """Fallback to hardcoded vulnerability database."""
        service_key = self._get_service_key(service, port)
        
        if service_key and service_key in self.VULNERABILITY_DATABASE:
            vuln_data = self.VULNERABILITY_DATABASE[service_key]['default']
            return {
                'port': port,
                'service': service,
                'product': product if product else 'N/A',
                'version': version if version else 'N/A',
                'cve': vuln_data['cve'],
                'description': vuln_data['description'],
                'severity': vuln_data['severity'],
                'cvss': vuln_data['cvss'],
                'recommendation': vuln_data['recommendation'],
                'source': 'hardcoded'
            }
        
        return None
    
    def _get_service_key(self, service: str, port: int) -> Optional[str]:
        """Get service key for hardcoded database lookup."""
        # Direct service name match
        if service in self.VULNERABILITY_DATABASE:
            return service
        
        # Check for partial matches
        for db_service in self.VULNERABILITY_DATABASE.keys():
            if db_service in service or service in db_service:
                return db_service
        
        # Port-based fallback for common services
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
        return port_service_map.get(port)
    
    def _lookup_nvd_by_cpe(self, cpe: str) -> List[Dict]:
        """
        Lookup CVEs using CPE (Common Platform Enumeration).
        This is the most accurate method as CPE is standardized.
        """
        try:
            print(f"Querying NVD by CPE: {cpe}")
            cves = self.nvd_client.search_cves_by_cpe(cpe, is_vulnerable=True)
            
            # Sort by CVSS score (highest first) and recency
            cves.sort(key=lambda x: (
                x.get('cvss_score') or 0,
                x.get('published', '')
            ), reverse=True)
            
            print(f"Found {len(cves)} CVEs for CPE {cpe}")
            return cves[:5]  # Return top 5 most severe/recent CVEs
            
        except Exception as e:
            print(f"NVD CPE lookup error for {cpe}: {e}")
            return []
    
    def _lookup_nvd_by_keyword(self, product: str, version: str) -> List[Dict]:
        """
        Lookup CVEs using keyword search with KEV prioritization.
        NVD client handles smart querying (KEV + HIGH + CRITICAL).
        """
        try:
            print(f"Querying NVD by keyword: {product} {version}")
            cves = self.nvd_client.search_cves_by_keyword(product, version if version != 'N/A' else None)
            
            print(f"Found {len(cves)} total CVEs (KEV + HIGH + CRITICAL)")
            return cves  # Return all results from smart query
            
        except Exception as e:
            print(f"NVD keyword lookup error for {product} {version}: {e}")
            return []
    
    def _format_nvd_vulnerability(self, cve_data: Dict, service: str, product: str, version: str, port: int, service_data: Dict = None) -> Dict:
        """Format NVD CVE data into our vulnerability structure."""
        vuln = {
            'port': port,
            'service': service,
            'product': product,
            'version': version,
            'cve': cve_data.get('cve_id', 'N/A'),
            'description': cve_data.get('description', 'No description available'),
            'severity': cve_data.get('severity', 'UNKNOWN'),
            'cvss': cve_data.get('cvss_score', 0.0),
            'recommendation': f"Update {product} to the latest patched version. See CVE details for specific remediation.",
            'source': 'nvd',  # Mark as NVD-sourced
            'in_kev': cve_data.get('in_kev', False),  # CISA Known Exploited Vulnerability
            'published': cve_data.get('published', 'N/A'),
            'references': cve_data.get('references', [])
        }
        
        # Add Nmap evidence for validation
        if service_data:
            vuln['nmap_evidence'] = {
                'port': port,
                'service_name': service_data.get('service_name', 'N/A'),
                'product': service_data.get('product', 'N/A'),
                'version': service_data.get('version', 'N/A'),
                'extrainfo': service_data.get('extrainfo', ''),
                'ostype': service_data.get('ostype', ''),
                'method': service_data.get('method', 'table')
            }
        
        return vuln
    
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
                model="claude-haiku-4-5-20251001",
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
        """Construct enhanced prompt for AI analysis."""
        services = host_data.get('services', [])
        vulnerabilities = host_data.get('vulnerabilities', [])
        
        service_list = '\n'.join([
            f"- Port {s['port']}/{s['protocol']}: {s['service_name']} {s.get('product', '')} {s.get('version', '')}"
            for s in services
        ])
        
        vuln_list = '\n'.join([
            f"- {v.get('severity', 'UNKNOWN')}: {v.get('description', 'Unknown')} (Port {v.get('port', 'N/A')})"
            for v in vulnerabilities[:10]  # Top 10 vulnerabilities
        ])
        
        prompt = f"""Analyze this network host for security vulnerabilities and attack chains:

Host Information:
- IP: {host_data.get('ip', 'unknown')}
- OS: {host_data.get('os', {}).get('name', 'unknown')}
- Risk Score: {host_data.get('risk_score', 0)}

Open Services:
{service_list}

Detected Vulnerabilities:
{vuln_list}

Provide a structured analysis:

1. **Critical Attack Scenarios**: Describe 2-3 realistic attack scenarios that exploit these vulnerabilities
2. **Vulnerability Chains**: Identify how multiple vulnerabilities could be chained together for greater impact
3. **Environment-Specific Risks**: Assess risks based on the service combination and OS
4. **Priority Remediation**: List top 3 actions in order of urgency with specific steps

Keep response focused and actionable. Use technical accuracy but clear language."""
        
        return prompt
