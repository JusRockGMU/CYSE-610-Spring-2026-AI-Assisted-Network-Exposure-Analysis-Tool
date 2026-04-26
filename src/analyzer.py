import os
import json
from typing import Dict, List, Optional
from anthropic import Anthropic
from .nvd_client import NVDClient
from .ai_validator import AIValidator


class VulnerabilityAnalyzer:
    """Analyze processed scan data for vulnerabilities using AI-enhanced detection."""
    
    # Safety limits
    MAX_PORTS_PER_HOST = 50  # Maximum ports to analyze per host (prevents infinite loops)
    
    # All vulnerability detection now uses NVD API automation with AI validation
    # No hardcoded rules - rely on AI-enhanced CPE matching and NVD queries
    VULNERABILITY_DATABASE = {}
    
    def __init__(self, use_ai: bool = False, use_nvd: bool = True, deep_analysis: bool = True):
        """Initialize the analyzer with optional AI and NVD support.
        
        Args:
            use_ai: Enable AI-enhanced analysis
            use_nvd: Enable NVD API integration
            deep_analysis: Enable iterative refinement (slower but more accurate)
        """
        self.use_ai = use_ai
        self.use_nvd = use_nvd
        self.deep_analysis = deep_analysis
        self.anthropic_client = None
        self.nvd_client = None
        self.ai_validator = None
        
        if use_ai:
            api_key = os.getenv('ANTHROPIC_API_KEY')
            if api_key:
                self.anthropic_client = Anthropic(api_key=api_key)
                self.ai_validator = AIValidator()
                print("AI-enhanced vulnerability detection enabled")
            else:
                print("Warning: ANTHROPIC_API_KEY not found. AI features disabled.")
        
        if use_nvd:
            # Initialize NVD client (can optionally use NVD_API_KEY env var for higher rate limits)
            nvd_api_key = os.getenv('NVD_API_KEY')
            self.nvd_client = NVDClient(api_key=nvd_api_key)
            print("NVD API integration enabled for real-time CVE lookups")
    
    def analyze(self, processed_data: Dict, progress_callback=None) -> Dict:
        """
        Analyze processed data for vulnerabilities.
        
        Args:
            processed_data: Processed scan data
            progress_callback: Optional callback for progress updates (step, percent, status)
            
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
        
        total_hosts = len(processed_data.get('hosts', []))
        for host_idx, host in enumerate(processed_data.get('hosts', [])):
            if progress_callback:
                progress_callback(
                    f'Analyzing host {host_idx + 1}/{total_hosts}',
                    50 + int((host_idx / total_hosts) * 30),
                    'Analyzing'
                )
            host_analysis = self._analyze_host(host, progress_callback)
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
    
    def _analyze_host(self, host: Dict, progress_callback=None) -> Dict:
        """Analyze individual host for vulnerabilities."""
        host_analysis = {
            'ip': host.get('ip', 'unknown'),
            'hostname': host.get('hostname', ''),
            'os': host.get('os', {}),
            'vulnerabilities': [],
            'filtered_vulnerabilities': [],  # CVEs filtered out by AI
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
        
        total_services = len(services)
        # Apply safety cap to prevent excessive processing
        services_to_analyze = services[:self.MAX_PORTS_PER_HOST]
        if len(services) > self.MAX_PORTS_PER_HOST:
            print(f"⚠️  WARNING: Host has {len(services)} ports. Limiting analysis to first {self.MAX_PORTS_PER_HOST} ports for safety.")
        
        for service_idx, service in enumerate(services_to_analyze):
            port = service.get('port', 'unknown')
            service_name = service.get('service_name', 'unknown')
            
            if progress_callback:
                progress_callback(
                    f'Checking service on port {port} ({service_idx + 1}/{total_services})',
                    50 + int((service_idx / total_services) * 30),
                    'NVD Query'
                )
            
            final_vulns, filtered_vulns = self._analyze_service(service, host.get('ip', ''), os_context, progress_callback)
            host_analysis['vulnerabilities'].extend(final_vulns)
            host_analysis['filtered_vulnerabilities'].extend(filtered_vulns)
        
        # Consolidate duplicate CVEs across multiple ports
        host_analysis['vulnerabilities'] = self._consolidate_vulnerabilities(host_analysis['vulnerabilities'])
        host_analysis['filtered_vulnerabilities'] = self._consolidate_vulnerabilities(host_analysis['filtered_vulnerabilities'])
        
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
    
    def _analyze_service(self, service: Dict, ip: str, os_context: Dict = None, progress_callback=None) -> tuple:
        """Analyze individual service for vulnerabilities.
        
        Returns:
            tuple: (final_vulnerabilities, filtered_vulnerabilities)
        """
        vulnerabilities = []
        filtered_vulnerabilities = []
        
        service_name = service.get('service_name', '').lower()
        port = service.get('port', 0)
        product = service.get('product', '')
        version = service.get('version', '')
        
        print(f"DEBUG: Analyzing service - port={port}, service_name={service_name}, product={product}")
        
        # Pass full service data and OS context for better detection
        result = self._check_known_vulnerabilities(service_name, product, version, port, service, os_context, progress_callback)
        if result:
            # Result is now a tuple: (final_vulns, filtered_vulns)
            if isinstance(result, tuple):
                final_vulns, filtered_vulns = result
                if isinstance(final_vulns, list):
                    vulnerabilities.extend(final_vulns)
                elif final_vulns:
                    vulnerabilities.append(final_vulns)
                if isinstance(filtered_vulns, list):
                    filtered_vulnerabilities.extend(filtered_vulns)
                elif filtered_vulns:
                    filtered_vulnerabilities.append(filtered_vulns)
                print(f"DEBUG: Found {len(vulnerabilities)} final, {len(filtered_vulnerabilities)} filtered for port {port}")
            # Backward compatibility: handle old format
            elif isinstance(result, list):
                vulnerabilities.extend(result)
                print(f"DEBUG: Found {len(result)} vulnerabilities for port {port}")
            else:
                vulnerabilities.append(result)
                print(f"DEBUG: Found vulnerability for port {port}: {result.get('cve', 'UNKNOWN')}")
        else:
            print(f"DEBUG: No vulnerability found for port {port}, service {service_name}")
        
        config_vuln = self._check_misconfigurations(service, port)
        if config_vuln:
            vulnerabilities.append(config_vuln)
        
        return vulnerabilities, filtered_vulnerabilities
    
    def _check_known_vulnerabilities(self, service: str, product: str, version: str, port: int, service_data: Dict = None, os_context: Dict = None, progress_callback=None) -> Optional[Dict]:
        """
        Multi-pass AI-enhanced vulnerability detection with consensus:
        1. Run multiple independent AI+NVD query passes (to account for AI variability)
        2. Track which CVEs appear consistently across passes
        3. Use consensus to assign confidence levels (high=all passes, medium=most, low=some)
        """
        
        if not self.use_nvd or not self.nvd_client:
            return self._check_hardcoded_vulnerabilities(service, product, version, port)
        
        # Multi-pass configuration
        num_passes = 3 if self.deep_analysis and self.ai_validator else 1
        print(f"\n🔄 PORT {port} - MULTI-PASS ANALYSIS ({num_passes} passes)")
        
        # Track CVE appearances across passes
        final_cve_appearances = {}  # {cve_id: {'count': N, 'cve_data': Dict, 'passes': [1,2,3]}}
        filtered_cve_appearances = {}  # Track filtered CVEs too
        
        for pass_num in range(1, num_passes + 1):
            print(f"\n  📍 Pass {pass_num}/{num_passes}")
            pass_results = self._single_pass_vulnerability_check(service, product, version, port, service_data, os_context, progress_callback, pass_num)
            
            # Track final CVEs from this pass
            for cve in pass_results.get('final', []):
                cve_id = cve.get('cve_id')
                if cve_id:
                    if cve_id not in final_cve_appearances:
                        final_cve_appearances[cve_id] = {'count': 0, 'cve_data': cve, 'passes': []}
                    final_cve_appearances[cve_id]['count'] += 1
                    final_cve_appearances[cve_id]['passes'].append(pass_num)
            
            # Track filtered CVEs from this pass
            for cve in pass_results.get('filtered', []):
                cve_id = cve.get('cve_id')
                if cve_id:
                    if cve_id not in filtered_cve_appearances:
                        filtered_cve_appearances[cve_id] = {'count': 0, 'cve_data': cve, 'passes': []}
                    filtered_cve_appearances[cve_id]['count'] += 1
                    filtered_cve_appearances[cve_id]['passes'].append(pass_num)
            
            # Send cumulative CVE list to frontend after each pass
            if progress_callback and final_cve_appearances:
                cumulative_cve_ids = list(final_cve_appearances.keys())
                progress_callback(
                    f'Pass {pass_num}/{num_passes}: Found {len(cumulative_cve_ids)} unique CVEs so far',
                    60 + (pass_num * 5),
                    f'Multi-Pass Analysis',
                    {'port': port, 'cves': cumulative_cve_ids, 'stage': 'found', 'pass': pass_num}
                )
        
        # Calculate consensus-based confidence
        print(f"\n🎯 PORT {port} - CONSENSUS ANALYSIS:")
        consensus_cves = []
        all_filtered_cves = []
        
        # Process final CVEs (those that passed AI filtering in at least one pass)
        for cve_id, data in final_cve_appearances.items():
            count = data['count']
            cve = data['cve_data']
            
            # Assign confidence based on how many passes found this CVE
            if count == num_passes:
                confidence = 'high'
            elif count >= num_passes * 0.66:  # 2 out of 3
                confidence = 'medium'
            else:
                confidence = 'low'
            
            cve['ai_confidence'] = confidence
            cve['consensus_score'] = count
            
            # Separate low confidence CVEs (might be false positives)
            if confidence == 'low':
                # Build comprehensive filter reason
                reasons = []
                reasons.append(f'Low consensus: appeared as valid in only {count}/{num_passes} passes')
                
                # Add AI reasoning if available
                if cve.get('ai_reasoning'):
                    reasons.append(f"AI analysis: {cve.get('ai_reasoning')}")
                
                # Add original filter reason if it exists
                if cve.get('filter_reason') and 'consensus' not in cve.get('filter_reason', '').lower():
                    reasons.append(cve.get('filter_reason'))
                
                cve['filter_reason'] = '. '.join(reasons)
                cve['filtered_by'] = 'Multi-Pass Consensus Analysis'
                cve['consensus_score'] = count
                all_filtered_cves.append(cve)
            else:
                consensus_cves.append(cve)
            
            print(f"  {cve_id}: {count}/{num_passes} passes → {confidence.upper()} confidence")
        
        # Add consistently filtered CVEs (filtered in all passes)
        for cve_id, data in filtered_cve_appearances.items():
            # Skip if this CVE also appeared in final (already processed above)
            if cve_id in final_cve_appearances:
                continue
            
            count = data['count']
            cve = data['cve_data']
            
            # Build comprehensive filter reason for consistently filtered CVEs
            reasons = []
            reasons.append(f'Consistently filtered by AI in {count}/{num_passes} passes')
            
            # Add AI reasoning if available
            if cve.get('ai_reasoning'):
                reasons.append(f"Reason: {cve.get('ai_reasoning')}")
            elif cve.get('filter_reason'):
                reasons.append(cve.get('filter_reason'))
            
            # Add confidence assessment
            if cve.get('cvss_score'):
                cvss = cve.get('cvss_score')
                if cvss >= 9.0:
                    reasons.append(f"Note: High CVSS score ({cvss}) but filtered due to low applicability")
            
            cve['filter_reason'] = '. '.join(reasons)
            cve['filtered_by'] = cve.get('filtered_by', 'AI Analysis')
            cve['ai_confidence'] = 'filtered'  # Mark as filtered
            cve['consensus_score'] = 0  # Didn't pass any consensus
            all_filtered_cves.append(cve)
            print(f"  {cve_id}: Filtered in {count}/{num_passes} passes")
        
        # Format vulnerabilities
        final_vulns = [self._format_nvd_vulnerability(cve, service, product, version, port, service_data) 
                      for cve in consensus_cves]
        filtered_vulns = [self._format_nvd_vulnerability(cve, service, product, version, port, service_data) 
                         for cve in all_filtered_cves]
        
        print(f"\n  ✅ Final: {len(final_vulns)} high/medium confidence CVEs")
        print(f"  🚫 Filtered: {len(filtered_vulns)} CVEs (low consensus + consistently filtered)")
        
        return (final_vulns, filtered_vulns)
    
    def _single_pass_vulnerability_check(self, service: str, product: str, version: str, port: int, service_data: Dict = None, os_context: Dict = None, progress_callback=None, pass_num: int = 1) -> List[Dict]:
        """Single pass of vulnerability detection (called multiple times for consensus)."""
        nvd_cves = []
        ai_enhanced_keywords = []
        
        # STAGE 1: AI-Enhanced CPE Validation and Keyword Generation (only in deep analysis mode)
        if self.deep_analysis and self.ai_validator and service_data:
            if progress_callback:
                progress_callback(f'AI enhancing CPE for port {port}', 55, 'AI Processing')
            print(f"DEBUG: Using AI to enhance CPE and keywords for port {port}")
            ai_enhancement = self.ai_validator.enhance_cpe_and_keywords(service_data, os_context)
            
            # Use AI-validated CPE if available
            validated_cpe = ai_enhancement.get('validated_cpe', '')
            if validated_cpe:
                print(f"DEBUG: AI validated/suggested CPE: {validated_cpe}")
                # Try AI-suggested CPE first
                cpe_cves = self.nvd_client.search_cves_by_cpe(validated_cpe)
                if cpe_cves:
                    nvd_cves.extend(cpe_cves)
                    print(f"DEBUG: AI-validated CPE returned {len(cpe_cves)} CVEs")
            
            # Get AI-optimized search keywords
            ai_enhanced_keywords = ai_enhancement.get('search_keywords', [])
            print(f"DEBUG: AI suggested keywords: {ai_enhanced_keywords}")
        
        # STRATEGY 2: Try original CPE-based matching if AI didn't find results
        if not nvd_cves:
            if progress_callback:
                progress_callback(f'Querying NVD for port {port}', 60, 'NVD Query')
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
                            print(f"DEBUG: CPE query returned {len(cpe_cves)} CVEs")
                            # Continue checking other CPEs to get comprehensive results
        
        # STRATEGY 3: Supplement with keyword search (AI-enhanced if available)
        # Always do keyword search to catch CVEs that CPE matching might miss
        print(f"DEBUG: Supplementing with keyword search (found {len(nvd_cves)} from CPE)")
        
        # Use AI-enhanced keywords first, then fallback to traditional keywords
        search_keywords = ai_enhanced_keywords if ai_enhanced_keywords else self._build_search_keywords(service, product, os_context)
        
        for keyword in search_keywords:
            cves = self._lookup_nvd_by_keyword(keyword, version)
            if cves:
                print(f"DEBUG: Keyword '{keyword}' returned {len(cves)} additional CVEs")
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
            
            # Debug: Log all found CVEs
            print(f"\n📋 PORT {port} - NVD QUERY RESULTS:")
            print(f"  Total CVEs found: {len(unique_cves)}")
            for cve in unique_cves:
                print(f"    - {cve.get('cve_id')} (CVSS: {cve.get('cvss_score', 'N/A')})")
            
            # Send found CVEs to frontend
            if progress_callback:
                cve_ids = [cve.get('cve_id') for cve in unique_cves if cve.get('cve_id')]
                progress_callback(
                    f'Found {len(unique_cves)} CVEs for port {port}', 
                    65, 
                    'NVD Query',
                    {'port': port, 'cves': cve_ids, 'stage': 'found'}
                )
            
            # Track which CVEs will be filtered out
            removed_cves = []
            
            # STAGE 4: AI-Enhanced False Positive Filtering (only in deep analysis mode)
            if self.deep_analysis and self.ai_validator and unique_cves:
                if progress_callback:
                    progress_callback(f'Pass {pass_num}/3: AI filtering {len(unique_cves)} CVEs for port {port}', 70, 'AI Filtering')
                print(f"\n🤖 PORT {port} - AI FILTERING:")
                print(f"  Input: {len(unique_cves)} CVEs")
                ai_filtered_cves = self.ai_validator.filter_and_rank_cves(unique_cves, service_data or {}, os_context)
                if ai_filtered_cves:
                    print(f"  Output: {len(ai_filtered_cves)} CVEs kept by AI")
                    # Track removed CVEs with reasoning
                    ai_filtered_ids = {cve.get('cve_id'): cve for cve in ai_filtered_cves}
                    for cve in unique_cves:
                        cve_id = cve.get('cve_id')
                        if cve_id not in ai_filtered_ids:
                            # This CVE was filtered out - add reasoning
                            cve['filter_reason'] = cve.get('ai_reasoning', 'Filtered by AI as likely false positive or low relevance')
                            cve['filtered_by'] = 'AI Analysis'
                            removed_cves.append(cve)
                            print(f"  ❌ Filtered out: {cve_id} - {cve['filter_reason'][:60]}...")
                    unique_cves = ai_filtered_cves
                else:
                    print(f"  ⚠️ AI filtering returned no results, using original CVEs")
            
            # Prioritize and filter
            filtered_cves = self._prioritize_vulnerabilities(unique_cves, service, os_context, product)
            
            # Track additional CVEs removed by prioritization
            if filtered_cves and len(filtered_cves) < len(unique_cves):
                filtered_ids = {cve.get('cve_id') for cve in filtered_cves}
                for cve in unique_cves:
                    if cve.get('cve_id') not in filtered_ids:
                        # Add reasoning for prioritization filtering
                        if 'filter_reason' not in cve:
                            cve['filter_reason'] = 'Lower priority compared to other vulnerabilities for this service'
                            cve['filtered_by'] = 'Prioritization'
                        removed_cves.append(cve)
            
            # Send final CVEs to frontend
            if progress_callback and filtered_cves:
                cve_ids = [cve.get('cve_id') for cve in filtered_cves if cve.get('cve_id')]
                progress_callback(
                    f'Final: {len(filtered_cves)} CVEs for port {port}', 
                    75, 
                    'AI Filtering',
                    {'port': port, 'cves': cve_ids, 'stage': 'final'}
                )
            
            if filtered_cves or removed_cves:
                # Return both final and filtered CVEs for consensus tracking
                print(f"    Pass {pass_num} found {len(filtered_cves)} final, {len(removed_cves)} filtered")
                return {'final': filtered_cves, 'filtered': removed_cves}
        
        # No results from this pass
        return {'final': [], 'filtered': []}
    
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
        
        # Copy AI analysis metadata
        metadata_copied = []
        if 'ai_confidence' in cve_data:
            vuln['ai_confidence'] = cve_data['ai_confidence']
            metadata_copied.append(f"confidence={cve_data['ai_confidence']}")
        if 'consensus_score' in cve_data:
            vuln['consensus_score'] = cve_data['consensus_score']
            metadata_copied.append(f"consensus={cve_data['consensus_score']}")
        if 'ai_reasoning' in cve_data:
            vuln['ai_reasoning'] = cve_data['ai_reasoning']
            metadata_copied.append("reasoning")
        if 'filter_reason' in cve_data:
            vuln['filter_reason'] = cve_data['filter_reason']
            metadata_copied.append("filter_reason")
        if 'filtered_by' in cve_data:
            vuln['filtered_by'] = cve_data['filtered_by']
            metadata_copied.append(f"filtered_by={cve_data['filtered_by']}")
        
        if metadata_copied:
            print(f"    📊 {vuln['cve']}: Copied metadata - {', '.join(metadata_copied)}")
        
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
