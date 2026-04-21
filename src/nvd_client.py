#!/usr/bin/env python3
"""
NVD API Client for CVE lookups.
Uses NVD API 2.0 to fetch real CVE data based on CPE (Common Platform Enumeration).
"""

import requests
import time
import json
from typing import List, Dict, Optional
from datetime import datetime, timedelta


class NVDClient:
    """Client for interacting with the NVD API 2.0."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT_DELAY = 6  # seconds between requests (10 requests per minute for public API)
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD client.
        
        Args:
            api_key: Optional API key for higher rate limits (50 req/30sec vs 5 req/30sec)
        """
        self.api_key = api_key
        self.last_request_time = 0
        self.cache = {}  # Simple in-memory cache
        
    def _rate_limit(self):
        """Enforce rate limiting between API requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.RATE_LIMIT_DELAY:
            time.sleep(self.RATE_LIMIT_DELAY - elapsed)
        self.last_request_time = time.time()
    
    def search_cves_by_cpe(self, cpe_name: str, is_vulnerable: bool = True) -> List[Dict]:
        """
        Search for CVEs affecting a specific CPE.
        
        Args:
            cpe_name: CPE 2.3 formatted string (e.g., "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*")
            is_vulnerable: Only return CVEs where the CPE is marked as vulnerable
            
        Returns:
            List of CVE dictionaries with relevant information
        """
        # Check cache first
        cache_key = f"{cpe_name}_{is_vulnerable}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        self._rate_limit()
        
        params = {
            'cpeName': cpe_name
        }
        
        if is_vulnerable:
            params['isVulnerable'] = ''
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            response = requests.get(self.BASE_URL, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = self._parse_cve_response(data)
            
            # Cache the results
            self.cache[cache_key] = cves
            
            return cves
            
        except requests.exceptions.RequestException as e:
            print(f"NVD API error: {e}")
            return []
    
    def search_cves_by_cpe(self, cpe_string: str) -> List[Dict]:
        """
        Search for CVEs by CPE (Common Platform Enumeration).
        This is more precise than keyword search.
        
        Args:
            cpe_string: CPE identifier (e.g., "cpe:/a:microsoft:internet_information_services:7.5")
            
        Returns:
            List of CVE dictionaries
        """
        # Convert CPE 2.2 format to CPE 2.3 format if needed
        # cpe:/a:vendor:product:version -> cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        if cpe_string.startswith('cpe:/'):
            parts = cpe_string[5:].split(':')
            # Build CPE 2.3 format
            cpe_23 = f"cpe:2.3:{':'.join(parts)}"
            # Pad with wildcards if needed
            while cpe_23.count(':') < 12:
                cpe_23 += ':*'
        else:
            cpe_23 = cpe_string
        
        cache_key = f"cpe_{cpe_23}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        print(f"Querying NVD by CPE: {cpe_23}")
        
        self._rate_limit()
        
        params = {
            'cpeName': cpe_23,
            'resultsPerPage': 100
        }
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            response = requests.get(self.BASE_URL, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = self._parse_cve_response(data)
            
            print(f"Found {len(cves)} CVEs for CPE: {cpe_23}")
            
            # Cache the results
            self.cache[cache_key] = cves
            
            return cves
            
        except requests.exceptions.RequestException as e:
            print(f"NVD API error for CPE query: {e}")
            return []
    
    def search_cves_by_keyword(self, product: str, version: str = None, prioritize_kev: bool = True) -> List[Dict]:
        """
        Search for CVEs by product name and optional version.
        
        Args:
            product: Product name (e.g., "vsftpd", "openssh")
            version: Optional version number
            prioritize_kev: If True, first search for KEV vulnerabilities, then all
            
        Returns:
            List of CVE dictionaries
        """
        # Build search keyword
        keyword = product
        if version:
            keyword = f"{product} {version}"
        
        cache_key = f"keyword_{keyword}_kev_{prioritize_kev}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        all_cves = []
        
        # Strategy 1: Search for CISA KEV (actively exploited) first
        if prioritize_kev:
            kev_cves = self._search_with_params(keyword, has_kev=True)
            all_cves.extend(kev_cves)
            print(f"Found {len(kev_cves)} KEV vulnerabilities for '{keyword}'")
        
        # Strategy 2: Search for HIGH/CRITICAL severity
        high_crit_cves = self._search_with_params(keyword, severity='HIGH')
        all_cves.extend(high_crit_cves)
        
        critical_cves = self._search_with_params(keyword, severity='CRITICAL')
        all_cves.extend(critical_cves)
        
        # Cache the results
        self.cache[cache_key] = all_cves
        
        return all_cves
    
    def _search_with_params(self, keyword: str, has_kev: bool = False, severity: str = None) -> List[Dict]:
        """Internal method to search with specific filter parameters."""
        self._rate_limit()
        
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': 100  # Increased from default 20
        }
        
        if has_kev:
            params['hasKev'] = ''  # Flag parameter, no value needed
        
        if severity:
            params['cvssV3Severity'] = severity
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            response = requests.get(self.BASE_URL, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = self._parse_cve_response(data)
            
            return cves
            
        except requests.exceptions.RequestException as e:
            print(f"NVD API error: {e}")
            return []
    
    def _parse_cve_response(self, data: Dict) -> List[Dict]:
        """
        Parse NVD API response and extract relevant CVE information.
        
        Args:
            data: Raw JSON response from NVD API
            
        Returns:
            List of simplified CVE dictionaries
        """
        cves = []
        
        vulnerabilities = data.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            cve_data = vuln.get('cve', {})
            
            cve_id = cve_data.get('id', 'N/A')
            
            # Get description
            descriptions = cve_data.get('descriptions', [])
            description = next(
                (d['value'] for d in descriptions if d.get('lang') == 'en'),
                'No description available'
            )
            
            # Get CVSS scores
            metrics = cve_data.get('metrics', {})
            cvss_score = None
            severity = 'UNKNOWN'
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]
                    cvss_data = metric.get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    severity = cvss_data.get('baseSeverity', metric.get('baseSeverity', 'UNKNOWN'))
                    break
            
            # Recalculate severity from CVSS score to ensure consistency
            # (NVD sometimes has mismatched severity labels, especially for older CVEs)
            if cvss_score is not None:
                if cvss_score >= 9.0:
                    severity = 'CRITICAL'
                elif cvss_score >= 7.0:
                    severity = 'HIGH'
                elif cvss_score >= 4.0:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
            
            # Get published and modified dates
            published = cve_data.get('published', 'N/A')
            last_modified = cve_data.get('lastModified', 'N/A')
            
            # Check if it's in CISA KEV catalog
            in_kev = any(
                ref.get('tags', []) and 'known-exploited-vulnerability' in ref.get('tags', [])
                for ref in cve_data.get('references', [])
            )
            
            cves.append({
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
                'published': published,
                'last_modified': last_modified,
                'in_kev': in_kev,
                'references': cve_data.get('references', [])
            })
        
        return cves
    
    def build_cpe_string(self, vendor: str, product: str, version: str = '*') -> str:
        """
        Build a CPE 2.3 formatted string.
        
        Args:
            vendor: Vendor name (e.g., "microsoft", "apache")
            product: Product name (e.g., "windows_10", "httpd")
            version: Version number (default: "*" for any version)
            
        Returns:
            CPE 2.3 formatted string
        """
        # Normalize inputs (lowercase, replace spaces with underscores)
        vendor = vendor.lower().replace(' ', '_')
        product = product.lower().replace(' ', '_')
        
        # CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        # For applications: part = 'a', for OS: part = 'o'
        # We'll default to 'a' (application)
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
