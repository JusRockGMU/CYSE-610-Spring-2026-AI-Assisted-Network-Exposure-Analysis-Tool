"""
AI-powered validation and enhancement for vulnerability detection.
Uses Claude to improve CPE matching, NVD queries, and CVE filtering.
"""

import json
import os
from typing import Dict, List, Optional
from anthropic import Anthropic


class AIValidator:
    """AI-powered validation for vulnerability detection pipeline."""
    
    def __init__(self):
        """Initialize AI validator with Anthropic client."""
        api_key = os.getenv('ANTHROPIC_API_KEY')
        self.client = Anthropic(api_key=api_key) if api_key else None
        self.model = "claude-haiku-4-5-20251001"
    
    def enhance_cpe_and_keywords(self, service_data: Dict, os_context: Dict = None) -> Dict:
        """
        Use AI to validate CPE and suggest better NVD search keywords.
        
        Returns:
        {
            'validated_cpe': str,
            'search_keywords': List[str],
            'product_variations': List[str],
            'confidence': str
        }
        """
        if not self.client:
            return self._fallback_enhancement(service_data)
        
        try:
            prompt = self._build_cpe_enhancement_prompt(service_data, os_context)
            
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            result = self._parse_json_response(response.content[0].text)
            return result if result else self._fallback_enhancement(service_data)
            
        except Exception as e:
            print(f"AI CPE enhancement error: {e}")
            return self._fallback_enhancement(service_data)
    
    def filter_and_rank_cves(self, cves: List[Dict], service_data: Dict, os_context: Dict = None) -> List[Dict]:
        """
        Use AI to filter false positives and rank CVEs by relevance.
        
        Returns filtered and ranked list of CVEs with confidence scores.
        """
        if not self.client or not cves:
            return cves
        
        try:
            # Limit to top 20 CVEs to avoid token limits
            cves_to_validate = cves[:20]
            
            prompt = self._build_cve_filtering_prompt(cves_to_validate, service_data, os_context)
            
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            result = self._parse_json_response(response.content[0].text)
            
            if result and 'filtered_cves' in result:
                # Map AI results back to original CVE objects
                filtered = []
                for ai_cve in result['filtered_cves']:
                    cve_id = ai_cve.get('cve_id')
                    # Find original CVE object
                    for original_cve in cves:
                        if original_cve.get('cve_id') == cve_id:
                            # Add AI confidence and reasoning
                            original_cve['ai_confidence'] = ai_cve.get('confidence', 'medium')
                            original_cve['ai_reasoning'] = ai_cve.get('reasoning', '')
                            filtered.append(original_cve)
                            break
                
                return filtered if filtered else cves
            
            return cves
            
        except Exception as e:
            print(f"AI CVE filtering error: {e}")
            return cves
    
    def _build_cpe_enhancement_prompt(self, service_data: Dict, os_context: Dict = None) -> str:
        """Build prompt for CPE validation and keyword enhancement."""
        service_name = service_data.get('service_name', 'unknown')
        product = service_data.get('product', '')
        version = service_data.get('version', '')
        port = service_data.get('port', '')
        cpe_list = service_data.get('cpe', [])
        
        os_info = ""
        if os_context:
            os_info = f"\nOS Context: {os_context.get('name', '')} {os_context.get('version', '')}"
        
        prompt = f"""You are a cybersecurity expert analyzing network service data to improve vulnerability detection.

Service Information:
- Service Name: {service_name}
- Product: {product}
- Version: {version}
- Port: {port}
- Detected CPE: {', '.join(cpe_list) if cpe_list else 'None'}{os_info}

Your tasks:
1. Validate the CPE string (if present) for accuracy
2. Suggest the correct CPE if the detected one is wrong or missing
3. Generate optimal NVD search keywords (prioritize specific product names, version info)
4. List product name variations that might be used in CVE databases
5. Assess confidence in the service identification

Respond ONLY with valid JSON in this exact format:
{{
    "validated_cpe": "cpe:/a:vendor:product:version or empty string if invalid",
    "search_keywords": ["keyword1", "keyword2", "keyword3"],
    "product_variations": ["variation1", "variation2"],
    "confidence": "high/medium/low",
    "reasoning": "brief explanation"
}}

Focus on precision - avoid generic terms. For example:
- For Microsoft IIS 7.5: use "Microsoft IIS 7.5", "Internet Information Services 7.5", not just "IIS"
- For OpenSSH 7.4: use "OpenSSH 7.4", "OpenSSH 7.4p1", not just "SSH"
"""
        return prompt
    
    def _build_cve_filtering_prompt(self, cves: List[Dict], service_data: Dict, os_context: Dict = None) -> str:
        """Build prompt for CVE filtering and ranking."""
        service_name = service_data.get('service_name', 'unknown')
        product = service_data.get('product', '')
        version = service_data.get('version', '')
        
        os_info = ""
        if os_context:
            os_info = f"\nOS: {os_context.get('name', '')} {os_context.get('version', '')}"
        
        cve_summary = []
        for cve in cves[:15]:  # Limit to avoid token overflow
            cve_summary.append({
                'cve_id': cve.get('cve_id'),
                'description': cve.get('description', '')[:200],  # Truncate long descriptions
                'cvss_score': cve.get('cvss_score', 0)
            })
        
        prompt = f"""You are a vulnerability analyst filtering CVE results for accuracy.

Detected Service:
- Service: {service_name}
- Product: {product}
- Version: {version}{os_info}

NVD returned these CVEs:
{json.dumps(cve_summary, indent=2)}

Your tasks:
1. Filter out FALSE POSITIVES (CVEs that don't apply to this specific product/version)
2. Identify CVEs for different products with similar names
3. Check version applicability (does the CVE affect this version?)
4. Rank remaining CVEs by relevance and exploitability
5. Provide confidence scores

Common false positives to watch for:
- Different products with similar names (e.g., Microsoft FTP vs TitanFTP)
- Version mismatches (CVE affects 7.0-7.4 but service is 7.5)
- OS-specific CVEs on wrong OS
- Protocol-level CVEs vs implementation CVEs

Respond ONLY with valid JSON in this exact format:
{{
    "filtered_cves": [
        {{
            "cve_id": "CVE-YYYY-NNNNN",
            "confidence": "high/medium/low",
            "reasoning": "why this CVE applies or doesn't apply",
            "is_false_positive": false
        }}
    ],
    "removed_count": 0,
    "summary": "brief explanation of filtering decisions"
}}

Only include CVEs you are confident apply to this specific service. When in doubt, mark confidence as "low".
"""
        return prompt
    
    def _parse_json_response(self, response_text: str) -> Optional[Dict]:
        """Parse JSON from AI response, handling markdown code blocks."""
        try:
            # Remove markdown code blocks if present
            text = response_text.strip()
            if text.startswith('```'):
                # Extract content between ``` markers
                lines = text.split('\n')
                json_lines = []
                in_code_block = False
                for line in lines:
                    if line.startswith('```'):
                        in_code_block = not in_code_block
                        continue
                    if in_code_block:
                        json_lines.append(line)
                text = '\n'.join(json_lines)
            
            return json.loads(text)
        except json.JSONDecodeError as e:
            print(f"Failed to parse AI JSON response: {e}")
            print(f"Response was: {response_text[:200]}")
            return None
    
    def _fallback_enhancement(self, service_data: Dict) -> Dict:
        """Fallback enhancement when AI is not available."""
        product = service_data.get('product', '')
        version = service_data.get('version', '')
        service_name = service_data.get('service_name', '')
        
        keywords = []
        if product and version:
            keywords.append(f"{product} {version}")
        if product:
            keywords.append(product)
        if service_name and service_name != product:
            keywords.append(service_name)
        
        return {
            'validated_cpe': '',
            'search_keywords': keywords[:3],
            'product_variations': [],
            'confidence': 'low'
        }
