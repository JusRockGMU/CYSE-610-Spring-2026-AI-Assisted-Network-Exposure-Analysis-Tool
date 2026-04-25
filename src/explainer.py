"""
Vulnerability explanation module using language models.
Provides natural language explanations and Q&A capabilities for scan results.
"""
import os
from typing import Dict, Optional
from anthropic import Anthropic


class VulnerabilityExplainer:
    """Generate natural language explanations for vulnerabilities using Claude."""
    
    def __init__(self):
        """Initialize the explainer with Anthropic client."""
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        self.anthropic_client = Anthropic(api_key=api_key) if api_key else None
    
    def explain_vulnerability(self, vulnerability: Dict, host: Dict) -> Optional[str]:
        """
        Generate a plain-language explanation for a vulnerability.
        
        Args:
            vulnerability: Vulnerability data dictionary
            host: Host information dictionary
            
        Returns:
            Natural language explanation or None if AI unavailable
        """
        if not self.anthropic_client:
            return None
        
        try:
            # Check if this is from NVD or hardcoded
            source = vulnerability.get('source', 'unknown')
            in_kev = vulnerability.get('in_kev', False)
            
            prompt = f"""Analyze this security vulnerability and validate the finding:

**Vulnerability Details:**
- CVE: {vulnerability.get('cve', 'N/A')}
- Service: {vulnerability.get('service', 'N/A')} on port {vulnerability.get('port', 'N/A')}
- Product: {vulnerability.get('product', 'N/A')} {vulnerability.get('version', 'N/A')}
- Severity: {vulnerability.get('severity', 'N/A')} (CVSS: {vulnerability.get('cvss', 'N/A')})
- Description: {vulnerability.get('description', 'N/A')}
- Source: {source} {"(CISA KEV - Known Exploited)" if in_kev else ""}

**Host Context:**
- IP: {host.get('ip', 'N/A')}
- OS: {host.get('os', {}).get('name', 'Unknown')}

**CRITICAL: You MUST provide your response using EXACTLY these section headers in this exact order. Do not skip any section or add extra sections:**

**Validation Assessment**
Validate if this CVE actually applies to the detected product/version. If the version is unknown or this appears to be a false positive, clearly state that and explain why.

**What is this vulnerability?**
Explain in clear terms what this vulnerability is and how it works. Be technical but accessible.

**Discovery & Timeline**
When was this CVE discovered and published? What systems and versions does it affect?{" Note that this is in CISA's Known Exploited Vulnerabilities catalog - actively exploited in the wild!" if in_kev else ""}

**Severity Context**
Explain the CVSS score and severity rating. Why is it rated at this level? What makes it critical/high/medium/low?

**Attack Scenarios**
Describe specific, realistic attack scenarios. What could an attacker accomplish by exploiting this vulnerability?

**Recommended Fix**
Provide actionable remediation steps with specific technical guidance. Include patches, workarounds, and mitigation strategies.

IMPORTANT: Use exactly these headers (with **header**) and provide 2-3 sentences for each section. Do not combine sections or use different headers."""
            
            response = self.anthropic_client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=1536,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            return response.content[0].text
        
        except Exception as e:
            print(f"Explanation error: {e}")
            return None
    
    def generate_executive_summary(self, analysis_data: Dict) -> Optional[str]:
        """
        Generate an executive summary of the scan results.
        
        Args:
            analysis_data: Complete analysis data
            
        Returns:
            Executive summary or None if AI unavailable
        """
        if not self.anthropic_client:
            return None
        
        try:
            summary = analysis_data.get('summary', {})
            hosts = analysis_data.get('hosts', [])
            
            # Build context
            host_summary = []
            for host in hosts[:5]:  # Top 5 hosts
                host_summary.append(
                    f"- {host.get('ip', 'Unknown')}: {len(host.get('vulnerabilities', []))} vulnerabilities, "
                    f"risk score {host.get('risk_score', 0)}"
                )
            
            prompt = f"""Generate an executive summary for this network security scan:

Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}
- Critical: {summary.get('critical_count', 0)}
- High: {summary.get('high_count', 0)}
- Medium: {summary.get('medium_count', 0)}
- Low: {summary.get('low_count', 0)}

Hosts Scanned: {len(hosts)}
Top Hosts:
{chr(10).join(host_summary)}

Provide:
1. Overall security posture assessment
2. Top 3 priority actions
3. Business impact summary
4. Recommended timeline for remediation

Write for a non-technical executive audience. Keep it under 200 words."""
            
            response = self.anthropic_client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=512,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            return response.content[0].text
        
        except Exception as e:
            print(f"Executive summary error: {e}")
            return None
    
    def answer_question(self, analysis_data: Dict, question: str) -> str:
        """
        Answer a question about the scan results using AI.
        
        Args:
            analysis_data: Complete analysis data
            question: User's question
            
        Returns:
            AI-generated answer
        """
        if not self.anthropic_client:
            return "AI features are not available. Please set ANTHROPIC_API_KEY environment variable."
        
        try:
            summary = analysis_data.get('summary', {})
            hosts = analysis_data.get('hosts', [])
            
            # Build context about the scan
            context_parts = [
                f"Total vulnerabilities found: {summary.get('total_vulnerabilities', 0)}",
                f"Critical: {summary.get('critical_count', 0)}, High: {summary.get('high_count', 0)}, "
                f"Medium: {summary.get('medium_count', 0)}, Low: {summary.get('low_count', 0)}",
                f"Hosts scanned: {len(hosts)}"
            ]
            
            # Add top vulnerabilities
            all_vulns = []
            for host in hosts:
                for vuln in host.get('vulnerabilities', []):
                    all_vulns.append({
                        'host': host.get('ip'),
                        'severity': vuln.get('severity'),
                        'cve': vuln.get('cve'),
                        'description': vuln.get('description'),
                        'port': vuln.get('port'),
                        'service': vuln.get('service')
                    })
            
            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            all_vulns.sort(key=lambda x: severity_order.get(x['severity'], 4))
            
            # Include top 10 vulnerabilities in context
            vuln_context = []
            for vuln in all_vulns[:10]:
                vuln_context.append(
                    f"- {vuln['host']}: {vuln['severity']} - {vuln['description']} "
                    f"({vuln['service']} on port {vuln['port']})"
                )
            
            prompt = f"""You are a cybersecurity expert analyzing network scan results. Answer the user's question based on this data:

Scan Summary:
{chr(10).join(context_parts)}

Top Vulnerabilities:
{chr(10).join(vuln_context)}

User Question: {question}

Provide a clear, specific answer based on the scan data. If the question asks for recommendations, be actionable and specific. If the data doesn't contain enough information to fully answer, say so."""
            
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
            return f"Error generating answer: {str(e)}"
    
    def get_remediation_guidance(self, vulnerability: Dict, host: Dict) -> str:
        """
        Get detailed step-by-step remediation guidance for a specific vulnerability.
        
        Args:
            vulnerability: Vulnerability data dictionary
            host: Host information dictionary
            
        Returns:
            Detailed remediation instructions
        """
        if not self.anthropic_client:
            return "AI features are not available. Please set ANTHROPIC_API_KEY environment variable."
        
        try:
            prompt = f"""You are a cybersecurity expert providing remediation guidance.

Vulnerability Details:
- CVE: {vulnerability.get('cve', 'N/A')}
- Description: {vulnerability.get('description', 'Unknown')}
- Severity: {vulnerability.get('severity', 'Unknown')} (CVSS: {vulnerability.get('cvss', 'N/A')})
- Service: {vulnerability.get('service', 'Unknown')}
- Product: {vulnerability.get('product', 'N/A')}
- Version: {vulnerability.get('version', 'N/A')}
- Port: {vulnerability.get('port', 'Unknown')}

Host Context:
- IP: {host.get('ip', 'Unknown')}
- OS: {host.get('os', {}).get('name', 'Unknown')}

Provide comprehensive remediation guidance:

1. **Immediate Actions** (what to do right now to reduce risk)
2. **Step-by-Step Fix** (detailed technical instructions)
3. **Configuration Examples** (specific commands or config changes if applicable)
4. **Verification Steps** (how to confirm the fix worked)
5. **Additional Hardening** (related security improvements)
6. **Rollback Plan** (if something goes wrong)

Be specific, technical, and actionable. Include actual commands where possible."""
            
            response = self.anthropic_client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=2048,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            return response.content[0].text
        
        except Exception as e:
            return f"Error generating remediation guidance: {str(e)}"
