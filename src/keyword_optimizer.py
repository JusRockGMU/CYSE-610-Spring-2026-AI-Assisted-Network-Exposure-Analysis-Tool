#!/usr/bin/env python3
"""
Keyword Optimizer for NVD Searches
Sanitizes, validates, and optimizes search keywords to improve CVE discovery.
"""

import re
from typing import List, Dict, Set, Tuple


class KeywordOptimizer:
    """Optimizes and validates keywords for NVD API searches."""
    
    # Common noise words that don't help NVD searches
    NOISE_WORDS = {
        'server', 'service', 'daemon', 'application', 'software',
        'the', 'a', 'an', 'for', 'and', 'or', 'with', 'on',
        'vulnerability', 'cve', 'exploit', 'remote', 'code', 'execution'
    }
    
    # Version patterns to preserve
    VERSION_PATTERN = re.compile(r'\d+\.\d+(\.\d+)?([a-z]\d*)?', re.IGNORECASE)
    
    # Maximum keyword length (NVD has limits)
    MAX_KEYWORD_LENGTH = 100
    
    # Minimum keyword length (too short = too broad)
    MIN_KEYWORD_LENGTH = 3
    
    def __init__(self):
        self.seen_keywords = set()  # Track keywords already used
    
    def sanitize_keyword(self, keyword: str) -> str:
        """
        Clean and normalize a keyword for NVD search.
        
        Args:
            keyword: Raw keyword string
            
        Returns:
            Sanitized keyword
        """
        if not keyword:
            return ""
        
        # Remove extra whitespace
        keyword = ' '.join(keyword.split())
        
        # Remove special characters except dots, hyphens, underscores
        keyword = re.sub(r'[^\w\s\.\-]', ' ', keyword)
        
        # Normalize spacing
        keyword = ' '.join(keyword.split())
        
        # Truncate if too long
        if len(keyword) > self.MAX_KEYWORD_LENGTH:
            keyword = keyword[:self.MAX_KEYWORD_LENGTH].rsplit(' ', 1)[0]
        
        return keyword.strip()
    
    def extract_version(self, text: str) -> str:
        """Extract version number from text."""
        match = self.VERSION_PATTERN.search(text)
        return match.group(0) if match else ""
    
    def remove_noise_words(self, keyword: str, preserve_version: bool = True) -> str:
        """
        Remove common noise words that don't help NVD searches.
        
        Args:
            keyword: Input keyword
            preserve_version: Keep version numbers even if they're "noise"
            
        Returns:
            Cleaned keyword
        """
        words = keyword.lower().split()
        version = self.extract_version(keyword) if preserve_version else ""
        
        # Filter out noise words
        filtered_words = [
            word for word in words 
            if word not in self.NOISE_WORDS and len(word) >= self.MIN_KEYWORD_LENGTH
        ]
        
        # Reconstruct keyword
        result = ' '.join(filtered_words)
        
        # Ensure version is included if it was in original
        if version and version not in result:
            result = f"{result} {version}".strip()
        
        return result
    
    def validate_keyword(self, keyword: str, min_words: int = 1) -> Tuple[bool, str]:
        """
        Validate if a keyword is suitable for NVD search.
        
        Args:
            keyword: Keyword to validate
            min_words: Minimum number of words required
            
        Returns:
            (is_valid, reason)
        """
        if not keyword or len(keyword) < self.MIN_KEYWORD_LENGTH:
            return False, "Too short"
        
        if len(keyword) > self.MAX_KEYWORD_LENGTH:
            return False, "Too long"
        
        words = keyword.split()
        if len(words) < min_words:
            return False, f"Need at least {min_words} words"
        
        # Check if it's all noise words
        if all(word.lower() in self.NOISE_WORDS for word in words):
            return False, "All noise words"
        
        # Check for duplicate
        if keyword.lower() in self.seen_keywords:
            return False, "Duplicate"
        
        return True, "Valid"
    
    def deduplicate_keywords(self, keywords: List[str]) -> List[str]:
        """Remove duplicate keywords (case-insensitive)."""
        seen = set()
        unique = []
        
        for keyword in keywords:
            keyword_lower = keyword.lower()
            if keyword_lower not in seen:
                seen.add(keyword_lower)
                unique.append(keyword)
        
        return unique
    
    def optimize_keywords(self, keywords: List[str], max_keywords: int = 5) -> List[str]:
        """
        Optimize a list of keywords for NVD search.
        
        Process:
        1. Sanitize each keyword
        2. Remove noise words
        3. Validate
        4. Deduplicate
        5. Rank by specificity
        6. Return top N
        
        Args:
            keywords: List of raw keywords
            max_keywords: Maximum number to return
            
        Returns:
            Optimized list of keywords
        """
        optimized = []
        
        for keyword in keywords:
            # Sanitize
            clean = self.sanitize_keyword(keyword)
            if not clean:
                continue
            
            # Remove noise
            clean = self.remove_noise_words(clean)
            if not clean:
                continue
            
            # Validate
            is_valid, reason = self.validate_keyword(clean)
            if is_valid:
                optimized.append(clean)
                self.seen_keywords.add(clean.lower())
            else:
                print(f"  ⚠️  Rejected keyword '{keyword}': {reason}")
        
        # Deduplicate
        optimized = self.deduplicate_keywords(optimized)
        
        # Rank by specificity (longer = more specific, usually better)
        # But also prioritize keywords with version numbers
        def keyword_score(kw):
            score = len(kw.split())  # More words = more specific
            if self.extract_version(kw):
                score += 10  # Boost keywords with versions
            return score
        
        optimized.sort(key=keyword_score, reverse=True)
        
        # Return top N
        return optimized[:max_keywords]
    
    def suggest_fallback_keywords(self, product: str, version: str = None, service: str = None) -> List[str]:
        """
        Generate fallback keywords when AI/primary keywords fail.
        
        Strategy:
        1. Product + version (most specific)
        2. Product name only
        3. Product vendor/family
        4. Service name
        
        Args:
            product: Product name
            version: Version string
            service: Service name
            
        Returns:
            List of fallback keywords
        """
        fallbacks = []
        
        if product and version:
            # Try product + version
            fallbacks.append(f"{product} {version}")
            
            # Try just major version
            major_version = version.split('.')[0] if '.' in version else version
            if major_version != version:
                fallbacks.append(f"{product} {major_version}")
        
        if product:
            # Try product name only
            fallbacks.append(product)
            
            # Try extracting vendor/family (e.g., "Microsoft IIS" -> "IIS")
            words = product.split()
            if len(words) > 1:
                fallbacks.append(words[-1])  # Last word often the product name
        
        if service and service != product:
            fallbacks.append(service)
        
        return self.optimize_keywords(fallbacks, max_keywords=3)
    
    def validate_nvd_response(self, keyword: str, total_results: int) -> Dict[str, any]:
        """
        Validate NVD response and suggest improvements.
        
        Args:
            keyword: Keyword that was searched
            total_results: Number of results returned by NVD
            
        Returns:
            {
                'status': 'good' | 'too_many' | 'too_few' | 'zero',
                'suggestion': str,
                'alternative_keywords': List[str]
            }
        """
        result = {
            'status': 'good',
            'suggestion': '',
            'alternative_keywords': []
        }
        
        if total_results == 0:
            result['status'] = 'zero'
            result['suggestion'] = 'Try broader keywords or remove version'
            
            # Suggest removing version or last word
            words = keyword.split()
            if len(words) > 1:
                result['alternative_keywords'] = [
                    ' '.join(words[:-1]),  # Remove last word
                    words[0]  # Just first word
                ]
        
        elif total_results > 1000:
            result['status'] = 'too_many'
            result['suggestion'] = 'Too broad - add version or more specific terms'
            
            # Suggest adding more specific terms
            version = self.extract_version(keyword)
            if not version:
                result['alternative_keywords'] = [f"{keyword} vulnerability"]
        
        elif total_results > 500:
            result['status'] = 'many'
            result['suggestion'] = 'Consider adding version for more precise results'
        
        else:
            result['status'] = 'good'
            result['suggestion'] = f'{total_results} results is a good range'
        
        return result
    
    def reset(self):
        """Reset seen keywords (call between scans)."""
        self.seen_keywords.clear()
