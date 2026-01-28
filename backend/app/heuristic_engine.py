"""
Heuristic Engine for Phishing Detection
Uses regex patterns and typosquatting detection to identify suspicious URLs
"""

import re
from urllib.parse import urlparse
from typing import Tuple, Optional
import difflib

class HeuristicEngine:
    """Pattern-based phishing detection using heuristics"""
    
    def __init__(self):
        """Initialize the heuristic engine with known patterns"""
        
        # Common legitimate domains that phishers impersonate
        self.legitimate_domains = {
            'google.com', 'facebook.com', 'amazon.com', 'paypal.com',
            'microsoft.com', 'apple.com', 'netflix.com', 'instagram.com',
            'twitter.com', 'linkedin.com', 'ebay.com', 'walmart.com',
            'chase.com', 'bankofamerica.com', 'wellsfargo.com',
            'github.com', 'dropbox.com', 'yahoo.com', 'outlook.com'
        }
        
        # Suspicious keywords often found in phishing URLs
        self.suspicious_keywords = [
            'verify', 'account', 'update', 'secure', 'banking',
            'signin', 'login', 'confirm', 'suspend', 'unlock',
            'validate', 'restore', 'recover', 'alert', 'urgent',
            'limited', 'unusual', 'activity', 'security-check'
        ]
        
        # Suspicious TLDs commonly used in phishing
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc',
            '.top', '.xyz', '.club', '.work', '.click'
        ]
        
        # Character substitutions commonly used in typosquatting
        self.char_substitutions = {
            '0': 'o', '1': 'i', '3': 'e', '5': 's',
            '8': 'b', '@': 'a', '$': 's'
        }
    
    def check_url(self, url: str) -> Tuple[bool, str, int]:
        """
        Perform heuristic checks on a URL
        
        Args:
            url: The URL to check
            
        Returns:
            Tuple of (is_suspicious, reason, confidence_score)
            confidence_score: 0-100 (higher = more confident it's phishing)
        """
        url = url.lower().strip()
        confidence = 0
        reasons = []
        
        # Check 1: IP address in URL
        if self._has_ip_address(url):
            confidence += 30
            reasons.append("Contains IP address instead of domain name")
        
        # Check 2: Excessive subdomains
        subdomain_count = self._count_subdomains(url)
        if subdomain_count >= 3:
            confidence += 20
            reasons.append(f"Suspicious number of subdomains ({subdomain_count})")
        
        # Check 3: Typosquatting detection
        typo_result = self._check_typosquatting(url)
        if typo_result:
            confidence += 40
            reasons.append(f"Possible typosquatting of {typo_result}")
        
        # Check 4: Suspicious keywords
        keyword_count = self._count_suspicious_keywords(url)
        if keyword_count >= 2:
            confidence += 25
            reasons.append(f"Contains {keyword_count} suspicious keywords")
        elif keyword_count == 1:
            confidence += 10
            reasons.append("Contains suspicious keyword")
        
        # Check 5: Suspicious TLD
        if self._has_suspicious_tld(url):
            confidence += 15
            reasons.append("Uses suspicious top-level domain")
        
        # Check 6: @ symbol in URL (technique to hide actual domain)
        if '@' in url:
            confidence += 35
            reasons.append("Contains @ symbol (potential domain masking)")
        
        # Check 7: Excessive hyphens
        hyphen_count = url.count('-')
        if hyphen_count >= 4:
            confidence += 15
            reasons.append(f"Excessive hyphens ({hyphen_count})")
        
        # Check 8: URL length
        if len(url) > 100:
            confidence += 10
            reasons.append("Unusually long URL")
        
        # Check 9: Homograph attack (Unicode lookalikes)
        if self._check_homograph(url):
            confidence += 30
            reasons.append("Possible homograph attack (lookalike characters)")
        
        # Cap confidence at 100
        confidence = min(confidence, 100)
        
        # Determine if suspicious (threshold: 40)
        is_suspicious = confidence >= 40
        reason = '; '.join(reasons) if reasons else 'No suspicious patterns detected'
        
        return is_suspicious, reason, confidence
    
    def _has_ip_address(self, url: str) -> bool:
        """Check if URL contains an IP address"""
        ip_pattern = r'(?:http[s]?://)?(\d{1,3}\.){3}\d{1,3}'
        return bool(re.search(ip_pattern, url))
    
    def _count_subdomains(self, url: str) -> int:
        """Count number of subdomains in URL"""
        try:
            parsed = urlparse(url if url.startswith('http') else 'http://' + url)
            hostname = parsed.hostname or ''
            parts = hostname.split('.')
            # Subtract 2 for domain and TLD
            return max(0, len(parts) - 2)
        except:
            return 0
    
    def _check_typosquatting(self, url: str) -> Optional[str]:
        """
        Check for typosquatting against known legitimate domains
        
        Returns:
            The legitimate domain being impersonated, or None
        """
        try:
            parsed = urlparse(url if url.startswith('http') else 'http://' + url)
            hostname = parsed.hostname or ''
            
            # Extract domain without subdomains
            parts = hostname.split('.')
            if len(parts) >= 2:
                domain = '.'.join(parts[-2:])
            else:
                domain = hostname
            
            # Check for exact match (legitimate)
            if domain in self.legitimate_domains:
                return None
            
            # Check for character substitution
            normalized = domain
            for fake, real in self.char_substitutions.items():
                normalized = normalized.replace(fake, real)
            
            if normalized in self.legitimate_domains:
                return normalized
            
            # Check for similarity to legitimate domains
            for legit_domain in self.legitimate_domains:
                similarity = difflib.SequenceMatcher(None, domain, legit_domain).ratio()
                if similarity > 0.8:  # 80% similar
                    return legit_domain
            
            return None
        except:
            return None
    
    def _count_suspicious_keywords(self, url: str) -> int:
        """Count suspicious keywords in URL"""
        count = 0
        for keyword in self.suspicious_keywords:
            if keyword in url:
                count += 1
        return count
    
    def _has_suspicious_tld(self, url: str) -> bool:
        """Check if URL uses a suspicious TLD"""
        for tld in self.suspicious_tlds:
            if url.endswith(tld) or tld + '/' in url:
                return True
        return False
    
    def _check_homograph(self, url: str) -> bool:
        """Check for homograph attacks (simplified)"""
        # Check for mix of different scripts or suspicious Unicode characters
        # This is a simplified check - production systems would be more sophisticated
        try:
            # If URL can't be encoded as ASCII, might contain Unicode lookalikes
            url.encode('ascii')
            return False
        except UnicodeEncodeError:
            # Contains non-ASCII characters
            # Check if it's a legitimate internationalized domain or suspicious
            parsed = urlparse(url if url.startswith('http') else 'http://' + url)
            hostname = parsed.hostname or ''
            
            # If hostname contains non-ASCII in suspicious context, flag it
            if any(ord(c) > 127 for c in hostname):
                return True
        
        return False