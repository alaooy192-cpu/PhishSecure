"""
Threat Analysis Engine
Analyzes domains/URLs for phishing indicators and threat scoring
"""

import re
import socket
import whois
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import requests
import json
import logging

class ThreatAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Suspicious TLD patterns
        self.high_risk_tlds = ['.tk', '.ml', '.ga', '.cf', '.ru', '.cn', '.cc', '.ws', '.to']
        self.medium_risk_tlds = ['.info', '.biz', '.xyz', '.top', '.click', '.download']
        
        # Suspicious keywords in domains
        self.suspicious_keywords = [
            'login', 'secure', 'verify', 'update', 'confirm', 'account', 'banking',
            'payment', 'paypal', 'amazon', 'microsoft', 'google', 'apple'
        ]
        
        # Brand patterns for typosquatting detection
        self.major_brands = [
            'paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook',
            'instagram', 'twitter', 'linkedin', 'netflix', 'spotify'
        ]

    def analyze_indicator(self, indicator: str, indicator_type: str = 'domain') -> Dict:
        """
        Comprehensive threat analysis of an indicator
        
        Args:
            indicator: Domain, URL, or IP to analyze
            indicator_type: 'domain', 'url', or 'ip'
            
        Returns:
            Dict with threat score, analysis details, and flags
        """
        
        analysis_result = {
            'indicator': indicator,
            'indicator_type': indicator_type,
            'threat_score': 0,
            'confidence_level': 'low',
            'flags': [],
            'technical_analysis': {},
            'risk_factors': [],
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            if indicator_type == 'domain':
                analysis_result.update(self._analyze_domain(indicator))
            elif indicator_type == 'url':
                analysis_result.update(self._analyze_url(indicator))
            elif indicator_type == 'ip':
                analysis_result.update(self._analyze_ip(indicator))
            
            # Calculate final threat score
            analysis_result['threat_score'] = self._calculate_threat_score(analysis_result)
            analysis_result['confidence_level'] = self._get_confidence_level(analysis_result['threat_score'])
            
        except Exception as e:
            self.logger.error(f"Error analyzing {indicator}: {e}")
            analysis_result['error'] = str(e)
        
        return analysis_result

    def _analyze_domain(self, domain: str) -> Dict:
        """Analyze a domain for phishing indicators"""
        result = {
            'technical_analysis': {},
            'flags': [],
            'risk_factors': []
        }
        
        # 1. Domain structure analysis
        structure_analysis = self._analyze_domain_structure(domain)
        result['technical_analysis']['structure'] = structure_analysis
        result['flags'].extend(structure_analysis.get('flags', []))
        
        # 2. TLD analysis
        tld_analysis = self._analyze_tld(domain)
        result['technical_analysis']['tld'] = tld_analysis
        if tld_analysis.get('risk_level') != 'low':
            result['flags'].append(f"Suspicious TLD: {tld_analysis.get('tld')}")
        
        # 3. Typosquatting detection
        typo_analysis = self._detect_typosquatting(domain)
        result['technical_analysis']['typosquatting'] = typo_analysis
        if typo_analysis.get('is_typosquatting'):
            result['flags'].append(f"Potential typosquatting: {typo_analysis.get('target_brand')}")
        
        # 4. Suspicious keywords
        keyword_analysis = self._analyze_suspicious_keywords(domain)
        result['technical_analysis']['keywords'] = keyword_analysis
        result['flags'].extend(keyword_analysis.get('flags', []))
        
        # 5. Domain age analysis (if WHOIS available)
        try:
            age_analysis = self._analyze_domain_age(domain)
            result['technical_analysis']['age'] = age_analysis
            if age_analysis.get('is_new_domain'):
                result['flags'].append("Recently registered domain")
        except Exception as e:
            result['technical_analysis']['age'] = {'error': str(e)}
        
        # 6. DNS analysis
        try:
            dns_analysis = self._analyze_dns(domain)
            result['technical_analysis']['dns'] = dns_analysis
        except Exception as e:
            result['technical_analysis']['dns'] = {'error': str(e)}
        
        return result

    def _analyze_url(self, url: str) -> Dict:
        """Analyze a URL for phishing indicators"""
        result = {
            'technical_analysis': {},
            'flags': [],
            'risk_factors': []
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Analyze the domain part
            domain_analysis = self._analyze_domain(domain)
            result.update(domain_analysis)
            
            # URL-specific analysis
            url_analysis = self._analyze_url_structure(parsed)
            result['technical_analysis']['url_structure'] = url_analysis
            result['flags'].extend(url_analysis.get('flags', []))
            
        except Exception as e:
            result['technical_analysis']['url_parsing'] = {'error': str(e)}
        
        return result

    def _analyze_ip(self, ip: str) -> Dict:
        """Analyze an IP address for threat indicators"""
        result = {
            'technical_analysis': {},
            'flags': [],
            'risk_factors': []
        }
        
        # Basic IP validation and analysis
        try:
            socket.inet_aton(ip)  # Validate IP format
            
            # Analyze IP characteristics
            ip_analysis = self._analyze_ip_characteristics(ip)
            result['technical_analysis']['ip_analysis'] = ip_analysis
            result['flags'].extend(ip_analysis.get('flags', []))
            
        except socket.error:
            result['flags'].append("Invalid IP address format")
        
        return result

    def _analyze_domain_structure(self, domain: str) -> Dict:
        """Analyze domain structure for suspicious patterns"""
        analysis = {
            'length': len(domain),
            'subdomain_count': domain.count('.') - 1,
            'has_hyphens': '-' in domain,
            'has_numbers': bool(re.search(r'\d', domain)),
            'flags': []
        }
        
        # Check for suspicious patterns
        if analysis['length'] > 50:
            analysis['flags'].append("Unusually long domain")
        
        if analysis['subdomain_count'] > 3:
            analysis['flags'].append("Multiple subdomains")
        
        if domain.count('-') > 3:
            analysis['flags'].append("Multiple hyphens")
        
        # Check for homoglyphs (basic detection)
        if self._contains_homoglyphs(domain):
            analysis['flags'].append("Contains suspicious characters")
        
        return analysis

    def _analyze_tld(self, domain: str) -> Dict:
        """Analyze Top Level Domain for risk"""
        tld = '.' + domain.split('.')[-1] if '.' in domain else ''
        
        analysis = {
            'tld': tld,
            'risk_level': 'low'
        }
        
        if tld in self.high_risk_tlds:
            analysis['risk_level'] = 'high'
        elif tld in self.medium_risk_tlds:
            analysis['risk_level'] = 'medium'
        
        return analysis

    def _detect_typosquatting(self, domain: str) -> Dict:
        """Detect potential typosquatting against major brands"""
        analysis = {
            'is_typosquatting': False,
            'target_brand': None,
            'similarity_score': 0
        }
        
        domain_clean = domain.lower().replace('-', '').replace('.', '')
        
        for brand in self.major_brands:
            similarity = self._calculate_similarity(domain_clean, brand)
            
            if similarity > 0.7 and similarity < 0.95:  # Similar but not exact
                analysis['is_typosquatting'] = True
                analysis['target_brand'] = brand
                analysis['similarity_score'] = similarity
                break
        
        return analysis

    def _analyze_suspicious_keywords(self, domain: str) -> Dict:
        """Analyze domain for suspicious keywords"""
        analysis = {
            'found_keywords': [],
            'flags': []
        }
        
        domain_lower = domain.lower()
        
        for keyword in self.suspicious_keywords:
            if keyword in domain_lower:
                analysis['found_keywords'].append(keyword)
                analysis['flags'].append(f"Contains suspicious keyword: {keyword}")
        
        return analysis

    def _analyze_domain_age(self, domain: str) -> Dict:
        """Analyze domain age using WHOIS data"""
        analysis = {
            'creation_date': None,
            'age_days': None,
            'is_new_domain': False
        }
        
        try:
            w = whois.whois(domain)
            
            if w.creation_date:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                analysis['creation_date'] = creation_date.isoformat() if creation_date else None
                
                if creation_date:
                    age = datetime.now() - creation_date
                    analysis['age_days'] = age.days
                    analysis['is_new_domain'] = age.days < 30  # Less than 30 days old
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    def _analyze_dns(self, domain: str) -> Dict:
        """Basic DNS analysis"""
        analysis = {
            'has_a_record': False,
            'has_mx_record': False,
            'ip_addresses': []
        }
        
        try:
            # Try to resolve A record
            ip = socket.gethostbyname(domain)
            analysis['has_a_record'] = True
            analysis['ip_addresses'].append(ip)
        except socket.gaierror:
            pass
        
        return analysis

    def _analyze_url_structure(self, parsed_url) -> Dict:
        """Analyze URL structure for suspicious patterns"""
        analysis = {
            'path_length': len(parsed_url.path),
            'has_query_params': bool(parsed_url.query),
            'suspicious_path_keywords': [],
            'flags': []
        }
        
        # Check for suspicious path keywords
        suspicious_path_keywords = ['login', 'secure', 'verify', 'update', 'confirm']
        path_lower = parsed_url.path.lower()
        
        for keyword in suspicious_path_keywords:
            if keyword in path_lower:
                analysis['suspicious_path_keywords'].append(keyword)
                analysis['flags'].append(f"Suspicious path keyword: {keyword}")
        
        # Check for overly long paths
        if analysis['path_length'] > 100:
            analysis['flags'].append("Unusually long URL path")
        
        return analysis

    def _analyze_ip_characteristics(self, ip: str) -> Dict:
        """Analyze IP address characteristics"""
        analysis = {
            'is_private': self._is_private_ip(ip),
            'flags': []
        }
        
        if analysis['is_private']:
            analysis['flags'].append("Private IP address")
        
        return analysis

    def _contains_homoglyphs(self, domain: str) -> bool:
        """Basic homoglyph detection"""
        # Simple check for non-ASCII characters that might be homoglyphs
        try:
            domain.encode('ascii')
            return False
        except UnicodeEncodeError:
            return True

    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings using Levenshtein distance"""
        from difflib import SequenceMatcher
        return SequenceMatcher(None, str1, str2).ratio()

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _calculate_threat_score(self, analysis: Dict) -> int:
        """Calculate overall threat score based on analysis"""
        score = 0
        
        # Base score for any flags
        flag_count = len(analysis.get('flags', []))
        score += min(40, flag_count * 8)  # Max 40 points for flags
        
        # TLD risk scoring
        tld_analysis = analysis.get('technical_analysis', {}).get('tld', {})
        if tld_analysis.get('risk_level') == 'high':
            score += 25
        elif tld_analysis.get('risk_level') == 'medium':
            score += 15
        
        # Typosquatting bonus
        typo_analysis = analysis.get('technical_analysis', {}).get('typosquatting', {})
        if typo_analysis.get('is_typosquatting'):
            score += 30
        
        # New domain penalty
        age_analysis = analysis.get('technical_analysis', {}).get('age', {})
        if age_analysis.get('is_new_domain'):
            score += 20
        
        # Suspicious keywords
        keyword_analysis = analysis.get('technical_analysis', {}).get('keywords', {})
        keyword_count = len(keyword_analysis.get('found_keywords', []))
        score += min(15, keyword_count * 5)
        
        return min(100, max(0, score))  # Clamp to 0-100

    def _get_confidence_level(self, score: int) -> str:
        """Determine confidence level based on threat score"""
        if score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'


# Example usage
if __name__ == "__main__":
    analyzer = ThreatAnalyzer()
    
    # Test domains
    test_cases = [
        ('paypa1.com', 'domain'),
        ('http://secure-login.tk/verify', 'url'),
        ('microsoft-update.info', 'domain'),
        ('192.168.1.1', 'ip')
    ]
    
    print("=== Threat Analysis Test ===\n")
    
    for indicator, indicator_type in test_cases:
        result = analyzer.analyze_indicator(indicator, indicator_type)
        print(f"Indicator: {indicator} ({indicator_type})")
        print(f"Threat Score: {result['threat_score']}/100 ({result['confidence_level']} confidence)")
        print(f"Flags: {result['flags']}")
        print("-" * 60)
