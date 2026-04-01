"""
Bahrain Relevance Scoring Engine
Calculates how relevant a phishing threat is to Bahrain-based organizations
"""

import re
import json
from typing import Dict, List, Tuple
from difflib import SequenceMatcher

class BahrainRelevanceScorer:
    def __init__(self):
        self.bahrain_keywords = {
            # Financial/Banking (High Priority)
            'banking': {
                'keywords': ['benefit', 'batelco', 'nbb', 'bbk', 'ahli', 'gulf', 'bank', 'banking', 'payment', 'transfer', 'بنك', 'بنفت', 'تحويل'],
                'weight': 25,
                'sector': 'banking'
            },
            
            # Telecommunications (High Priority)
            'telecom': {
                'keywords': ['batelco', 'stc', 'viva', 'zain', 'mobile', 'internet', 'telecom', 'باتلكو', 'اس تي سي', 'فيفا'],
                'weight': 20,
                'sector': 'telecom'
            },
            
            # Government (Critical Priority)
            'government': {
                'keywords': ['bahrain', 'gov', 'egov', 'ministry', 'government', 'official', 'البحرين', 'حكومة', 'وزارة'],
                'weight': 30,
                'sector': 'government'
            },
            
            # Geographic/Cultural
            'geographic': {
                'keywords': ['bahrain', 'manama', 'muharraq', 'riffa', 'hamad', 'isa', 'البحرين', 'المنامة', 'المحرق'],
                'weight': 15,
                'sector': 'geographic'
            },
            
            # Business/Commerce
            'business': {
                'keywords': ['mall', 'shopping', 'delivery', 'shop', 'store', 'business', 'company', 'تسوق', 'توصيل', 'شركة'],
                'weight': 10,
                'sector': 'business'
            }
        }
        
        # Brand impersonation patterns with Levenshtein distance thresholds
        self.brand_patterns = {
            'benefit': {'official': ['benefit.bh'], 'threshold': 0.8},
            'batelco': {'official': ['batelco.bh', 'batelco.com'], 'threshold': 0.8},
            'stc': {'official': ['stc.bh'], 'threshold': 0.9},
            'nbb': {'official': ['nbbonline.com', 'nbb.bh'], 'threshold': 0.8},
            'bbk': {'official': ['bbkonline.com', 'bbk.bh'], 'threshold': 0.8}
        }
        
        # Suspicious TLD patterns for Bahrain context
        self.suspicious_tlds = {
            'high_risk': ['.tk', '.ml', '.ga', '.cf', '.ru', '.cn'],
            'medium_risk': ['.info', '.biz', '.cc', '.ws', '.to'],
            'bahrain_spoofing': ['.bh-', '-bh.', '.bahrain.']
        }

    def calculate_bahrain_score(self, indicator: str, indicator_type: str = 'domain') -> Dict:
        """
        Calculate Bahrain relevance score (0-100)
        
        Args:
            indicator: Domain, URL, or IP to analyze
            indicator_type: 'domain', 'url', or 'ip'
            
        Returns:
            Dict with score, breakdown, matched keywords, and sector classification
        """
        
        score_breakdown = {
            'keyword_match': 0,
            'brand_impersonation': 0,
            'tld_analysis': 0,
            'geographic_relevance': 0,
            'sector_targeting': 0
        }
        
        matched_keywords = []
        detected_sectors = []
        
        # Normalize indicator for analysis
        normalized = indicator.lower().replace('-', '').replace('_', '')
        
        # 1. Keyword Matching (40% of score)
        keyword_score, keywords, sectors = self._analyze_keywords(normalized)
        score_breakdown['keyword_match'] = keyword_score
        matched_keywords.extend(keywords)
        detected_sectors.extend(sectors)
        
        # 2. Brand Impersonation Detection (30% of score)
        brand_score, brand_info = self._detect_brand_impersonation(indicator)
        score_breakdown['brand_impersonation'] = brand_score
        if brand_info:
            matched_keywords.append(f"Brand impersonation: {brand_info}")
        
        # 3. TLD Analysis (15% of score)
        tld_score, tld_info = self._analyze_tld(indicator)
        score_breakdown['tld_analysis'] = tld_score
        if tld_info:
            matched_keywords.append(f"TLD pattern: {tld_info}")
        
        # 4. Geographic Relevance (10% of score)
        geo_score = self._calculate_geographic_relevance(normalized)
        score_breakdown['geographic_relevance'] = geo_score
        
        # 5. Sector Targeting Bonus (5% of score)
        sector_score = self._calculate_sector_bonus(detected_sectors)
        score_breakdown['sector_targeting'] = sector_score
        
        # Calculate final score
        total_score = sum(score_breakdown.values())
        total_score = min(100, max(0, total_score))  # Clamp to 0-100
        
        # Determine primary sector
        primary_sector = self._determine_primary_sector(detected_sectors)
        
        return {
            'bahrain_score': int(total_score),
            'confidence_level': self._get_confidence_level(total_score),
            'primary_sector': primary_sector,
            'matched_keywords': list(set(matched_keywords)),
            'detected_sectors': list(set(detected_sectors)),
            'score_breakdown': score_breakdown,
            'explanation': self._generate_explanation(total_score, score_breakdown, primary_sector)
        }

    def _analyze_keywords(self, normalized_indicator: str) -> Tuple[int, List[str], List[str]]:
        """Analyze keyword matches and return score, keywords, sectors"""
        total_score = 0
        matched_keywords = []
        sectors = []
        
        for category, data in self.bahrain_keywords.items():
            for keyword in data['keywords']:
                if keyword.lower() in normalized_indicator:
                    total_score += data['weight']
                    matched_keywords.append(keyword)
                    sectors.append(data['sector'])
        
        # Cap keyword score at 40
        return min(40, total_score), matched_keywords, sectors

    def _detect_brand_impersonation(self, indicator: str) -> Tuple[int, str]:
        """Detect brand impersonation using similarity matching"""
        max_score = 0
        best_match = ""
        
        for brand, config in self.brand_patterns.items():
            for official_domain in config['official']:
                similarity = SequenceMatcher(None, indicator.lower(), official_domain).ratio()
                
                if similarity >= config['threshold'] and similarity < 0.95:  # Similar but not exact
                    score = int(30 * similarity)  # Max 30 points for brand impersonation
                    if score > max_score:
                        max_score = score
                        best_match = f"{brand} (similarity: {similarity:.2f})"
        
        return max_score, best_match

    def _analyze_tld(self, indicator: str) -> Tuple[int, str]:
        """Analyze TLD for Bahrain-specific suspicious patterns"""
        score = 0
        info = ""
        
        # Extract TLD
        if '.' in indicator:
            tld = '.' + indicator.split('.')[-1]
            
            # Check for high-risk TLDs
            if tld in self.suspicious_tlds['high_risk']:
                score = 15
                info = f"High-risk TLD: {tld}"
            elif tld in self.suspicious_tlds['medium_risk']:
                score = 10
                info = f"Medium-risk TLD: {tld}"
            
            # Check for Bahrain TLD spoofing patterns
            for pattern in self.suspicious_tlds['bahrain_spoofing']:
                if pattern in indicator:
                    score = max(score, 12)
                    info = f"Bahrain TLD spoofing: {pattern}"
        
        return score, info

    def _calculate_geographic_relevance(self, normalized_indicator: str) -> int:
        """Calculate geographic relevance bonus"""
        geo_keywords = ['bahrain', 'manama', 'muharraq', 'البحرين', 'المنامة']
        
        for keyword in geo_keywords:
            if keyword in normalized_indicator:
                return 10
        
        return 0

    def _calculate_sector_bonus(self, detected_sectors: List[str]) -> int:
        """Calculate bonus for targeting critical sectors"""
        if 'government' in detected_sectors:
            return 5
        elif 'banking' in detected_sectors:
            return 4
        elif 'telecom' in detected_sectors:
            return 3
        
        return 0

    def _determine_primary_sector(self, sectors: List[str]) -> str:
        """Determine the primary targeted sector"""
        if not sectors:
            return 'general'
        
        # Priority order
        priority = ['government', 'banking', 'telecom', 'business', 'geographic']
        
        for sector in priority:
            if sector in sectors:
                return sector
        
        return sectors[0] if sectors else 'general'

    def _get_confidence_level(self, score: int) -> str:
        """Determine confidence level based on score"""
        if score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'

    def _generate_explanation(self, score: int, breakdown: Dict, sector: str) -> str:
        """Generate human-readable explanation of the score"""
        explanations = []
        
        if breakdown['keyword_match'] > 20:
            explanations.append(f"Contains Bahrain-specific keywords (+{breakdown['keyword_match']} points)")
        
        if breakdown['brand_impersonation'] > 15:
            explanations.append(f"Potential brand impersonation detected (+{breakdown['brand_impersonation']} points)")
        
        if breakdown['tld_analysis'] > 10:
            explanations.append(f"Suspicious TLD pattern (+{breakdown['tld_analysis']} points)")
        
        if breakdown['geographic_relevance'] > 0:
            explanations.append("Geographic relevance to Bahrain (+10 points)")
        
        if breakdown['sector_targeting'] > 0:
            explanations.append(f"Targets critical sector: {sector} (+{breakdown['sector_targeting']} points)")
        
        if score >= 70:
            risk_level = "HIGH relevance to Bahrain organizations"
        elif score >= 40:
            risk_level = "MEDIUM relevance to Bahrain organizations"
        else:
            risk_level = "LOW relevance to Bahrain organizations"
        
        explanation = f"{risk_level}. "
        if explanations:
            explanation += " ".join(explanations)
        else:
            explanation += "No significant Bahrain-specific indicators detected."
        
        return explanation


# Example usage and testing
if __name__ == "__main__":
    scorer = BahrainRelevanceScorer()
    
    # Test cases
    test_domains = [
        "benefit-pay.tk",           # High score: brand + suspicious TLD
        "batelco-login.info",       # High score: brand + medium risk TLD
        "nbb-online-banking.com",   # High score: brand + banking keywords
        "bahrain-government.ru",    # High score: geo + gov + suspicious TLD
        "secure-login.com",         # Low score: generic
        "paypal-verify.net"         # Low score: no Bahrain relevance
    ]
    
    print("=== Bahrain Relevance Scoring Test ===\n")
    
    for domain in test_domains:
        result = scorer.calculate_bahrain_score(domain)
        print(f"Domain: {domain}")
        print(f"Score: {result['bahrain_score']}/100 ({result['confidence_level']} confidence)")
        print(f"Sector: {result['primary_sector']}")
        print(f"Keywords: {result['matched_keywords']}")
        print(f"Explanation: {result['explanation']}")
        print("-" * 60)
