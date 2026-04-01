"""
Threat Actor Attribution Service for PhishSecure
Links suspicious domains to known phishing kits/campaigns and provides geographic context
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class PhishingKit:
    """Known phishing kit signature"""
    name: str
    description: str
    indicators: List[str]
    typical_targets: List[str]
    first_seen: str
    threat_level: str  # 'low', 'medium', 'high', 'critical'
    ttps: List[str]  # Tactics, Techniques, and Procedures


# Database of known phishing kit patterns
KNOWN_PHISHING_KITS = [
    PhishingKit(
        name="LogoKit",
        description="Modular phishing kit that dynamically fetches victim company logos to create convincing fake login pages",
        indicators=["logo", "login", "signin", "auth", "verify"],
        typical_targets=["Microsoft 365", "Google Workspace", "Corporate email"],
        first_seen="2021",
        threat_level="high",
        ttps=["Dynamic logo fetching", "Real-time credential harvesting", "Multi-brand targeting"]
    ),
    PhishingKit(
        name="Kr3pto",
        description="Banking-focused phishing kit targeting financial institutions with SMS-based 2FA bypass",
        indicators=["bank", "secure", "verify", "account", "update", "confirm"],
        typical_targets=["Banks", "Financial services", "Payment processors"],
        first_seen="2022",
        threat_level="critical",
        ttps=["2FA interception", "Real-time session hijacking", "SMS phishing integration"]
    ),
    PhishingKit(
        name="EvilProxy",
        description="Adversary-in-the-middle phishing kit that can bypass MFA by proxying authentication",
        indicators=["login", "auth", "sso", "oauth", "microsoft", "google"],
        typical_targets=["Microsoft 365", "Google", "Enterprise SSO"],
        first_seen="2022",
        threat_level="critical",
        ttps=["MFA bypass", "Session token theft", "Reverse proxy phishing"]
    ),
    PhishingKit(
        name="Caffeine",
        description="Phishing-as-a-Service platform offering customizable phishing pages",
        indicators=["office", "outlook", "onedrive", "sharepoint", "document"],
        typical_targets=["Microsoft 365", "SharePoint", "OneDrive"],
        first_seen="2022",
        threat_level="high",
        ttps=["Customizable templates", "Automated deployment", "Credential exfiltration"]
    ),
    PhishingKit(
        name="16Shop",
        description="Commercial phishing kit sold on underground forums, targeting major brands",
        indicators=["apple", "amazon", "paypal", "cash", "app"],
        typical_targets=["Apple", "Amazon", "PayPal", "Cash App"],
        first_seen="2018",
        threat_level="high",
        ttps=["Brand impersonation", "Mobile-optimized pages", "Geo-targeting"]
    ),
    PhishingKit(
        name="BulletProofLink",
        description="Large-scale phishing-as-a-service operation with extensive template library",
        indicators=["secure", "verify", "update", "confirm", "alert", "notification"],
        typical_targets=["Multiple brands", "Email providers", "Social media"],
        first_seen="2020",
        threat_level="high",
        ttps=["Template marketplace", "Hosting infrastructure", "Affiliate model"]
    ),
    PhishingKit(
        name="Greatness",
        description="Microsoft 365-focused phishing kit with MFA bypass capabilities",
        indicators=["microsoft", "office", "365", "outlook", "teams", "onedrive"],
        typical_targets=["Microsoft 365", "Azure AD"],
        first_seen="2023",
        threat_level="critical",
        ttps=["MFA bypass", "Telegram bot integration", "Real-time notifications"]
    ),
    PhishingKit(
        name="W3LL Panel",
        description="Business Email Compromise focused kit targeting corporate accounts",
        indicators=["business", "corporate", "invoice", "payment", "wire", "transfer"],
        typical_targets=["Corporate email", "Finance departments"],
        first_seen="2023",
        threat_level="critical",
        ttps=["BEC attacks", "Account takeover", "Email thread hijacking"]
    ),
    PhishingKit(
        name="Strox",
        description="Cryptocurrency-focused phishing kit targeting wallet and exchange users",
        indicators=["crypto", "wallet", "bitcoin", "eth", "binance", "coinbase", "metamask"],
        typical_targets=["Cryptocurrency exchanges", "Wallet providers"],
        first_seen="2021",
        threat_level="high",
        ttps=["Seed phrase harvesting", "Wallet draining", "Exchange impersonation"]
    ),
    PhishingKit(
        name="Robin Banks",
        description="Banking phishing kit with advanced evasion and anti-detection features",
        indicators=["bank", "chase", "wells", "citi", "boa", "capital"],
        typical_targets=["US Banks", "Credit unions"],
        first_seen="2022",
        threat_level="critical",
        ttps=["Bot detection bypass", "Geo-fencing", "Device fingerprinting"]
    )
]

# Registrar reputation database (simplified)
REGISTRAR_REPUTATION = {
    # High-risk registrars often used for malicious domains
    'high_risk': [
        'namecheap', 'namesilo', 'porkbun', 'dynadot', 'regtons',
        'nicenic', 'west263', 'bizcn', 'hichina', 'xinnet',
        'ename', 'dnspod', '22net', 'reg.ru', 'r01'
    ],
    # Moderate risk
    'medium_risk': [
        'godaddy', 'tucows', 'enom', 'name.com', 'hover',
        'dreamhost', 'bluehost', 'hostgator'
    ],
    # Generally legitimate
    'low_risk': [
        'markmonitor', 'corporatedomains', 'cscdbs', 'safenames',
        'networksolutions', 'register.com', 'cloudflare'
    ]
}

# Geographic threat intelligence
GEO_THREAT_INTEL = {
    'high_risk_regions': {
        'RU': {'name': 'Russia', 'common_attacks': ['BEC', 'Ransomware', 'APT']},
        'CN': {'name': 'China', 'common_attacks': ['APT', 'IP theft', 'Espionage']},
        'NG': {'name': 'Nigeria', 'common_attacks': ['BEC', '419 scams', 'Romance scams']},
        'RO': {'name': 'Romania', 'common_attacks': ['Carding', 'Phishing']},
        'BR': {'name': 'Brazil', 'common_attacks': ['Banking trojans', 'Phishing']},
        'IN': {'name': 'India', 'common_attacks': ['Tech support scams', 'Phishing']},
        'PK': {'name': 'Pakistan', 'common_attacks': ['Phishing', 'Scams']},
        'VN': {'name': 'Vietnam', 'common_attacks': ['Phishing', 'Malware']},
        'ID': {'name': 'Indonesia', 'common_attacks': ['Phishing', 'Carding']},
        'UA': {'name': 'Ukraine', 'common_attacks': ['Carding', 'Malware']}
    },
    'bulletproof_hosting_regions': ['RU', 'UA', 'MD', 'NL', 'PA', 'SC', 'BZ']
}

# TLD threat intelligence
TLD_THREAT_INTEL = {
    'high_risk': {
        'tk': 'Tokelau - Free domain, heavily abused',
        'ml': 'Mali - Free domain, heavily abused',
        'ga': 'Gabon - Free domain, heavily abused',
        'cf': 'Central African Republic - Free domain, heavily abused',
        'gq': 'Equatorial Guinea - Free domain, heavily abused',
        'xyz': 'Generic - Cheap, commonly abused',
        'top': 'Generic - Cheap, commonly abused',
        'work': 'Generic - Commonly used in phishing',
        'click': 'Generic - Commonly used in phishing',
        'link': 'Generic - Commonly used in phishing',
        'buzz': 'Generic - Commonly used in spam/phishing',
        'icu': 'Generic - Heavily abused for phishing'
    },
    'medium_risk': {
        'info': 'Generic - Sometimes abused',
        'biz': 'Business - Sometimes abused',
        'online': 'Generic - Sometimes abused',
        'site': 'Generic - Sometimes abused',
        'website': 'Generic - Sometimes abused',
        'space': 'Generic - Sometimes abused',
        'fun': 'Generic - Sometimes abused',
        'live': 'Generic - Sometimes abused'
    }
}


class ThreatAttributionService:
    def __init__(self):
        self.phishing_kits = KNOWN_PHISHING_KITS
    
    def analyze_domain_patterns(self, domain: str) -> Dict:
        """Analyze domain for patterns matching known phishing kits"""
        domain_lower = domain.lower()
        matches = []
        
        for kit in self.phishing_kits:
            score = 0
            matched_indicators = []
            
            for indicator in kit.indicators:
                if indicator in domain_lower:
                    score += 1
                    matched_indicators.append(indicator)
            
            # Calculate match percentage
            if score > 0:
                match_percentage = (score / len(kit.indicators)) * 100
                if match_percentage >= 20:  # At least 20% indicator match
                    matches.append({
                        'kit_name': kit.name,
                        'description': kit.description,
                        'match_score': round(match_percentage, 1),
                        'matched_indicators': matched_indicators,
                        'typical_targets': kit.typical_targets,
                        'threat_level': kit.threat_level,
                        'ttps': kit.ttps,
                        'first_seen': kit.first_seen
                    })
        
        # Sort by match score
        matches.sort(key=lambda x: x['match_score'], reverse=True)
        
        return {
            'matches': matches[:3],  # Top 3 matches
            'has_kit_match': len(matches) > 0,
            'highest_match': matches[0] if matches else None
        }
    
    def analyze_registrar(self, registrar: Optional[str]) -> Dict:
        """Analyze domain registrar for threat indicators"""
        if not registrar:
            return {
                'risk_level': 'unknown',
                'explanation': 'Registrar information not available',
                'registrar': None
            }
        
        registrar_lower = registrar.lower()
        
        # Check against known registrar reputation
        for high_risk in REGISTRAR_REPUTATION['high_risk']:
            if high_risk in registrar_lower:
                return {
                    'risk_level': 'high',
                    'explanation': f'Registrar "{registrar}" is commonly used for malicious domain registration',
                    'registrar': registrar,
                    'indicator': 'High-risk registrar'
                }
        
        for medium_risk in REGISTRAR_REPUTATION['medium_risk']:
            if medium_risk in registrar_lower:
                return {
                    'risk_level': 'medium',
                    'explanation': f'Registrar "{registrar}" has mixed reputation',
                    'registrar': registrar,
                    'indicator': 'Medium-risk registrar'
                }
        
        for low_risk in REGISTRAR_REPUTATION['low_risk']:
            if low_risk in registrar_lower:
                return {
                    'risk_level': 'low',
                    'explanation': f'Registrar "{registrar}" is typically used by legitimate organizations',
                    'registrar': registrar,
                    'indicator': 'Enterprise registrar'
                }
        
        return {
            'risk_level': 'unknown',
            'explanation': f'Registrar "{registrar}" has no specific reputation data',
            'registrar': registrar
        }
    
    def analyze_tld(self, domain: str) -> Dict:
        """Analyze TLD for threat indicators"""
        tld = domain.split('.')[-1].lower()
        
        if tld in TLD_THREAT_INTEL['high_risk']:
            return {
                'tld': tld,
                'risk_level': 'high',
                'explanation': TLD_THREAT_INTEL['high_risk'][tld],
                'recommendation': 'Exercise extreme caution with this TLD'
            }
        
        if tld in TLD_THREAT_INTEL['medium_risk']:
            return {
                'tld': tld,
                'risk_level': 'medium',
                'explanation': TLD_THREAT_INTEL['medium_risk'][tld],
                'recommendation': 'Verify sender through other means'
            }
        
        return {
            'tld': tld,
            'risk_level': 'low',
            'explanation': f'.{tld} is a standard TLD',
            'recommendation': None
        }
    
    def infer_geographic_origin(self, domain: str, registrar: Optional[str] = None, 
                                whois_data: Optional[Dict] = None) -> Dict:
        """Infer potential geographic origin based on available data"""
        indicators = []
        likely_regions = []
        
        # Check TLD for country hints
        tld = domain.split('.')[-1].lower()
        country_tlds = {
            'ru': 'Russia', 'cn': 'China', 'br': 'Brazil', 'in': 'India',
            'pk': 'Pakistan', 'ng': 'Nigeria', 'ro': 'Romania', 'ua': 'Ukraine',
            'vn': 'Vietnam', 'id': 'Indonesia', 'ir': 'Iran', 'kp': 'North Korea'
        }
        
        if tld in country_tlds:
            likely_regions.append(country_tlds[tld])
            indicators.append(f"Country-code TLD: .{tld}")
        
        # Check registrar for geographic hints
        if registrar:
            registrar_lower = registrar.lower()
            if any(x in registrar_lower for x in ['china', 'hichina', 'xinnet', 'bizcn', 'west263']):
                likely_regions.append('China')
                indicators.append('Chinese registrar')
            elif any(x in registrar_lower for x in ['reg.ru', 'r01', 'nic.ru']):
                likely_regions.append('Russia')
                indicators.append('Russian registrar')
        
        # Check WHOIS data if available
        if whois_data:
            if whois_data.get('country'):
                country = whois_data['country']
                if country in GEO_THREAT_INTEL['high_risk_regions']:
                    region_info = GEO_THREAT_INTEL['high_risk_regions'][country]
                    likely_regions.append(region_info['name'])
                    indicators.append(f"WHOIS country: {region_info['name']}")
        
        # Determine risk based on geographic indicators
        geo_risk = 'unknown'
        if likely_regions:
            for region in likely_regions:
                for code, info in GEO_THREAT_INTEL['high_risk_regions'].items():
                    if info['name'] == region:
                        geo_risk = 'high'
                        break
        
        return {
            'likely_regions': list(set(likely_regions)),
            'indicators': indicators,
            'geo_risk': geo_risk,
            'bulletproof_hosting_likely': tld in ['ru', 'ua', 'md'] or 
                                          (registrar and any(x in registrar.lower() for x in ['bulletproof', 'offshore']))
        }
    
    def get_attack_pattern_analysis(self, domain: str) -> Dict:
        """Analyze domain for common attack patterns"""
        domain_lower = domain.lower()
        patterns = []
        
        # Brand impersonation patterns
        brands = ['paypal', 'microsoft', 'apple', 'amazon', 'google', 'facebook', 
                  'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'adobe',
                  'chase', 'wellsfargo', 'bankofamerica', 'citibank']
        
        for brand in brands:
            if brand in domain_lower:
                # Check if it's NOT the legitimate domain
                legitimate = [f'{brand}.com', f'{brand}.net', f'{brand}.org']
                if not any(domain_lower == leg or domain_lower.endswith('.' + leg) for leg in legitimate):
                    patterns.append({
                        'type': 'brand_impersonation',
                        'brand': brand,
                        'description': f'Domain appears to impersonate {brand.title()}'
                    })
        
        # Urgency/action patterns
        urgency_keywords = ['urgent', 'immediate', 'suspend', 'locked', 'verify', 
                          'confirm', 'update', 'expire', 'alert', 'warning']
        found_urgency = [kw for kw in urgency_keywords if kw in domain_lower]
        if found_urgency:
            patterns.append({
                'type': 'urgency_tactic',
                'keywords': found_urgency,
                'description': 'Domain uses urgency keywords to pressure victims'
            })
        
        # Credential harvesting patterns
        cred_keywords = ['login', 'signin', 'password', 'credential', 'auth', 'sso', 'oauth']
        found_cred = [kw for kw in cred_keywords if kw in domain_lower]
        if found_cred:
            patterns.append({
                'type': 'credential_harvesting',
                'keywords': found_cred,
                'description': 'Domain appears designed to harvest credentials'
            })
        
        # Financial fraud patterns
        financial_keywords = ['bank', 'payment', 'invoice', 'billing', 'wire', 'transfer', 'refund']
        found_financial = [kw for kw in financial_keywords if kw in domain_lower]
        if found_financial:
            patterns.append({
                'type': 'financial_fraud',
                'keywords': found_financial,
                'description': 'Domain may be used for financial fraud'
            })
        
        return {
            'patterns': patterns,
            'pattern_count': len(patterns),
            'primary_attack_type': patterns[0]['type'] if patterns else None
        }
    
    def get_full_attribution(self, domain: str, whois_data: Optional[Dict] = None) -> Dict:
        """Get complete threat attribution analysis"""
        
        # Get registrar from WHOIS if available
        registrar = whois_data.get('registrar') if whois_data else None
        
        # Run all analyses
        kit_analysis = self.analyze_domain_patterns(domain)
        registrar_analysis = self.analyze_registrar(registrar)
        tld_analysis = self.analyze_tld(domain)
        geo_analysis = self.infer_geographic_origin(domain, registrar, whois_data)
        attack_patterns = self.get_attack_pattern_analysis(domain)
        
        # Calculate overall threat attribution confidence
        confidence_score = 0
        attribution_indicators = []
        
        if kit_analysis['has_kit_match']:
            confidence_score += 30
            attribution_indicators.append(f"Matches {kit_analysis['highest_match']['kit_name']} phishing kit patterns")
        
        if registrar_analysis['risk_level'] == 'high':
            confidence_score += 20
            attribution_indicators.append(registrar_analysis['indicator'])
        
        if tld_analysis['risk_level'] == 'high':
            confidence_score += 20
            attribution_indicators.append(f"High-risk TLD: .{tld_analysis['tld']}")
        
        if geo_analysis['geo_risk'] == 'high':
            confidence_score += 15
            attribution_indicators.extend(geo_analysis['indicators'])
        
        if attack_patterns['pattern_count'] > 0:
            confidence_score += 15
            attribution_indicators.append(f"Attack pattern: {attack_patterns['primary_attack_type']}")
        
        # Determine attribution confidence level
        if confidence_score >= 70:
            confidence_level = 'high'
        elif confidence_score >= 40:
            confidence_level = 'medium'
        elif confidence_score >= 20:
            confidence_level = 'low'
        else:
            confidence_level = 'minimal'
        
        # Generate summary
        summary = self._generate_attribution_summary(
            domain, kit_analysis, geo_analysis, attack_patterns, confidence_level
        )
        
        return {
            'domain': domain,
            'attribution_confidence': confidence_level,
            'confidence_score': confidence_score,
            'summary': summary,
            'indicators': attribution_indicators,
            'phishing_kit': kit_analysis,
            'registrar_analysis': registrar_analysis,
            'tld_analysis': tld_analysis,
            'geographic_origin': geo_analysis,
            'attack_patterns': attack_patterns,
            'timestamp': datetime.now().isoformat()
        }
    
    def _generate_attribution_summary(self, domain: str, kit_analysis: Dict, 
                                      geo_analysis: Dict, attack_patterns: Dict,
                                      confidence_level: str) -> str:
        """Generate human-readable attribution summary"""
        
        parts = []
        
        # Kit match
        if kit_analysis['has_kit_match']:
            kit = kit_analysis['highest_match']
            parts.append(f"This domain shows patterns similar to the '{kit['kit_name']}' phishing kit "
                        f"({kit['description'][:100]}...).")
        
        # Geographic origin
        if geo_analysis['likely_regions']:
            regions = ', '.join(geo_analysis['likely_regions'])
            parts.append(f"Geographic indicators suggest origin from: {regions}.")
        
        # Attack type
        if attack_patterns['patterns']:
            attack_type = attack_patterns['primary_attack_type'].replace('_', ' ').title()
            parts.append(f"Primary attack vector appears to be: {attack_type}.")
        
        if not parts:
            return f"Limited attribution data available for {domain}. Exercise standard caution."
        
        confidence_text = {
            'high': 'High confidence attribution',
            'medium': 'Moderate confidence attribution',
            'low': 'Low confidence attribution',
            'minimal': 'Speculative attribution'
        }
        
        return f"{confidence_text[confidence_level]}: " + " ".join(parts)


# Singleton instance
threat_attribution_service = ThreatAttributionService()
