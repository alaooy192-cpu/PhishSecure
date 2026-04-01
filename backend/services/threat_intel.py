"""
Threat Intelligence Service for PhishSecure
Integrates with VirusTotal and WHOIS to provide global threat context
"""

import requests
import whois
import os
import time
from datetime import datetime
from typing import Dict, Optional

class ThreatIntelService:
    def __init__(self):
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY', 'cd21c955bc5d2baacde63903d31963208e3668ff41e740cc8a06cf4ae90884cd')
        self.vt_base_url = 'https://www.virustotal.com/api/v3'
        
    def check_virustotal(self, domain: str) -> Dict:
        """Check domain reputation against VirusTotal"""
        try:
            headers = {'x-apikey': self.vt_api_key}
            url = f'{self.vt_base_url}/domains/{domain}'
            
            # Add timeout to prevent hanging
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                # Extract key metrics
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                malicious_count = last_analysis_stats.get('malicious', 0)
                harmless_count = last_analysis_stats.get('harmless', 0)
                suspicious_count = last_analysis_stats.get('suspicious', 0)
                undetected_count = last_analysis_stats.get('undetected', 0)
                
                # Calculate reputation score
                total_engines = sum(last_analysis_stats.values())
                threat_percentage = (malicious_count + suspicious_count) / total_engines * 100 if total_engines > 0 else 0
                
                return {
                    'success': True,
                    'malicious_count': malicious_count,
                    'suspicious_count': suspicious_count,
                    'harmless_count': harmless_count,
                    'undetected_count': undetected_count,
                    'total_engines': total_engines,
                    'threat_percentage': round(threat_percentage, 1),
                    'reputation': attributes.get('reputation', 0),
                    'creation_date': attributes.get('creation_date'),
                    'last_modification_date': attributes.get('last_modification_date'),
                    'categories': attributes.get('categories', {}),
                    'subdomains': attributes.get('subdomains', [])
                }
            elif response.status_code == 404:
                return {'success': False, 'error': 'Domain not found in VirusTotal'}
            else:
                return {'success': False, 'error': f'VirusTotal API error: {response.status_code}'}
                
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'VirusTotal request timed out'}
        except Exception as e:
            return {'success': False, 'error': f'VirusTotal request failed: {str(e)}'}
    
    def get_domain_age(self, domain: str) -> Dict:
        """Get domain age using WHOIS"""
        try:
            domain_info = whois.whois(domain)
            
            # Handle cases where creation_date is a list or single value
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                return {
                    'success': True,
                    'age_days': age_days,
                    'creation_date': creation_date.strftime('%Y-%m-%d'),
                    'registrar': domain_info.registrar,
                    'expires_date': domain_info.expiration_date,
                    'status': domain_info.status
                }
            else:
                return {'success': False, 'error': 'Could not determine domain age'}
                
        except Exception as e:
            return {'success': False, 'error': f'WHOIS lookup failed: {str(e)}'}
    
    def analyze_threat_level(self, vt_data: Dict, whois_data: Dict, base_result: Dict) -> Dict:
        """Determine if this is part of an active phishing campaign"""
        threat_indicators = []
        campaign_likelihood = 'low'
        
        # VirusTotal threat indicators
        if vt_data.get('success'):
            malicious_count = vt_data.get('malicious_count', 0)
            suspicious_count = vt_data.get('suspicious_count', 0)
            threat_percentage = vt_data.get('threat_percentage', 0)
            
            if malicious_count >= 10:
                threat_indicators.append('High malicious detections')
                campaign_likelihood = 'high'
            elif malicious_count >= 5:
                threat_indicators.append('Multiple malicious detections')
                campaign_likelihood = 'medium'
            elif malicious_count > 0:
                threat_indicators.append('Known malicious domain')
                campaign_likelihood = 'medium'
            
            if threat_percentage >= 30:
                threat_indicators.append('High threat percentage')
            elif threat_percentage >= 15:
                threat_indicators.append('Moderate threat percentage')
        
        # Domain age indicators
        if whois_data.get('success'):
            age_days = whois_data.get('age_days', 0)
            
            if age_days <= 7:
                threat_indicators.append('Very new domain (high risk)')
                campaign_likelihood = 'high' if campaign_likelihood != 'high' else campaign_likelihood
            elif age_days <= 30:
                threat_indicators.append('Recently registered domain')
                campaign_likelihood = 'medium' if campaign_likelihood == 'low' else campaign_likelihood
            elif age_days <= 90:
                threat_indicators.append('New domain')
        
        # Combine with base phishing detection
        if base_result.get('verdict') == 'phishing':
            if campaign_likelihood == 'high':
                campaign_likelihood = 'very_high'
            elif campaign_likelihood == 'medium':
                campaign_likelihood = 'high'
            elif campaign_likelihood == 'low':
                campaign_likelihood = 'medium'
        
        # Determine threat status
        threat_status = 'clear'
        if campaign_likelihood == 'very_high':
            threat_status = 'critical'
        elif campaign_likelihood == 'high':
            threat_status = 'active_campaign'
        elif campaign_likelihood == 'medium':
            threat_status = 'suspicious'
        elif len(threat_indicators) > 0:
            threat_status = 'monitor'
        
        return {
            'threat_status': threat_status,
            'campaign_likelihood': campaign_likelihood,
            'threat_indicators': threat_indicators,
            'risk_level': self._calculate_risk_level(vt_data, whois_data, base_result)
        }
    
    def _calculate_risk_level(self, vt_data: Dict, whois_data: Dict, base_result: Dict) -> str:
        """Calculate overall risk level"""
        risk_score = 0
        
        # Base phishing detection
        if base_result.get('verdict') == 'phishing':
            risk_score += 30
        
        # VirusTotal contribution
        if vt_data.get('success'):
            malicious_count = vt_data.get('malicious_count', 0)
            risk_score += min(malicious_count * 5, 40)  # Cap at 40 points
        
        # Domain age contribution
        if whois_data.get('success'):
            age_days = whois_data.get('age_days', 365)
            if age_days <= 7:
                risk_score += 30
            elif age_days <= 30:
                risk_score += 20
            elif age_days <= 90:
                risk_score += 10
        
        # Determine risk level
        if risk_score >= 70:
            return 'critical'
        elif risk_score >= 50:
            return 'high'
        elif risk_score >= 30:
            return 'medium'
        elif risk_score >= 15:
            return 'low'
        else:
            return 'minimal'
    
    def enrich_analysis(self, domain: str, base_result: Dict) -> Dict:
        """Main method to enrich phishing analysis with threat intelligence"""
        # Get threat intelligence data
        vt_data = self.check_virustotal(domain)
        whois_data = self.get_domain_age(domain)
        
        # Analyze threat level
        threat_analysis = self.analyze_threat_level(vt_data, whois_data, base_result)
        
        # Build enriched result
        enriched_result = {
            **base_result,
            'threat_intel': {
                'virustotal': vt_data,
                'whois': whois_data,
                'threat_status': threat_analysis['threat_status'],
                'campaign_likelihood': threat_analysis['campaign_likelihood'],
                'threat_indicators': threat_analysis['threat_indicators'],
                'risk_level': threat_analysis['risk_level'],
                'last_checked': datetime.now().isoformat()
            }
        }
        
        # Add business context
        enriched_result['business_context'] = self._generate_business_context(
            threat_analysis, vt_data, whois_data
        )
        
        return enriched_result
    
    def _generate_business_context(self, threat_analysis: Dict, vt_data: Dict, whois_data: Dict) -> Dict:
        """Generate business-focused insights"""
        context = {
            'organizational_impact': 'low',
            'recommended_actions': [],
            'threat_timeline': 'unknown',
            'global_context': 'local'
        }
        
        # Determine organizational impact
        if threat_analysis['threat_status'] in ['critical', 'active_campaign']:
            context['organizational_impact'] = 'high'
            SUSPICIOUS_KEYWORDS = [
                'login', 'signin', 'sign-in', 'logon', 'log-on',
                'secure', 'security', 'verify', 'verification', 'validate', 'validation',
                'account', 'accounts', 'update', 'confirm', 'confirmation',
                'password', 'credential', 'auth', 'authenticate', 'authentication',
                'suspend', 'suspended', 'locked', 'unlock', 'restore', 'recover', 'recovery',
                'alert', 'warning', 'urgent', 'immediate', 'action', 'required',
                'billing', 'invoice', 'payment', 'pay', 'wallet', 'bank', 'banking',
                'support', 'help', 'helpdesk', 'service', 'customer', 'client',
                'webmail', 'inbox',
                'online', 'web', 'portal', 'access', 'member', 'user'
            ]
            context['recommended_actions'] = [
                'Block domain immediately',
                'Alert security team',
                'Notify affected departments',
                'Update email filters'
            ]
        elif threat_analysis['threat_status'] == 'suspicious':
            context['organizational_impact'] = 'medium'
            context['recommended_actions'] = [
                'Monitor for similar emails',
                'Increase security awareness',
                'Consider temporary block'
            ]
        else:
            context['recommended_actions'] = [
                'Continue monitoring',
                'Standard security protocols'
            ]
        
        # Global context
        if vt_data.get('success') and vt_data.get('malicious_count', 0) > 0:
            context['global_context'] = 'known_threat'
            context['threat_timeline'] = 'active'
        elif whois_data.get('success') and whois_data.get('age_days', 0) <= 30:
            context['global_context'] = 'emerging_threat'
            context['threat_timeline'] = 'recent'
        
        return context

# Singleton instance
threat_intel_service = ThreatIntelService()
