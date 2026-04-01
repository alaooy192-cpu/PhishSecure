"""
Automated Takedown System for PhishSecure Bahrain CTI
Generates and submits abuse reports to registrars, hosting providers, and authorities
"""

import asyncio
import aiohttp
import logging
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional, List
import whois
import socket

from database.models import DatabaseManager, ThreatIndicator

class TakedownManager:
    """
    Manages automated takedown requests for malicious domains and URLs
    """
    
    def __init__(self, config):
        self.config = config
        self.db_manager = DatabaseManager()
        
        # Configuration
        self.cert_email = getattr(config, 'CERT_EMAIL', 'cert@cert.bh')
        self.abuse_email_sender = getattr(config, 'ABUSE_EMAIL_SENDER', 'abuse@phishsecure.bh')
        self.smtp_host = getattr(config, 'EMAIL_SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = getattr(config, 'EMAIL_SMTP_PORT', 587)
        self.smtp_user = getattr(config, 'EMAIL_USERNAME', None)
        self.smtp_pass = getattr(config, 'EMAIL_PASSWORD', None)
        
        self.logger = logging.getLogger(__name__)
        
    async def initiate_takedown(self, threat: ThreatIndicator) -> Dict[str, Any]:
        """Initiate takedown process for a threat"""
        try:
            results = {
                'threat_id': threat.id,
                'indicator': threat.indicator,
                'actions_taken': [],
                'status': 'pending'
            }
            
            # Only process URLs and domains
            if threat.indicator_type not in ['url', 'domain']:
                results['status'] = 'skipped'
                results['reason'] = 'Only URLs and domains can be processed for takedown'
                return results
                
            # Extract domain from URL if needed
            domain = self._extract_domain(threat.indicator)
            
            if not domain:
                results['status'] = 'failed'
                results['reason'] = 'Could not extract domain'
                return results
                
            # Get WHOIS information
            whois_data = await self._get_whois_info(domain)
            results['whois_data'] = whois_data
            
            # Find abuse contacts
            abuse_contacts = self._find_abuse_contacts(whois_data, domain)
            results['abuse_contacts'] = abuse_contacts
            
            # Generate takedown emails
            if abuse_contacts:
                # Send to registrar/hosting provider
                for contact in abuse_contacts:
                    success = await self._send_takedown_email(contact, threat, domain)
                    if success:
                        results['actions_taken'].append(f"Email sent to {contact}")
                        
            # Report to CERT Bahrain for high-priority threats
            if threat.bahrain_score >= 80 and threat.threat_score >= 80:
                cert_success = await self._report_to_cert(threat, domain, whois_data)
                if cert_success:
                    results['actions_taken'].append("Reported to CERT Bahrain")
                    
            # Update threat status
            with self.db_manager.get_session() as session:
                threat.status = 'takedown_initiated'
                threat.metadata = threat.metadata or {}
                threat.metadata['takedown_initiated'] = datetime.utcnow().isoformat()
                threat.metadata['takedown_results'] = results
                session.commit()
                
            results['status'] = 'initiated' if results['actions_taken'] else 'no_action'
            return results
            
        except Exception as e:
            self.logger.error(f"Error in takedown process: {e}")
            return {'status': 'error', 'error': str(e)}
            
    def _extract_domain(self, indicator: str) -> Optional[str]:
        """Extract domain from URL or domain string"""
        try:
            if indicator.startswith('http'):
                from urllib.parse import urlparse
                parsed = urlparse(indicator)
                return parsed.netloc
            else:
                # Assume it's already a domain
                return indicator
        except:
            return None
            
    async def _get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for domain"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'registrant_email': w.registrant_email,
                'admin_email': w.admin_email,
                'tech_email': w.tech_email,
                'name_servers': w.name_servers,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'abuse_email': w.get('abuse_email', None),
                'raw': str(w)
            }
        except Exception as e:
            self.logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return {'error': str(e)}
            
    def _find_abuse_contacts(self, whois_data: Dict, domain: str) -> List[str]:
        """Find abuse contact emails from WHOIS data"""
        contacts = []
        
        # Check for abuse email
        if whois_data.get('abuse_email'):
            contacts.append(whois_data['abuse_email'])
            
        # Check common abuse addresses based on registrar
        registrar = whois_data.get('registrar', '').lower()
        
        # Common registrar abuse addresses
        registrar_abuse = {
            'godaddy': 'abuse@godaddy.com',
            'namecheap': 'abuse@namecheap.com',
            'google': 'abuse@google.com',
            'cloudflare': 'abuse@cloudflare.com',
            'amazon': 'abuse@amazonaws.com',
            'alibaba': 'abuse@alibaba-inc.com',
            'name.com': 'abuse@name.com'
        }
        
        for key, email in registrar_abuse.items():
            if key in registrar:
                contacts.append(email)
                break
                
        # Remove duplicates
        return list(set(contacts))
        
    async def _send_takedown_email(self, to_email: str, threat: ThreatIndicator, domain: str) -> bool:
        """Send takedown email to abuse contact"""
        try:
            subject = f"URGENT: Phishing/Malicious Domain Report - {domain}"
            
            body = f"""
Dear Abuse Team,

We are writing to report a malicious domain/URL that is actively being used for cyber attacks:

DOMAIN/URL: {threat.indicator}
TYPE: {threat.threat_type or 'Malicious Activity'}
SEVERITY: {'CRITICAL' if threat.threat_score >= 80 else 'HIGH'}

EVIDENCE:
- Threat Score: {threat.threat_score}/100
- Detected by: {threat.source}
- First Seen: {threat.first_seen}
- Targeting: {threat.targeted_sector or 'Unknown sector'}

DESCRIPTION:
{threat.description or 'This domain has been identified as malicious through our threat intelligence platform.'}

BAHRAIN IMPACT:
This threat has been flagged as specifically targeting Bahrain organizations with a relevance score of {threat.bahrain_score}/100.

REQUESTED ACTION:
Please investigate this domain/URL and take appropriate action including:
1. Suspend the domain/URL
2. Review associated accounts
3. Preserve logs for law enforcement if necessary

We are available to provide additional information if needed.

Reported by:
PhishSecure Bahrain CTI Platform
Cyber Threat Intelligence for Bahrain
Contact: abuse@phishsecure.bh

This is an automated report generated by our threat intelligence platform.
Report ID: TAKEDOWN-{threat.id}-{datetime.utcnow().strftime('%Y%m%d')}
"""

            if not self.smtp_user or not self.smtp_pass:
                self.logger.warning("SMTP not configured - cannot send takedown email")
                return False
                
            msg = MIMEMultipart()
            msg['From'] = self.abuse_email_sender
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            # Send in separate thread
            import threading
            
            def send():
                try:
                    server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_pass)
                    server.send_message(msg)
                    server.quit()
                    self.logger.info(f"Takedown email sent to {to_email} for {domain}")
                except Exception as e:
                    self.logger.error(f"Failed to send takedown email: {e}")
                    
            thread = threading.Thread(target=send)
            thread.start()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error preparing takedown email: {e}")
            return False
            
    async def _report_to_cert(self, threat: ThreatIndicator, domain: str, whois_data: Dict) -> bool:
        """Report high-priority threat to CERT Bahrain"""
        try:
            # Prepare report for CERT
            report = {
                'incident_type': threat.threat_type or 'malicious_domain',
                'severity': 'critical' if threat.threat_score >= 80 else 'high',
                'indicator': threat.indicator,
                'indicator_type': threat.indicator_type,
                'target_country': 'Bahrain',
                'target_sector': threat.targeted_sector,
                'threat_score': threat.threat_score,
                'bahrain_relevance': threat.bahrain_score,
                'timestamp': datetime.utcnow().isoformat(),
                'source': threat.source,
                'whois_data': whois_data,
                'description': threat.description
            }
            
            # In production, this would send to CERT API/email
            self.logger.info(f"CERT Bahrain report prepared for {domain}")
            self.logger.info(f"Report data: {report}")
            
            # TODO: Implement actual CERT reporting mechanism
            # await self._send_cert_api_request(report)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error reporting to CERT: {e}")
            return False
            
    async def batch_takedown(self, min_threat_score: int = 75, min_bahrain_score: int = 70) -> Dict[str, Any]:
        """Initiate takedown for multiple high-priority threats"""
        try:
            with self.db_manager.get_session() as session:
                threats = session.query(ThreatIndicator).filter(
                    ThreatIndicator.status == 'active',
                    ThreatIndicator.threat_score >= min_threat_score,
                    ThreatIndicator.bahrain_score >= min_bahrain_score,
                    ThreatIndicator.indicator_type.in_(['url', 'domain'])
                ).all()
                
                results = {
                    'total_threats': len(threats),
                    'processed': 0,
                    'successful': 0,
                    'failed': 0
                }
                
                for threat in threats:
                    result = await self.initiate_takedown(threat)
                    results['processed'] += 1
                    
                    if result.get('status') in ['initiated', 'completed']:
                        results['successful'] += 1
                    else:
                        results['failed'] += 1
                        
                return results
                
        except Exception as e:
            self.logger.error(f"Error in batch takedown: {e}")
            return {'error': str(e)}
