"""
Real-Time Alerting System for PhishSecure Bahrain CTI
Sends notifications when critical threats targeting Bahrain are detected
"""

import asyncio
import aiohttp
import smtplib
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json

from database.models import DatabaseManager, ThreatIndicator

class RealTimeAlertManager:
    """
    Manages real-time alerts for critical Bahrain threats
    Sends notifications via Slack, Email, Webhooks
    """
    
    def __init__(self, config):
        self.config = config
        self.db_manager = DatabaseManager()
        
        # Alert configuration
        self.slack_webhook_url = getattr(config, 'SLACK_WEBHOOK_URL', None)
        self.teams_webhook_url = getattr(config, 'TEAMS_WEBHOOK_URL', None)
        self.email_smtp_host = getattr(config, 'EMAIL_SMTP_HOST', 'smtp.gmail.com')
        self.email_smtp_port = getattr(config, 'EMAIL_SMTP_PORT', 587)
        self.email_username = getattr(config, 'EMAIL_USERNAME', None)
        self.email_password = getattr(config, 'EMAIL_PASSWORD', None)
        self.alert_recipients = getattr(config, 'ALERT_RECIPIENTS', []).split(',') if hasattr(config, 'ALERT_RECIPIENTS') and config.ALERT_RECIPIENTS else []
        
        # Alert thresholds
        self.critical_threshold = getattr(config, 'CRITICAL_THREAT_SCORE', 80)
        self.bahrain_threshold = getattr(config, 'CRITICAL_BAHRAIN_SCORE', 70)
        
        self.logger = logging.getLogger(__name__)
        
    async def check_and_alert(self, threat: ThreatIndicator):
        """Check if threat meets alert criteria and send notifications"""
        try:
            # Check if threat qualifies for alert
            if not self._should_alert(threat):
                return False
                
            # Generate alert message
            alert_data = self._format_alert(threat)
            
            # Send to all configured channels concurrently
            tasks = []
            
            if self.slack_webhook_url:
                tasks.append(self._send_slack_alert(alert_data))
                
            if self.teams_webhook_url:
                tasks.append(self._send_teams_alert(alert_data))
                
            if self.email_username and self.alert_recipients:
                tasks.append(self._send_email_alert(alert_data))
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                success_count = sum(1 for r in results if r is True)
                self.logger.info(f"Alert sent via {success_count}/{len(tasks)} channels for threat: {threat.indicator}")
                return success_count > 0
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error sending alert: {e}")
            return False
            
    def _should_alert(self, threat: ThreatIndicator) -> bool:
        """Determine if threat should trigger an alert"""
        # Critical Bahrain threats
        if threat.threat_score >= self.critical_threshold and threat.bahrain_score >= self.bahrain_threshold:
            return True
            
        # Banking sector critical threats
        if threat.targeted_sector == 'banking' and threat.threat_score >= 75:
            return True
            
        # Government sector critical threats
        if threat.targeted_sector == 'government' and threat.threat_score >= 70:
            return True
            
        # Infrastructure attacks
        if threat.targeted_sector == 'infrastructure' and threat.threat_score >= 75:
            return True
            
        return False
        
    def _format_alert(self, threat: ThreatIndicator) -> Dict[str, Any]:
        """Format threat data into alert message"""
        severity = 'CRITICAL' if threat.threat_score >= 85 else 'HIGH'
        
        # Get threat type description
        threat_types = {
            'phishing': '[>>] Phishing Campaign',
            'malware': '[!!] Malware Distribution',
            'typosquatting': '[~] Typosquatting',
            'credential_harvesting': '[KEY] Credential Harvesting',
            'infrastructure': '[INF] Infrastructure Attack'
        }
        
        threat_type = threat_types.get(threat.threat_type, '[WARN] Suspicious Activity')
        
        return {
            'severity': severity,
            'threat_type': threat_type,
            'indicator': threat.indicator,
            'indicator_type': threat.indicator_type,
            'threat_score': threat.threat_score,
            'bahrain_score': threat.bahrain_score,
            'sector': threat.targeted_sector or 'unknown',
            'source': threat.source,
            'first_seen': threat.first_seen.isoformat() if threat.first_seen else None,
            'description': threat.description or 'No description available',
            'target_brands': threat.target_brands or [],
            'timestamp': datetime.utcnow().isoformat(),
            'dashboard_url': f"https://phishsecure-bahrain.vercel.app/indicators?id={threat.id}"
        }
        
    async def _send_slack_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send alert to Slack webhook"""
        try:
            color = '#FF0000' if alert_data['severity'] == 'CRITICAL' else '#FFA500'
            
            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"[ALERT] {alert_data['severity']} Bahrain Threat Detected",
                        "title_link": alert_data['dashboard_url'],
                        "fields": [
                            {"title": "Threat Type", "value": alert_data['threat_type'], "short": True},
                            {"title": "Target Sector", "value": alert_data['sector'], "short": True},
                            {"title": "Indicator", "value": f"`{alert_data['indicator']}`", "short": False},
                            {"title": "Threat Score", "value": f"{alert_data['threat_score']}/100", "short": True},
                            {"title": "Bahrain Relevance", "value": f"{alert_data['bahrain_score']}/100", "short": True},
                            {"title": "Source", "value": alert_data['source'], "short": True},
                            {"title": "Time Detected", "value": alert_data['timestamp'], "short": True}
                        ],
                        "footer": "PhishSecure Bahrain CTI",
                        "ts": int(datetime.utcnow().timestamp())
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.slack_webhook_url,
                    json=payload,
                    timeout=10
                ) as response:
                    if response.status == 200:
                        self.logger.info(f"Slack alert sent for {alert_data['indicator']}")
                        return True
                    else:
                        self.logger.warning(f"Slack alert failed: {response.status}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Error sending Slack alert: {e}")
            return False
            
    async def _send_teams_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send alert to Microsoft Teams webhook"""
        try:
            theme_color = "FF0000" if alert_data['severity'] == 'CRITICAL' else "FFA500"
            
            payload = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "themeColor": theme_color,
                "summary": f"{alert_data['severity']} Bahrain Threat: {alert_data['indicator']}",
                "sections": [
                    {
                        "activityTitle": f"[ALERT] {alert_data['severity']} Threat Detected",
                        "activitySubtitle": f"PhishSecure Bahrain CTI - {alert_data['timestamp']}",
                        "facts": [
                            {"name": "Threat Type:", "value": alert_data['threat_type']},
                            {"name": "Indicator:", "value": alert_data['indicator']},
                            {"name": "Target Sector:", "value": alert_data['sector']},
                            {"name": "Threat Score:", "value": f"{alert_data['threat_score']}/100"},
                            {"name": "Bahrain Relevance:", "value": f"{alert_data['bahrain_score']}/100"},
                            {"name": "Source:", "value": alert_data['source']},
                            {"name": "Detected:", "value": alert_data['timestamp']}
                        ],
                        "markdown": True
                    }
                ],
                "potentialAction": [
                    {
                        "@type": "OpenUri",
                        "name": "View in Dashboard",
                        "targets": [{"os": "default", "uri": alert_data['dashboard_url']}]
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.teams_webhook_url,
                    json=payload,
                    timeout=10
                ) as response:
                    if response.status == 200:
                        self.logger.info(f"Teams alert sent for {alert_data['indicator']}")
                        return True
                    else:
                        self.logger.warning(f"Teams alert failed: {response.status}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Error sending Teams alert: {e}")
            return False
            
    async def _send_email_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send alert via email"""
        try:
            subject = f"[ALERT] {alert_data['severity']} Bahrain Threat: {alert_data['indicator']}"
            
            body = f"""
CRITICAL THREAT DETECTED - PhishSecure Bahrain CTI

Threat Type: {alert_data['threat_type']}
Severity: {alert_data['severity']}
Indicator: {alert_data['indicator']}
Indicator Type: {alert_data['indicator_type']}

Target Details:
- Sector: {alert_data['sector']}
- Threat Score: {alert_data['threat_score']}/100
- Bahrain Relevance: {alert_data['bahrain_score']}/100
- Source: {alert_data['source']}
- Detected: {alert_data['timestamp']}

Description: {alert_data['description']}

View in Dashboard: {alert_data['dashboard_url']}

---
This alert was automatically generated by PhishSecure Bahrain CTI Platform.
            """
            
            msg = MIMEMultipart()
            msg['From'] = self.email_username
            msg['To'] = ', '.join(self.alert_recipients)
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email (run in thread to not block)
            import threading
            
            def send_email():
                try:
                    server = smtplib.SMTP(self.email_smtp_host, self.email_smtp_port)
                    server.starttls()
                    server.login(self.email_username, self.email_password)
                    server.send_message(msg)
                    server.quit()
                    self.logger.info(f"Email alert sent to {len(self.alert_recipients)} recipients")
                except Exception as e:
                    self.logger.error(f"Error sending email: {e}")
                    
            thread = threading.Thread(target=send_email)
            thread.start()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error preparing email alert: {e}")
            return False
            
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get statistics on alert system"""
        return {
            'channels_configured': {
                'slack': bool(self.slack_webhook_url),
                'teams': bool(self.teams_webhook_url),
                'email': bool(self.email_username and self.alert_recipients)
            },
            'alert_thresholds': {
                'critical_score': self.critical_threshold,
                'bahrain_score': self.bahrain_threshold
            },
            'recipients_count': len(self.alert_recipients)
        }
