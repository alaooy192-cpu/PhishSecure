"""
MISP Integration for PhishSecure Bahrain CTI
Exports threats to MISP (Malware Information Sharing Platform)
Connects to the global threat sharing community
"""

import asyncio
import aiohttp
import logging
from datetime import datetime
from typing import Dict, Any, Optional
import json

from database.models import DatabaseManager, ThreatIndicator

class MISPIntegration:
    """
    MISP (Malware Information Sharing Platform) integration
    Shares Bahrain-focused threat intelligence with the security community
    """
    
    def __init__(self, config):
        self.config = config
        self.db_manager = DatabaseManager()
        
        # MISP Configuration
        self.misp_url = getattr(config, 'MISP_URL', None)
        self.api_key = getattr(config, 'MISP_API_KEY', None)
        self.verify_ssl = getattr(config, 'MISP_VERIFY_SSL', True)
        
        # Default MISP settings
        self.default_distribution = 1  # This community only
        self.default_threat_level = 3  # Low
        self.default_analysis = 0  # Initial
        
        self.logger = logging.getLogger(__name__)
        
    async def export_threat_to_misp(self, threat: ThreatIndicator) -> Optional[str]:
        """Export a threat indicator to MISP as an event"""
        try:
            if not self.misp_url or not self.api_key:
                self.logger.warning("MISP not configured - skipping export")
                return None
                
            # Only export high-quality Bahrain threats
            if threat.bahrain_score < 60:
                self.logger.debug(f"Threat {threat.indicator} doesn't meet Bahrain relevance threshold for MISP")
                return None
                
            # Create MISP event
            event_data = self._create_event_payload(threat)
            
            headers = {
                'Authorization': self.api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                # Create event
                async with session.post(
                    f"{self.misp_url}/events/add",
                    headers=headers,
                    json=event_data,
                    ssl=self.verify_ssl,
                    timeout=30
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        event_id = result.get('Event', {}).get('id')
                        self.logger.info(f"Threat exported to MISP: Event ID {event_id}")
                        return event_id
                    else:
                        error_text = await response.text()
                        self.logger.error(f"MISP export failed: {response.status} - {error_text}")
                        return None
                        
        except Exception as e:
            self.logger.error(f"Error exporting to MISP: {e}")
            return None
            
    def _create_event_payload(self, threat: ThreatIndicator) -> Dict[str, Any]:
        """Create MISP event payload from threat indicator"""
        # Determine threat level based on scores
        if threat.threat_score >= 85 and threat.bahrain_score >= 80:
            threat_level = 1  # High
        elif threat.threat_score >= 70:
            threat_level = 2  # Medium
        else:
            threat_level = 3  # Low
            
        # Map indicator type to MISP attribute type
        misp_type_map = {
            'ip': 'ip-dst',
            'domain': 'domain',
            'url': 'url',
            'hash': 'md5' if len(threat.indicator) == 32 else 'sha256',
            'email': 'email-src'
        }
        
        misp_type = misp_type_map.get(threat.indicator_type, 'other')
        
        # Build event info
        sector_display = threat.targeted_sector or 'Unknown'
        event_info = f"[Bahrain CTI] {threat.threat_type or 'Threat'} targeting {sector_display}: {threat.indicator}"
        
        # Create tags
        tags = [
            {'name': 'Bahrain', 'colour': '#00FF00', 'exportable': True},
            {'name': f"Sector:{sector_display}", 'colour': '#0000FF', 'exportable': True},
            {'name': f"Source:{threat.source}", 'colour': '#FF0000', 'exportable': True}
        ]
        
        # Add threat type tag if available
        if threat.threat_type:
            tags.append({'name': threat.threat_type, 'colour': '#FFA500', 'exportable': True})
            
        # Add target brands as tags
        if threat.target_brands:
            for brand in threat.target_brands:
                tags.append({'name': f"Brand:{brand}", 'colour': '#800080', 'exportable': True})
        
        event_payload = {
            "Event": {
                "info": event_info,
                "distribution": self.default_distribution,
                "threat_level_id": threat_level,
                "analysis": self.default_analysis,
                "timestamp": int(datetime.utcnow().timestamp()),
                "publish_timestamp": int(datetime.utcnow().timestamp()),
                "org_id": "1",
                "orgc_id": "1",
                "Tag": tags,
                "Attribute": [
                    {
                        "type": misp_type,
                        "category": "Network activity" if threat.indicator_type in ['ip', 'domain', 'url'] else "Payload delivery",
                        "to_ids": True,
                        "distribution": 5,  # Inherit event
                        "value": threat.indicator,
                        "comment": f"Threat Score: {threat.threat_score}/100, Bahrain Relevance: {threat.bahrain_score}/100",
                        "disable_correlation": False,
                        "Tag": [
                            {"name": "Bahrain-Relevance", "colour": "#00FF00"},
                            {"name": f"Score:{threat.threat_score}", "colour": "#FF0000"}
                        ]
                    }
                ],
                "Object": []
            }
        }
        
        # Add additional metadata as attributes if available
        if threat.metadata:
            metadata = threat.metadata if isinstance(threat.metadata, dict) else json.loads(threat.metadata)
            
            # Add malware family if available
            if metadata.get('malware_family'):
                event_payload["Event"]["Attribute"].append({
                    "type": "text",
                    "category": "Attribution",
                    "to_ids": False,
                    "value": f"Malware Family: {metadata['malware_family']}"
                })
                
            # Add threat actor if available
            if metadata.get('threat_actor'):
                event_payload["Event"]["Attribute"].append({
                    "type": "threat-actor",
                    "category": "Attribution",
                    "to_ids": False,
                    "value": metadata['threat_actor']
                })
        
        return event_payload
        
    async def sync_recent_threats(self, hours: int = 24) -> Dict[str, Any]:
        """Sync recent high-priority threats to MISP"""
        try:
            from datetime import timedelta
            
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            with self.db_manager.get_session() as session:
                # Get recent high-quality Bahrain threats
                threats = session.query(ThreatIndicator).filter(
                    ThreatIndicator.first_seen >= cutoff_time,
                    ThreatIndicator.bahrain_score >= 60,
                    ThreatIndicator.threat_score >= 60
                ).all()
                
                exported = 0
                failed = 0
                
                for threat in threats:
                    result = await self.export_threat_to_misp(threat)
                    if result:
                        exported += 1
                    else:
                        failed += 1
                        
                return {
                    'total_threats': len(threats),
                    'exported': exported,
                    'failed': failed,
                    'time_range_hours': hours
                }
                
        except Exception as e:
            self.logger.error(f"Error syncing threats to MISP: {e}")
            return {'error': str(e)}
            
    async def get_misp_stats(self) -> Dict[str, Any]:
        """Get statistics from MISP instance"""
        try:
            if not self.misp_url or not self.api_key:
                return {'configured': False, 'message': 'MISP not configured'}
                
            headers = {'Authorization': self.api_key, 'Accept': 'application/json'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.misp_url}/users/statistics.json",
                    headers=headers,
                    ssl=self.verify_ssl,
                    timeout=10
                ) as response:
                    if response.status == 200:
                        stats = await response.json()
                        return {
                            'configured': True,
                            'stats': stats,
                            'url': self.misp_url
                        }
                    else:
                        return {
                            'configured': True,
                            'error': f"HTTP {response.status}",
                            'url': self.misp_url
                        }
                        
        except Exception as e:
            return {
                'configured': bool(self.misp_url and self.api_key),
                'error': str(e),
                'url': self.misp_url
            }
            
    def get_connection_status(self) -> Dict[str, Any]:
        """Get MISP connection status"""
        return {
            'configured': bool(self.misp_url and self.api_key),
            'url': self.misp_url,
            'ssl_verification': self.verify_ssl,
            'distribution_setting': self.default_distribution,
            'threat_level_default': self.default_threat_level
        }
