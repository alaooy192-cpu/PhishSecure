"""
SIEM Integration for PhishSecure Bahrain CTI
Sends threat data to Security Information and Event Management systems
Supports Splunk, QRadar, Sentinel, and generic webhooks
"""

import asyncio
import aiohttp
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
import json
import hashlib

from database.models import DatabaseManager, ThreatIndicator

class SIEMIntegration:
    """
    SIEM integration for real-time threat sharing with SOC teams
    """
    
    def __init__(self, config):
        self.config = config
        self.db_manager = DatabaseManager()
        
        # SIEM Configuration
        self.webhook_url = getattr(config, 'SIEM_WEBHOOK_URL', None)
        self.api_key = getattr(config, 'SIEM_API_KEY', None)
        
        self.logger = logging.getLogger(__name__)
        
    async def send_to_siem(self, threat: ThreatIndicator, event_type: str = "threat_detected") -> bool:
        """Send threat to SIEM system"""
        try:
            if not self.webhook_url:
                return False
                
            payload = self._format_siem_payload(threat, event_type)
            
            headers = {
                'Content-Type': 'application/json'
            }
            
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    headers=headers,
                    json=payload,
                    timeout=10
                ) as response:
                    if response.status in [200, 201, 202]:
                        self.logger.info(f"Threat sent to SIEM: {threat.indicator}")
                        return True
                    else:
                        self.logger.warning(f"SIEM webhook failed: {response.status}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Error sending to SIEM: {e}")
            return False
            
    def _format_siem_payload(self, threat: ThreatIndicator, event_type: str) -> Dict[str, Any]:
        """Format threat for SIEM consumption (CEF, LEEF, or JSON)"""
        
        # Common Event Format (CEF) style payload
        return {
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "severity": self._calculate_severity(threat.threat_score),
            "source": "PhishSecure_Bahrain_CTI",
            "threat": {
                "indicator": threat.indicator,
                "indicator_type": threat.indicator_type,
                "threat_score": threat.threat_score,
                "bahrain_score": threat.bahrain_score,
                "threat_type": threat.threat_type,
                "sector": threat.targeted_sector,
                "confidence": threat.confidence,
                "first_seen": threat.first_seen.isoformat() if threat.first_seen else None,
                "source_feed": threat.source
            },
            "mitre_attack": self._map_to_mitre(threat.threat_type),
            "ioc_hash": hashlib.sha256(threat.indicator.encode()).hexdigest()[:16],
            "action_recommended": self._get_recommended_action(threat)
        }
        
    def _calculate_severity(self, threat_score: int) -> str:
        """Convert threat score to severity level"""
        if threat_score >= 85:
            return "CRITICAL"
        elif threat_score >= 70:
            return "HIGH"
        elif threat_score >= 50:
            return "MEDIUM"
        else:
            return "LOW"
            
    def _map_to_mitre(self, threat_type: Optional[str]) -> List[str]:
        """Map threat type to MITRE ATT&CK techniques"""
        mitre_map = {
            'phishing': ['T1566.001', 'T1566.002'],  # Spearphishing
            'malware': ['T1204.002', 'T1059'],  # Malicious file, Command scripting
            'credential_harvesting': ['T1056', 'T1111'],  # Input capture
            'typosquatting': ['T1583.001'],  # Acquire domains
            'infrastructure': ['T1584', 'T1583']  # Compromise infrastructure
        }
        return mitre_map.get(threat_type, ['T1595'])  # Default: Active scanning
        
    def _get_recommended_action(self, threat: ThreatIndicator) -> str:
        """Get recommended SOC action based on threat type"""
        if threat.threat_score >= 80:
            return "BLOCK_IMMEDIATE_INVESTIGATE"
        elif threat.threat_score >= 60:
            return "MONITOR_ALERT"
        else:
            return "LOG_FOR_REFERENCE"
            
    async def export_ioc_list(self, format_type: str = "stix") -> Dict[str, Any]:
        """Export IOCs in various formats for SIEM ingestion"""
        try:
            with self.db_manager.get_session() as session:
                # Get active threats
                threats = session.query(ThreatIndicator).filter(
                    ThreatIndicator.status == 'active',
                    ThreatIndicator.threat_score >= 60
                ).all()
                
                if format_type == "stix":
                    return self._export_stix(threats)
                elif format_type == "misp_csv":
                    return self._export_misp_csv(threats)
                elif format_type == "splunk_lookup":
                    return self._export_splunk_lookup(threats)
                elif format_type == "qradar_ref":
                    return self._export_qradar_ref(threats)
                else:
                    return self._export_simple_json(threats)
                    
        except Exception as e:
            self.logger.error(f"Error exporting IOCs: {e}")
            return {'error': str(e)}
            
    def _export_stix(self, threats: List[ThreatIndicator]) -> Dict[str, Any]:
        """Export threats in STIX 2.1 format"""
        indicators = []
        
        for threat in threats:
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{hashlib.sha256(threat.indicator.encode()).hexdigest()[:32]}",
                "created": threat.first_seen.isoformat() if threat.first_seen else datetime.utcnow().isoformat(),
                "modified": threat.last_seen.isoformat() if threat.last_seen else datetime.utcnow().isoformat(),
                "name": f"Bahrain Threat: {threat.indicator}",
                "description": threat.description or f"Threat targeting {threat.targeted_sector}",
                "indicator_types": ["malicious-activity"],
                "pattern": self._create_stix_pattern(threat),
                "pattern_type": "stix",
                "valid_from": threat.first_seen.isoformat() if threat.first_seen else datetime.utcnow().isoformat(),
                "labels": [threat.threat_type or "threat", f"bahrain-{threat.targeted_sector}"],
                "confidence": threat.confidence or "medium",
                "object_marking_refs": ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"]
            }
            indicators.append(indicator)
        
        return {
            "type": "bundle",
            "id": f"bundle--{hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest()[:32]}",
            "spec_version": "2.1",
            "objects": indicators
        }
        
    def _create_stix_pattern(self, threat: ThreatIndicator) -> str:
        """Create STIX pattern from indicator"""
        if threat.indicator_type == 'ip':
            return f"[ipv4-addr:value = '{threat.indicator}']"
        elif threat.indicator_type == 'domain':
            return f"[domain-name:value = '{threat.indicator}']"
        elif threat.indicator_type == 'url':
            return f"[url:value = '{threat.indicator}']"
        elif threat.indicator_type == 'hash':
            if len(threat.indicator) == 32:
                return f"[file:hashes.MD5 = '{threat.indicator}']"
            else:
                return f"[file:hashes.SHA256 = '{threat.indicator}']"
        else:
            return f"[x-custom:value = '{threat.indicator}']"
            
    def _export_simple_json(self, threats: List[ThreatIndicator]) -> Dict[str, Any]:
        """Export simple JSON format for generic SIEMs"""
        return {
            "indicators": [
                {
                    "value": t.indicator,
                    "type": t.indicator_type,
                    "threat_score": t.threat_score,
                    "bahrain_score": t.bahrain_score,
                    "sector": t.targeted_sector,
                    "first_seen": t.first_seen.isoformat() if t.first_seen else None,
                    "source": t.source
                }
                for t in threats
            ],
            "total": len(threats),
            "exported_at": datetime.utcnow().isoformat()
        }
        
    def _export_misp_csv(self, threats: List[ThreatIndicator]) -> str:
        """Export MISP CSV format"""
        lines = ["uuid,event_id,category,type,value,comment,to_ids,date"]
        
        for threat in threats:
            uuid = hashlib.sha256(threat.indicator.encode()).hexdigest()[:32]
            date_str = threat.first_seen.strftime('%Y-%m-%d') if threat.first_seen else datetime.utcnow().strftime('%Y-%m-%d')
            line = f'"{uuid}","1","Network activity","{threat.indicator_type}","{threat.indicator}","{threat.description or "Bahrain threat"}","1","{date_str}"'
            lines.append(line)
            
        return "\n".join(lines)
        
    def _export_splunk_lookup(self, threats: List[ThreatIndicator]) -> str:
        """Export Splunk lookup table format"""
        lines = ["indicator,indicator_type,threat_score,bahrain_score,sector,source,action"]
        
        for threat in threats:
            action = "block" if threat.threat_score >= 75 else "monitor"
            line = f"{threat.indicator},{threat.indicator_type},{threat.threat_score},{threat.bahrain_score},{threat.targeted_sector},{threat.source},{action}"
            lines.append(line)
            
        return "\n".join(lines)
        
    def _export_qradar_ref(self, threats: List[ThreatIndicator]) -> List[Dict[str, Any]]:
        """Export QRadar reference set format"""
        return [
            {
                "value": t.indicator,
                "type": t.indicator_type,
                "threat_level": self._calculate_severity(t.threat_score),
                "bahrain_relevance": t.bahrain_score,
                "first_seen": t.first_seen.isoformat() if t.first_seen else None,
                "source": "PhishSecure_Bahrain_CTI"
            }
            for t in threats
        ]
