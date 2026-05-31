"""
Continuous Threat Monitoring Service for Bahrain
Automatically collects, analyzes, and alerts on threats targeting Bahrain organizations
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import threading
import requests
from sqlalchemy.orm import sessionmaker
from sqlalchemy import desc

from database.models import DatabaseManager, ThreatIndicator, BahrainBrand, AnalysisHistory
from services.threat_collector import ThreatCollector
from services.bahrain_scorer import BahrainRelevanceScorer
from services.threat_analyzer import ThreatAnalyzer

class ContinuousThreatMonitor:
    """
    Continuous monitoring service that:
    1. Automatically collects threats from multiple sources
    2. Analyzes threats for Bahrain relevance in real-time
    3. Generates alerts for high-priority threats
    4. Maintains threat intelligence database
    """
    
    def __init__(self, config):
        self.config = config
        self.db_manager = DatabaseManager(getattr(config, 'DATABASE_PATH', 'cti_database.db'))
        self.threat_collector = ThreatCollector(getattr(config, 'DATABASE_PATH', 'cti_database.db'))
        self.bahrain_scorer = BahrainRelevanceScorer()
        self.threat_analyzer = ThreatAnalyzer()
        
        # Monitoring state
        self.is_running = False
        self.last_collection = None
        self.collection_count = 0
        self.alert_count = 0
        
        # Threading
        self.monitor_thread = None
        self.stop_event = threading.Event()
        
        # Logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Alert thresholds
        self.CRITICAL_THREAT_THRESHOLD = 80
        self.HIGH_BAHRAIN_RELEVANCE_THRESHOLD = 70
        self.COLLECTION_INTERVAL_MINUTES = 15  # Check every 15 minutes
        
    def start_monitoring(self):
        """Start continuous threat monitoring"""
        if self.is_running:
            self.logger.warning("Monitor already running")
            return
            
        self.logger.info("[START] Starting Continuous Threat Monitor for Bahrain")
        self.is_running = True
        self.stop_event.clear()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info(f"[OK] Monitor started - checking every {self.COLLECTION_INTERVAL_MINUTES} minutes")
        
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        if not self.is_running:
            return
            
        self.logger.info("[STOP] Stopping Continuous Threat Monitor")
        self.is_running = False
        self.stop_event.set()
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=30)
            
        self.logger.info("[OK] Monitor stopped")
        
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while not self.stop_event.is_set():
            try:
                start_time = time.time()
                
                # Collect new threats
                self._collect_threats()
                
                # Analyze recent threats for Bahrain relevance
                self._analyze_recent_threats()
                
                # Generate alerts for critical threats
                self._check_for_alerts()
                
                # Update monitoring stats
                self._update_monitoring_stats()
                
                elapsed = time.time() - start_time
                self.logger.info(f"[STAT] Monitoring cycle completed in {elapsed:.2f}s")
                
                # Wait for next cycle
                self.stop_event.wait(self.COLLECTION_INTERVAL_MINUTES * 60)
                
            except Exception as e:
                self.logger.error(f"[ERR] Error in monitoring loop: {e}")
                # Wait before retrying
                self.stop_event.wait(60)
                
    def _collect_threats(self):
        """Collect threats from all configured sources"""
        try:
            self.logger.info("[SEARCH] Collecting new threats...")
            
            # Collect from URLhaus
            urlhaus_count = self._collect_from_urlhaus()
            
            # Collect from other sources (placeholder for future sources)
            # virustotal_count = self._collect_from_virustotal()
            # custom_feeds_count = self._collect_from_custom_feeds()
            
            total_collected = urlhaus_count
            self.collection_count += total_collected
            self.last_collection = datetime.utcnow()
            
            if total_collected > 0:
                self.logger.info(f"[OK] Collected {total_collected} new threats")
            else:
                self.logger.info("[INFO] No new threats found")
                
        except Exception as e:
            self.logger.error(f"[ERR] Error collecting threats: {e}")
            
    def _collect_from_urlhaus(self) -> int:
        """Collect recent threats from URLhaus"""
        try:
            # Get recent URLhaus data (last 24 hours)
            url = "https://urlhaus-api.abuse.ch/v1/payloads/recent/"
            response = requests.get(url, timeout=30)
            
            if response.status_code != 200:
                self.logger.warning(f"URLhaus API returned {response.status_code}")
                return 0
                
            data = response.json()
            if data.get('query_status') != 'ok':
                return 0
                
            payloads = data.get('payloads', [])
            new_threats = 0
            
            with self.db_manager.get_session() as session:
                for payload in payloads[:50]:  # Limit to 50 most recent
                    try:
                        # Extract threat information
                        url_full = payload.get('url_full', '')
                        if not url_full:
                            continue
                            
                        # Check if we already have this threat
                        existing = session.query(ThreatIndicator).filter_by(
                            indicator_value=url_full
                        ).first()
                        
                        if existing:
                            continue
                            
                        # Create new threat indicator
                        threat = ThreatIndicator(
                            indicator_value=url_full,
                            indicator_type='url',
                            source='urlhaus',
                            first_seen=datetime.utcnow(),
                            last_updated=datetime.utcnow(),
                            threat_score=0,  # Will be calculated
                            bahrain_score=0,  # Will be calculated
                            targeted_sector='unknown',
                            confidence_level='medium',
                            status='active',
                            notes=json.dumps({
                                'malware_family': payload.get('malware', 'unknown'),
                                'file_type': payload.get('file_type', ''),
                                'signature': payload.get('signature', ''),
                                'urlhaus_id': payload.get('id', ''),
                                'tags': payload.get('tags', [])
                            })
                        )
                        
                        session.add(threat)
                        new_threats += 1
                        
                    except Exception as e:
                        self.logger.warning(f"Error processing URLhaus payload: {e}")
                        continue
                        
                session.commit()
                
            return new_threats
            
        except Exception as e:
            self.logger.error(f"Error collecting from URLhaus: {e}")
            return 0
            
    def _analyze_recent_threats(self):
        """Analyze recent threats for Bahrain relevance"""
        try:
            self.logger.info("[ANALYZE] Analyzing recent threats for Bahrain relevance...")
            
            # Get unanalyzed threats from last 24 hours
            with self.db_manager.get_session() as session:
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                
                unanalyzed_threats = session.query(ThreatIndicator).filter(
                    ThreatIndicator.first_seen >= cutoff_time,
                    ThreatIndicator.threat_score == 0  # Not yet analyzed
                ).limit(100).all()
                
                analyzed_count = 0
                bahrain_relevant_count = 0
                
                for threat in unanalyzed_threats:
                    try:
                        # Analyze threat level
                        threat_analysis = self.threat_analyzer.analyze_indicator(
                            threat.indicator, threat.indicator_type
                        )
                        
                        # Calculate Bahrain relevance
                        bahrain_analysis = self.bahrain_scorer.calculate_relevance_score(
                            threat.indicator, threat.indicator_type
                        )
                        
                        # Update threat with analysis results
                        threat.threat_score = threat_analysis.get('threat_score', 0)
                        threat.bahrain_score = bahrain_analysis.get('bahrain_score', 0)
                        threat.sector = bahrain_analysis.get('target_sector', 'unknown')
                        threat.confidence = threat_analysis.get('confidence', 'medium')
                        
                        # Update metadata with analysis details
                        if threat.metadata is None:
                            threat.metadata = {}
                        threat.metadata.update({
                            'threat_analysis': threat_analysis,
                            'bahrain_analysis': bahrain_analysis,
                            'analyzed_at': datetime.utcnow().isoformat()
                        })
                        
                        analyzed_count += 1
                        
                        if threat.bahrain_score >= self.HIGH_BAHRAIN_RELEVANCE_THRESHOLD:
                            bahrain_relevant_count += 1
                            
                    except Exception as e:
                        self.logger.warning(f"Error analyzing threat {threat.id}: {e}")
                        continue
                        
                session.commit()
                
                if analyzed_count > 0:
                    self.logger.info(f"[OK] Analyzed {analyzed_count} threats, {bahrain_relevant_count} Bahrain-relevant")
                    
        except Exception as e:
            self.logger.error(f"Error analyzing recent threats: {e}")
            
    def _check_for_alerts(self):
        """Check for critical threats and generate alerts"""
        try:
            # Get critical threats from last hour
            with self.db_manager.get_session() as session:
                cutoff_time = datetime.utcnow() - timedelta(hours=1)
                
                critical_threats = session.query(ThreatIndicator).filter(
                    ThreatIndicator.last_updated >= cutoff_time,
                    ThreatIndicator.threat_score >= self.CRITICAL_THREAT_THRESHOLD,
                    ThreatIndicator.bahrain_score >= self.HIGH_BAHRAIN_RELEVANCE_THRESHOLD
                ).all()
                
                for threat in critical_threats:
                    self._generate_alert(threat)
                    
        except Exception as e:
            self.logger.error(f"Error checking for alerts: {e}")
            
    def _generate_alert(self, threat: ThreatIndicator):
        """Generate alert for critical threat"""
        try:
            alert_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'threat_id': threat.id,
                'indicator': threat.indicator,
                'type': threat.indicator_type,
                'threat_score': threat.threat_score,
                'bahrain_score': threat.bahrain_score,
                'sector': threat.sector,
                'source': threat.source,
                'severity': self._get_severity_level(threat.threat_score, threat.bahrain_score)
            }
            
            # Log critical alert
            self.logger.critical(
                f"[ALERT] CRITICAL THREAT ALERT: {threat.indicator} "
                f"(Threat: {threat.threat_score}, Bahrain: {threat.bahrain_score}, "
                f"Sector: {threat.sector})"
            )
            
            # Store alert in database
            self._store_alert(alert_data)
            
            # TODO: Send notifications (email, Slack, etc.)
            # self._send_notification(alert_data)
            
            self.alert_count += 1
            
        except Exception as e:
            self.logger.error(f"Error generating alert: {e}")
            
    def _get_severity_level(self, threat_score: int, bahrain_score: int) -> str:
        """Determine severity level based on scores"""
        if threat_score >= 90 and bahrain_score >= 80:
            return 'CRITICAL'
        elif threat_score >= 80 and bahrain_score >= 70:
            return 'HIGH'
        elif threat_score >= 60 and bahrain_score >= 50:
            return 'MEDIUM'
        else:
            return 'LOW'
            
    def _store_alert(self, alert_data: Dict[str, Any]):
        """Store alert in database"""
        try:
            with self.db_manager.get_session() as session:
                # Store in analysis history for now
                # TODO: Create dedicated alerts table
                analysis = AnalysisHistory(
                    indicator=alert_data['indicator'],
                    indicator_type=alert_data['type'],
                    analysis_type='alert',
                    timestamp=datetime.utcnow(),
                    results={
                        'alert_type': 'critical_threat',
                        'severity': alert_data['severity'],
                        'threat_score': alert_data['threat_score'],
                        'bahrain_score': alert_data['bahrain_score'],
                        'sector': alert_data['sector']
                    }
                )
                session.add(analysis)
                session.commit()
                
        except Exception as e:
            self.logger.error(f"Error storing alert: {e}")
            
    def _update_monitoring_stats(self):
        """Update monitoring statistics"""
        try:
            with self.db_manager.get_session() as session:
                # Count total threats
                total_threats = session.query(ThreatIndicator).count()
                
                # Count recent threats (last 24 hours)
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                recent_threats = session.query(ThreatIndicator).filter(
                    ThreatIndicator.first_seen >= cutoff_time
                ).count()
                
                # Count Bahrain-relevant threats
                bahrain_threats = session.query(ThreatIndicator).filter(
                    ThreatIndicator.bahrain_score >= self.HIGH_BAHRAIN_RELEVANCE_THRESHOLD
                ).count()
                
                self.logger.info(
                    f"[STAT] Stats: {total_threats} total threats, "
                    f"{recent_threats} in last 24h, "
                    f"{bahrain_threats} Bahrain-relevant, "
                    f"{self.alert_count} alerts generated"
                )
                
        except Exception as e:
            self.logger.error(f"Error updating stats: {e}")
            
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        return {
            'is_running': self.is_running,
            'last_collection': self.last_collection.isoformat() if self.last_collection else None,
            'collection_count': self.collection_count,
            'alert_count': self.alert_count,
            'collection_interval_minutes': self.COLLECTION_INTERVAL_MINUTES,
            'critical_threshold': self.CRITICAL_THREAT_THRESHOLD,
            'bahrain_threshold': self.HIGH_BAHRAIN_RELEVANCE_THRESHOLD
        }
        
    def get_recent_alerts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        try:
            with self.db_manager.get_session() as session:
                cutoff_time = datetime.utcnow() - timedelta(hours=hours)
                
                alerts = session.query(AnalysisHistory).filter(
                    AnalysisHistory.analysis_type == 'alert',
                    AnalysisHistory.timestamp >= cutoff_time
                ).order_by(desc(AnalysisHistory.timestamp)).limit(50).all()
                
                return [
                    {
                        'id': alert.id,
                        'timestamp': alert.timestamp.isoformat(),
                        'indicator': alert.indicator,
                        'type': alert.indicator_type,
                        'severity': alert.results.get('severity', 'UNKNOWN'),
                        'threat_score': alert.results.get('threat_score', 0),
                        'bahrain_score': alert.results.get('bahrain_score', 0),
                        'sector': alert.results.get('sector', 'unknown')
                    }
                    for alert in alerts
                ]
                
        except Exception as e:
            self.logger.error(f"Error getting recent alerts: {e}")
            return []
