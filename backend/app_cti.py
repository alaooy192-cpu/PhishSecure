"""
PhishSecure Bahrain CTI Platform - Main Flask Application
Cyber Threat Intelligence platform focused on phishing threats relevant to Bahrain
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import logging
from datetime import datetime, timedelta
import json

# Import CTI services
from services.threat_collector import ThreatCollector, ThreatCollectionScheduler
from services.threat_analyzer import ThreatAnalyzer
from services.bahrain_scorer import BahrainRelevanceScorer
from services.continuous_monitor import ContinuousThreatMonitor
from services.multi_intel_collector import MultiIntelCollector
from services.alert_manager import RealTimeAlertManager
from services.misp_integration import MISPIntegration
from services.siem_integration import SIEMIntegration
from services.takedown_manager import TakedownManager
from database.models import DatabaseManager, ThreatIndicator, BahrainBrand, DashboardStats
from config import Config

# Initialize Flask app
app = Flask(__name__)
CORS(app)
app.config.from_object(Config)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize services
db_manager = DatabaseManager(Config.DATABASE_PATH)
threat_collector = ThreatCollector(Config.DATABASE_PATH)
threat_analyzer = ThreatAnalyzer()
bahrain_scorer = BahrainRelevanceScorer()
continuous_monitor = ContinuousThreatMonitor(Config)
multi_intel_collector = MultiIntelCollector(Config)

# Initialize real-world integration services
alert_manager = RealTimeAlertManager(Config)
misp_integration = MISPIntegration(Config)
siem_integration = SIEMIntegration(Config)
takedown_manager = TakedownManager(Config)

# Initialize database on startup
try:
    db_manager.create_tables()
    db_manager.init_default_data()
    logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Database initialization error: {e}")



@app.route("/")
def home():
    """API status and information"""
    config_warnings = Config.validate_config()
    intel_status = multi_intel_collector.get_source_status() if hasattr(multi_intel_collector, 'get_source_status') else {}
    
    return jsonify({
        "service": "PhishSecure Bahrain CTI Platform",
        "version": "1.0.0",
        "status": "operational",
        "description": "Cyber Threat Intelligence platform for Bahrain-focused phishing threats",
        "endpoints": {
            "dashboard": "/api/dashboard/stats",
            "indicators": "/api/indicators/list",
            "analysis": "/api/analysis/domain",
            "collection": "/api/collection/run",
            "multi_intel": "/api/intelligence/collect"
        },
        "configuration": {
            "demo_mode": Config.USE_DEMO_DATA,
            "warnings": config_warnings
        },
        "intelligence_sources": intel_status
    })

# ==================== DASHBOARD ENDPOINTS ====================

@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    """Get high-level dashboard statistics"""
    try:
        days = request.args.get("days", 7, type=int)
        session = db_manager.get_session()
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get basic counts
        total_indicators = session.query(ThreatIndicator).count()
        
        high_threat_count = session.query(ThreatIndicator).filter(
            ThreatIndicator.threat_score >= Config.HIGH_THREAT_THRESHOLD
        ).count()
        
        bahrain_relevant_count = session.query(ThreatIndicator).filter(
            ThreatIndicator.bahrain_score >= Config.HIGH_BAHRAIN_RELEVANCE_THRESHOLD
        ).count()
        
        new_indicators_today = session.query(ThreatIndicator).filter(
            ThreatIndicator.first_seen >= start_date
        ).count()
        
        # Get sector breakdown
        sector_stats = {}
        indicators = session.query(ThreatIndicator).filter(
            ThreatIndicator.targeted_sector.isnot(None)
        ).all()
        
        for indicator in indicators:
            sector = indicator.targeted_sector or 'general'
            sector_stats[sector] = sector_stats.get(sector, 0) + 1
        
        # Get recent high-priority threats
        recent_threats = session.query(ThreatIndicator).filter(
            ThreatIndicator.threat_score >= 70,
            ThreatIndicator.first_seen >= start_date
        ).order_by(ThreatIndicator.first_seen.desc()).limit(10).all()
        
        recent_threats_data = []
        for threat in recent_threats:
            recent_threats_data.append({
                'id': threat.id,
                'indicator': threat.indicator_value,
                'type': threat.indicator_type,
                'threat_score': threat.threat_score,
                'bahrain_score': threat.bahrain_score,
                'sector': threat.targeted_sector,
                'first_seen': threat.first_seen.isoformat() if threat.first_seen else None
            })
        
        session.close()
        
        return jsonify({
            'period_days': days,
            'total_indicators': total_indicators,
            'high_threat_count': high_threat_count,
            'bahrain_relevant_count': bahrain_relevant_count,
            'new_indicators_today': new_indicators_today,
            'sector_breakdown': sector_stats,
            'recent_high_priority': recent_threats_data,
            'updated_at': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/dashboard/trends", methods=["GET"])
def get_threat_trends():
    """Get threat trends over time"""
    try:
        days = request.args.get("days", 7, type=int)
        session = db_manager.get_session()
        
        # Get daily threat counts for the period
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        daily_stats = []
        current_date = start_date
        
        while current_date <= end_date:
            next_date = current_date + timedelta(days=1)
            
            daily_count = session.query(ThreatIndicator).filter(
                ThreatIndicator.first_seen >= current_date,
                ThreatIndicator.first_seen < next_date
            ).count()
            
            high_threat_count = session.query(ThreatIndicator).filter(
                ThreatIndicator.first_seen >= current_date,
                ThreatIndicator.first_seen < next_date,
                ThreatIndicator.threat_score >= Config.HIGH_THREAT_THRESHOLD
            ).count()
            
            daily_stats.append({
                'date': current_date.strftime('%Y-%m-%d'),
                'total_threats': daily_count,
                'high_priority': high_threat_count
            })
            
            current_date = next_date
        
        session.close()
        
        return jsonify({
            'period_days': days,
            'daily_trends': daily_stats
        })
        
    except Exception as e:
        logger.error(f"Trends error: {e}")
        return jsonify({"error": str(e)}), 500

# ==================== THREAT INDICATORS ENDPOINTS ====================

@app.route("/api/indicators/list", methods=["GET"])
def list_indicators():
    """List threat indicators with filtering and pagination"""
    try:
        # Query parameters
        limit = request.args.get("limit", 50, type=int)
        offset = request.args.get("offset", 0, type=int)
        indicator_type = request.args.get("type")  # domain, url, ip
        min_threat_score = request.args.get("min_threat_score", type=int)
        min_bahrain_score = request.args.get("min_bahrain_score", type=int)
        sector = request.args.get("sector")
        
        session = db_manager.get_session()
        query = session.query(ThreatIndicator)
        
        # Apply filters
        if indicator_type:
            query = query.filter(ThreatIndicator.indicator_type == indicator_type)
        
        if min_threat_score is not None:
            query = query.filter(ThreatIndicator.threat_score >= min_threat_score)
        
        if min_bahrain_score is not None:
            query = query.filter(ThreatIndicator.bahrain_score >= min_bahrain_score)
        
        if sector:
            query = query.filter(ThreatIndicator.targeted_sector == sector)
        
        # Get total count for pagination
        total_count = query.count()
        
        # Apply pagination and ordering
        indicators = query.order_by(ThreatIndicator.first_seen.desc()).offset(offset).limit(limit).all()
        
        # Format response
        indicators_data = []
        for indicator in indicators:
            indicators_data.append({
                'id': indicator.id,
                'indicator_type': indicator.indicator_type,
                'indicator_value': indicator.indicator_value,
                'threat_score': indicator.threat_score,
                'bahrain_score': indicator.bahrain_score,
                'confidence_level': indicator.confidence_level,
                'targeted_sector': indicator.targeted_sector,
                'source': indicator.source,
                'first_seen': indicator.first_seen.isoformat() if indicator.first_seen else None,
                'last_updated': indicator.last_updated.isoformat() if indicator.last_updated else None,
                'tags': json.loads(indicator.tags) if indicator.tags else [],
                'status': indicator.status
            })
        
        session.close()
        
        return jsonify({
            'indicators': indicators_data,
            'pagination': {
                'total': total_count,
                'limit': limit,
                'offset': offset,
                'has_more': offset + limit < total_count
            }
        })
        
    except Exception as e:
        logger.error(f"List indicators error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/indicators/<int:indicator_id>", methods=["GET"])
def get_indicator_details(indicator_id):
    """Get detailed information about a specific indicator"""
    try:
        session = db_manager.get_session()
        indicator = session.query(ThreatIndicator).filter(ThreatIndicator.id == indicator_id).first()
        
        if not indicator:
            return jsonify({"error": "Indicator not found"}), 404
        
        # Get analysis history
        history = []
        for analysis in indicator.analysis_history:
            history.append({
                'analysis_date': analysis.analysis_date.isoformat() if analysis.analysis_date else None,
                'analysis_type': analysis.analysis_type,
                'threat_score_change': f"{analysis.previous_threat_score} → {analysis.new_threat_score}",
                'bahrain_score_change': f"{analysis.previous_bahrain_score} → {analysis.new_bahrain_score}",
                'analyst_id': analysis.analyst_id
            })
        
        indicator_data = {
            'id': indicator.id,
            'indicator_type': indicator.indicator_type,
            'indicator_value': indicator.indicator_value,
            'threat_score': indicator.threat_score,
            'bahrain_score': indicator.bahrain_score,
            'confidence_level': indicator.confidence_level,
            'targeted_sector': indicator.targeted_sector,
            'source': indicator.source,
            'first_seen': indicator.first_seen.isoformat() if indicator.first_seen else None,
            'last_updated': indicator.last_updated.isoformat() if indicator.last_updated else None,
            'domain_age_days': indicator.domain_age_days,
            'tld': indicator.tld,
            'subdomain_count': indicator.subdomain_count,
            'virustotal_detections': indicator.virustotal_detections,
            'virustotal_total': indicator.virustotal_total,
            'geolocation_country': indicator.geolocation_country,
            'tags': json.loads(indicator.tags) if indicator.tags else [],
            'bahrain_keywords': json.loads(indicator.bahrain_keywords) if indicator.bahrain_keywords else [],
            'suspicious_patterns': json.loads(indicator.suspicious_patterns) if indicator.suspicious_patterns else [],
            'notes': indicator.notes,
            'status': indicator.status,
            'analyst_reviewed': indicator.analyst_reviewed,
            'analysis_history': history
        }
        
        session.close()
        return jsonify(indicator_data)
        
    except Exception as e:
        logger.error(f"Get indicator details error: {e}")
        return jsonify({"error": str(e)}), 500

# ==================== ANALYSIS ENDPOINTS ====================

@app.route("/api/analysis/domain", methods=["POST"])
def analyze_domain():
    """Analyze a domain for phishing indicators and Bahrain relevance"""
    try:
        data = request.get_json()
        domain = data.get("domain")
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
        # Run threat analysis
        threat_analysis = threat_analyzer.analyze_indicator(domain, 'domain')
        
        # Run Bahrain relevance scoring
        bahrain_analysis = bahrain_scorer.calculate_bahrain_score(domain, 'domain')
        
        # Combine results
        combined_analysis = {
            'domain': domain,
            'analysis_timestamp': datetime.now().isoformat(),
            'threat_analysis': threat_analysis,
            'bahrain_relevance': bahrain_analysis,
            'overall_assessment': {
                'threat_level': _get_threat_level(threat_analysis['threat_score']),
                'bahrain_relevance_level': _get_relevance_level(bahrain_analysis['bahrain_score']),
                'recommended_action': _get_recommended_action(
                    threat_analysis['threat_score'], 
                    bahrain_analysis['bahrain_score']
                )
            }
        }
        
        return jsonify(combined_analysis)
        
    except Exception as e:
        logger.error(f"Domain analysis error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/analysis/bulk", methods=["POST"])
def analyze_bulk():
    """Analyze multiple indicators in bulk"""
    try:
        data = request.get_json()
        indicators = data.get("indicators", [])
        
        if not indicators or len(indicators) > 10:
            return jsonify({"error": "Provide 1-10 indicators for bulk analysis"}), 400
        
        results = []
        
        for indicator_data in indicators:
            indicator = indicator_data.get("value")
            indicator_type = indicator_data.get("type", "domain")
            
            if not indicator:
                continue
            
            try:
                # Run analyses
                threat_analysis = threat_analyzer.analyze_indicator(indicator, indicator_type)
                bahrain_analysis = bahrain_scorer.calculate_bahrain_score(indicator, indicator_type)
                
                result = {
                    'indicator': indicator,
                    'type': indicator_type,
                    'threat_score': threat_analysis['threat_score'],
                    'bahrain_score': bahrain_analysis['bahrain_score'],
                    'threat_level': _get_threat_level(threat_analysis['threat_score']),
                    'bahrain_relevance_level': _get_relevance_level(bahrain_analysis['bahrain_score']),
                    'primary_sector': bahrain_analysis.get('primary_sector', 'general')
                }
                
                results.append(result)
                
            except Exception as e:
                logger.error(f"Error analyzing {indicator}: {e}")
                results.append({
                    'indicator': indicator,
                    'type': indicator_type,
                    'error': str(e)
                })
        
        return jsonify({
            'bulk_analysis_results': results,
            'analysis_timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Bulk analysis error: {e}")
        return jsonify({"error": str(e)}), 500

# ==================== COLLECTION ENDPOINTS ====================

@app.route("/api/collection/run", methods=["POST"])
def run_collection():
    """Manually trigger threat intelligence collection"""
    try:
        data = request.get_json() or {}
        use_demo = data.get("use_demo", Config.USE_DEMO_DATA)
        
        # Run collection cycle
        result = threat_collector.run_collection_cycle(use_demo=use_demo)
        
        # If new indicators were collected, analyze them
        if result.get('new_indicators', 0) > 0:
            _analyze_new_indicators()
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Collection error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/collection/status", methods=["GET"])
def get_collection_status():
    """Get status of threat intelligence collection"""
    try:
        session = db_manager.get_session()
        
        # Get latest collection stats
        latest_indicators = session.query(ThreatIndicator).order_by(
            ThreatIndicator.first_seen.desc()
        ).limit(5).all()
        
        last_collection_time = None
        if latest_indicators:
            last_collection_time = latest_indicators[0].first_seen.isoformat()
        
        status = {
            'last_collection': last_collection_time,
            'total_indicators': session.query(ThreatIndicator).count(),
            'collection_sources': ['urlhaus', 'demo'] if Config.USE_DEMO_DATA else ['urlhaus'],
            'next_scheduled_collection': 'Manual trigger only',
            'demo_mode': Config.USE_DEMO_DATA
        }
        
        session.close()
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Collection status error: {e}")
        return jsonify({"error": str(e)}), 500

# ==================== HELPER FUNCTIONS ====================

def _analyze_new_indicators():
    """Analyze newly collected indicators for Bahrain relevance"""
    try:
        session = db_manager.get_session()
        
        # Get indicators that haven't been analyzed for Bahrain relevance
        unanalyzed = session.query(ThreatIndicator).filter(
            ThreatIndicator.bahrain_score == 0
        ).limit(50).all()
        
        for indicator in unanalyzed:
            try:
                # Run Bahrain relevance analysis
                bahrain_analysis = bahrain_scorer.calculate_bahrain_score(
                    indicator.indicator_value, 
                    indicator.indicator_type
                )
                
                # Update indicator with Bahrain analysis
                indicator.bahrain_score = bahrain_analysis['bahrain_score']
                indicator.targeted_sector = bahrain_analysis.get('primary_sector', 'general')
                indicator.bahrain_keywords = json.dumps(bahrain_analysis.get('matched_keywords', []))
                indicator.last_updated = datetime.now()
                
            except Exception as e:
                logger.error(f"Error analyzing indicator {indicator.id}: {e}")
                continue
        
        session.commit()
        session.close()
        
    except Exception as e:
        logger.error(f"Error analyzing new indicators: {e}")

def _get_threat_level(score):
    """Convert threat score to threat level"""
    if score >= 80:
        return 'critical'
    elif score >= 60:
        return 'high'
    elif score >= 40:
        return 'medium'
    else:
        return 'low'

def _get_relevance_level(score):
    """Convert Bahrain relevance score to relevance level"""
    if score >= 70:
        return 'high'
    elif score >= 40:
        return 'medium'
    else:
        return 'low'

def _get_recommended_action(threat_score, bahrain_score):
    """Get recommended action based on scores"""
    if threat_score >= 70 and bahrain_score >= 60:
        return 'immediate_block'
    elif threat_score >= 60 or bahrain_score >= 70:
        return 'monitor_closely'
    elif threat_score >= 40 or bahrain_score >= 40:
        return 'investigate'
    else:
        return 'low_priority'

# ==================== CONTINUOUS MONITORING ENDPOINTS ====================

@app.route("/api/monitoring/start", methods=["POST"])
def start_monitoring():
    """Start continuous threat monitoring"""
    try:
        continuous_monitor.start_monitoring()
        return jsonify({
            "status": "success",
            "message": "Continuous threat monitoring started",
            "monitoring_status": continuous_monitor.get_monitoring_status()
        })
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/monitoring/stop", methods=["POST"])
def stop_monitoring():
    """Stop continuous threat monitoring"""
    try:
        continuous_monitor.stop_monitoring()
        return jsonify({
            "status": "success",
            "message": "Continuous threat monitoring stopped"
        })
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/monitoring/status", methods=["GET"])
def get_monitoring_status():
    """Get current monitoring status"""
    try:
        status = continuous_monitor.get_monitoring_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting monitoring status: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/monitoring/alerts", methods=["GET"])
def get_recent_alerts():
    """Get recent threat alerts"""
    try:
        hours = request.args.get("hours", 24, type=int)
        alerts = continuous_monitor.get_recent_alerts(hours)
        return jsonify({
            "alerts": alerts,
            "count": len(alerts),
            "period_hours": hours
        })
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/monitoring/live-stats", methods=["GET"])
def get_live_monitoring_stats():
    """Get live monitoring statistics"""
    try:
        session = db_manager.get_session()
        
        # Get real-time stats
        total_threats = session.query(ThreatIndicator).count()
        
        # Threats in last hour
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent_threats = session.query(ThreatIndicator).filter(
            ThreatIndicator.first_seen >= one_hour_ago
        ).count()
        
        # Critical Bahrain threats
        critical_bahrain = session.query(ThreatIndicator).filter(
            ThreatIndicator.threat_score >= 80,
            ThreatIndicator.bahrain_score >= 70
        ).count()
        
        # Active monitoring status
        monitoring_status = continuous_monitor.get_monitoring_status()
        
        session.close()
        
        return jsonify({
            "live_stats": {
                "total_threats": total_threats,
                "recent_threats_1h": recent_threats,
                "critical_bahrain_threats": critical_bahrain,
                "monitoring_active": monitoring_status["is_running"],
                "last_collection": monitoring_status["last_collection"],
                "alert_count": monitoring_status["alert_count"]
            },
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting live stats: {e}")
        return jsonify({"error": str(e)}), 500

# ==================== MULTI-SOURCE INTELLIGENCE ENDPOINTS ====================

@app.route("/api/intelligence/collect", methods=["POST"])
def collect_multi_source_intelligence():
    """Trigger collection from all configured threat intelligence sources"""
    try:
        import asyncio
        
        logger.info("[NET] Starting multi-source intelligence collection...")
        
        # Run the async collection
        results = asyncio.run(multi_intel_collector.collect_all_sources())
        
        return jsonify({
            "status": "success",
            "message": "Multi-source intelligence collection completed",
            "results": results,
            "timestamp": datetime.utcnow().isoformat(),
            "sources_active": {
                "urlhaus": True,
                "phishtank": True,
                "otx": bool(Config.OTX_API_KEY),
                "virustotal": bool(Config.VIRUSTOTAL_API_KEY),
                "abuseipdb": bool(Config.ABUSEIPDB_API_KEY),
                "greynoise": bool(Config.GREYNOISE_API_KEY)
            }
        })
        
    except Exception as e:
        logger.error(f"Error in multi-source collection: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/api/intelligence/status", methods=["GET"])
def get_intelligence_source_status():
    """Get status of all threat intelligence sources"""
    try:
        status = multi_intel_collector.get_source_status()
        return jsonify({
            "status": "success",
            "sources": status,
            "api_keys_configured": {
                "virustotal": bool(Config.VIRUSTOTAL_API_KEY),
                "otx": bool(Config.OTX_API_KEY),
                "abuseipdb": bool(Config.ABUSEIPDB_API_KEY),
                "greynoise": bool(Config.GREYNOISE_API_KEY)
            },
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting intelligence status: {e}")
        return jsonify({"error": str(e)}), 500

# ==================== REAL-WORLD ACTION ENDPOINTS ====================

@app.route("/api/alerts/test", methods=["POST"])
def test_alert_system():
    """Test the real-time alerting system"""
    try:
        import asyncio
        
        # Create a test threat
        test_threat = ThreatIndicator(
            indicator="test-phishing-bahrain.com",
            indicator_type="domain",
            threat_type="phishing",
            threat_score=85,
            bahrain_score=80,
            targeted_sector="banking",
            source="test",
            description="Test alert for NBB phishing campaign"
        )
        
        # Send test alert
        result = asyncio.run(alert_manager.check_and_alert(test_threat))
        
        return jsonify({
            "status": "success",
            "alert_sent": result,
            "channels": alert_manager.get_alert_stats(),
            "message": "Test alert sent to configured channels"
        })
        
    except Exception as e:
        logger.error(f"Error testing alerts: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/alerts/status", methods=["GET"])
def get_alert_status():
    """Get alerting system status"""
    try:
        return jsonify({
            "status": "success",
            "alert_config": alert_manager.get_alert_stats()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/iocs/export", methods=["GET"])
def export_iocs():
    """Export IOCs in various formats for SIEM ingestion"""
    try:
        import asyncio
        
        format_type = request.args.get("format", "stix")
        
        result = asyncio.run(siem_integration.export_ioc_list(format_type))
        
        if format_type == "misp_csv":
            return result, 200, {'Content-Type': 'text/csv'}
        elif format_type == "splunk_lookup":
            return result, 200, {'Content-Type': 'text/plain'}
        else:
            return jsonify(result)
            
    except Exception as e:
        logger.error(f"Error exporting IOCs: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/misp/status", methods=["GET"])
def get_misp_status():
    """Get MISP integration status"""
    try:
        import asyncio
        
        status = misp_integration.get_connection_status()
        stats = asyncio.run(misp_integration.get_misp_stats())
        
        return jsonify({
            "status": "success",
            "connection": status,
            "misp_stats": stats
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/takedown/<int:threat_id>", methods=["POST"])
def initiate_takedown(threat_id):
    """Initiate takedown process for a threat"""
    try:
        import asyncio
        
        session = db_manager.get_session()
        threat = session.query(ThreatIndicator).filter_by(id=threat_id).first()
        
        if not threat:
            return jsonify({"error": "Threat not found"}), 404
            
        result = asyncio.run(takedown_manager.initiate_takedown(threat))
        
        return jsonify({
            "status": "success",
            "takedown_result": result,
            "message": f"Takedown initiated for {threat.indicator}"
        })
        
    except Exception as e:
        logger.error(f"Error initiating takedown: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/takedown/batch", methods=["POST"])
def batch_takedown():
    """Initiate batch takedown for high-priority threats"""
    try:
        import asyncio
        
        data = request.get_json() or {}
        min_threat = data.get('min_threat_score', 75)
        min_bahrain = data.get('min_bahrain_score', 70)
        
        result = asyncio.run(takedown_manager.batch_takedown(min_threat, min_bahrain))
        
        return jsonify({
            "status": "success",
            "batch_result": result
        })
        
    except Exception as e:
        logger.error(f"Error in batch takedown: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Log startup information
    logger.info("[START] Starting PhishSecure Bahrain CTI Platform with Continuous Monitoring")
    config_warnings = Config.validate_config()
    
    if config_warnings:
        for warning in config_warnings:
            logger.warning(warning)
    
    # Auto-start continuous monitoring if configured
    if getattr(Config, 'AUTO_START_MONITORING', True):
        logger.info("[SEARCH] Auto-starting continuous threat monitoring...")
        try:
            continuous_monitor.start_monitoring()
            logger.info("[OK] Continuous monitoring started successfully")
        except Exception as e:
            logger.error(f"[ERR] Failed to start continuous monitoring: {e}")
    
    app.run(debug=Config.DEBUG, host='0.0.0.0', port=5000)
