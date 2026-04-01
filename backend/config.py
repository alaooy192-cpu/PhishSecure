"""
Configuration management for PhishSecure Bahrain CTI Platform
"""

import os
from datetime import timedelta

class Config:
    # Database
    DATABASE_PATH = os.getenv('DATABASE_PATH', './cti_database.db')
    
    # Demo mode (generates sample data if no real sources available)
    USE_DEMO_DATA = os.getenv('USE_DEMO_DATA', 'true').lower() == 'true'
    
    # Threat collection settings
    COLLECTION_INTERVAL_HOURS = int(os.getenv('COLLECTION_INTERVAL_HOURS', '6'))
    
    # Scoring thresholds
    HIGH_THREAT_THRESHOLD = int(os.getenv('HIGH_THREAT_THRESHOLD', '70'))
    HIGH_BAHRAIN_RELEVANCE_THRESHOLD = int(os.getenv('HIGH_BAHRAIN_RELEVANCE_THRESHOLD', '60'))
    
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'phishsecure-bahrain-cti-dev-key')
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    
    # Threat Intelligence API Keys (for accurate live results)
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'd227e1dd1a60592c3128bf72fe60469259a420798d80feea47b2fd07be3fccfbc8fffd323bd98d19')
    OTX_API_KEY = os.getenv('OTX_API_KEY')
    CENSYS_API_KEY = os.getenv('CENSYS_API_KEY', 'censys_eVCj1dw9_MbHjv34t3eyD9Q7SGdrYjy4N')
    
    # Continuous monitoring settings
    AUTO_START_MONITORING = os.getenv('AUTO_START_MONITORING', 'true').lower() == 'true'
    MONITORING_INTERVAL_MINUTES = int(os.getenv('MONITORING_INTERVAL_MINUTES', '15'))
    
    # Multi-source intelligence settings
    ENABLE_MULTI_SOURCE = os.getenv('ENABLE_MULTI_SOURCE', 'true').lower() == 'true'
    MAX_INDICATORS_PER_COLLECTION = int(os.getenv('MAX_INDICATORS_PER_COLLECTION', '500'))
    
    # Rate Limiting
    API_RATE_LIMIT_SECONDS = int(os.getenv('API_RATE_LIMIT_SECONDS', '2'))
    
    # Alerting Configuration
    SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')
    TEAMS_WEBHOOK_URL = os.getenv('TEAMS_WEBHOOK_URL')
    EMAIL_SMTP_HOST = os.getenv('EMAIL_SMTP_HOST', 'smtp.gmail.com')
    EMAIL_SMTP_PORT = int(os.getenv('EMAIL_SMTP_PORT', '587'))
    EMAIL_USERNAME = os.getenv('EMAIL_USERNAME')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
    ALERT_RECIPIENTS = os.getenv('ALERT_RECIPIENTS', '')  # Comma-separated emails
    
    # MISP Integration
    MISP_URL = os.getenv('MISP_URL')
    MISP_API_KEY = os.getenv('MISP_API_KEY')
    MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'true').lower() == 'true'
    
    # SIEM Integration
    SIEM_WEBHOOK_URL = os.getenv('SIEM_WEBHOOK_URL')  # Splunk, QRadar, etc.
    SIEM_API_KEY = os.getenv('SIEM_API_KEY')
    
    @classmethod
    def validate_config(cls):
        """Validate configuration and return any warnings"""
        warnings = []
        
        if not cls.VIRUSTOTAL_API_KEY:
            warnings.append("VirusTotal API key not configured - enrichment features limited")
        
        if not cls.ABUSEIPDB_API_KEY:
            warnings.append("AbuseIPDB API key not configured - IP analysis limited")
        
        if cls.USE_DEMO_DATA:
            warnings.append("Running in demo mode - using simulated threat data")
        
        return warnings
