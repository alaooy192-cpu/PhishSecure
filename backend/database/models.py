"""
SQLAlchemy models for PhishSecure Bahrain CTI Platform
"""

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import json

Base = declarative_base()

class ThreatIndicator(Base):
    __tablename__ = 'threat_indicators'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(String(20), nullable=False)  # 'domain', 'url', 'ip'
    indicator_value = Column(Text, nullable=False, unique=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow)
    source = Column(String(50), nullable=False)  # 'urlhaus', 'manual', 'enrichment'
    status = Column(String(20), default='active')  # 'active', 'inactive', 'false_positive'
    
    # Threat Scoring
    threat_score = Column(Integer, default=0)  # 0-100
    confidence_level = Column(String(20), default='low')  # 'low', 'medium', 'high'
    
    # Bahrain Relevance
    bahrain_score = Column(Integer, default=0)  # 0-100
    bahrain_keywords = Column(Text)  # JSON array of matched keywords
    targeted_sector = Column(String(50))  # 'banking', 'telecom', 'government', 'general'
    
    # Technical Analysis
    domain_age_days = Column(Integer)
    tld = Column(String(10))
    subdomain_count = Column(Integer, default=0)
    suspicious_patterns = Column(Text)  # JSON array of detected patterns
    
    # Enrichment Data
    virustotal_detections = Column(Integer, default=0)
    virustotal_total = Column(Integer, default=0)
    abuse_confidence = Column(Integer, default=0)
    geolocation_country = Column(String(3))
    
    # Metadata
    tags = Column(Text)  # JSON array of tags
    notes = Column(Text)
    analyst_reviewed = Column(Boolean, default=False)
    
    # Relationships
    analysis_history = relationship("AnalysisHistory", back_populates="indicator")

class BahrainBrand(Base):
    __tablename__ = 'bahrain_brands'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    brand_name = Column(String(100), nullable=False)
    sector = Column(String(50), nullable=False)
    official_domains = Column(Text)  # JSON array of legitimate domains
    common_typos = Column(Text)  # JSON array of common typosquatting patterns
    keywords = Column(Text)  # JSON array of brand-related keywords
    risk_weight = Column(Integer, default=1)  # Multiplier for scoring
    created_at = Column(DateTime, default=datetime.utcnow)

class AnalysisHistory(Base):
    __tablename__ = 'analysis_history'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_id = Column(Integer, ForeignKey('threat_indicators.id'))
    analysis_type = Column(String(50))  # 'automated', 'manual', 'enrichment'
    analysis_date = Column(DateTime, default=datetime.utcnow)
    previous_threat_score = Column(Integer)
    new_threat_score = Column(Integer)
    previous_bahrain_score = Column(Integer)
    new_bahrain_score = Column(Integer)
    changes_made = Column(Text)  # JSON object describing changes
    analyst_id = Column(String(50))
    
    # Relationships
    indicator = relationship("ThreatIndicator", back_populates="analysis_history")

class DashboardStats(Base):
    __tablename__ = 'dashboard_stats'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    stat_date = Column(DateTime, nullable=False, unique=True)
    total_indicators = Column(Integer, default=0)
    high_threat_count = Column(Integer, default=0)
    bahrain_relevant_count = Column(Integer, default=0)
    new_indicators_today = Column(Integer, default=0)
    top_sectors = Column(Text)  # JSON object with sector counts
    threat_trends = Column(Text)  # JSON object with trend data
    updated_at = Column(DateTime, default=datetime.utcnow)

# Database initialization
class DatabaseManager:
    def __init__(self, db_path: str = "phishsecure_cti.db"):
        self.engine = create_engine(f'sqlite:///{db_path}')
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
    def create_tables(self):
        """Create all tables"""
        Base.metadata.create_all(bind=self.engine)
        
    def get_session(self):
        """Get database session"""
        return self.SessionLocal()
        
    def init_default_data(self):
        """Initialize default Bahrain brands and sectors"""
        session = self.get_session()
        
        try:
            # Check if brands already exist
            if session.query(BahrainBrand).count() > 0:
                return
            
            default_brands = [
                {
                    'brand_name': 'Benefit',
                    'sector': 'banking',
                    'official_domains': json.dumps(['benefit.bh', 'benefit-bh.com']),
                    'common_typos': json.dumps(['benef1t', 'benefit-pay', 'benefitpay']),
                    'keywords': json.dumps(['benefit', 'payment', 'transfer', 'بنفت']),
                    'risk_weight': 3
                },
                {
                    'brand_name': 'Batelco',
                    'sector': 'telecom',
                    'official_domains': json.dumps(['batelco.bh', 'batelco.com']),
                    'common_typos': json.dumps(['bate1co', 'batelc0', 'battelco']),
                    'keywords': json.dumps(['batelco', 'mobile', 'internet', 'باتلكو']),
                    'risk_weight': 3
                },
                {
                    'brand_name': 'STC Bahrain',
                    'sector': 'telecom',
                    'official_domains': json.dumps(['stc.bh', 'stc-bahrain.com']),
                    'common_typos': json.dumps(['stc-bh', 'stcbahrain', 'stc-pay']),
                    'keywords': json.dumps(['stc', 'viva', 'telecom', 'اس تي سي']),
                    'risk_weight': 3
                },
                {
                    'brand_name': 'NBB',
                    'sector': 'banking',
                    'official_domains': json.dumps(['nbbonline.com', 'nbb.bh']),
                    'common_typos': json.dumps(['nbb-online', 'nbbank', 'nbb-bh']),
                    'keywords': json.dumps(['nbb', 'national', 'bank', 'البنك الأهلي']),
                    'risk_weight': 3
                },
                {
                    'brand_name': 'BBK',
                    'sector': 'banking',
                    'official_domains': json.dumps(['bbkonline.com', 'bbk.bh']),
                    'common_typos': json.dumps(['bbk-online', 'bbkbank', 'bbk-bh']),
                    'keywords': json.dumps(['bbk', 'bahrain', 'kuwait', 'بنك البحرين والكويت']),
                    'risk_weight': 3
                },
                {
                    'brand_name': 'Government of Bahrain',
                    'sector': 'government',
                    'official_domains': json.dumps(['bahrain.bh', 'gov.bh', 'egov.bh']),
                    'common_typos': json.dumps(['bahrain-gov', 'gov-bh', 'egov-bahrain']),
                    'keywords': json.dumps(['government', 'ministry', 'egov', 'حكومة البحرين']),
                    'risk_weight': 4
                }
            ]
            
            for brand_data in default_brands:
                brand = BahrainBrand(**brand_data)
                session.add(brand)
            
            session.commit()
            
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
