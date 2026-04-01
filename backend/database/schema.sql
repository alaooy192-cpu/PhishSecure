-- PhishSecure Bahrain CTI Database Schema

-- Threat Indicators Table
CREATE TABLE threat_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_type VARCHAR(20) NOT NULL, -- 'domain', 'url', 'ip'
    indicator_value TEXT NOT NULL UNIQUE,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(50) NOT NULL, -- 'urlhaus', 'manual', 'enrichment'
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'inactive', 'false_positive'
    
    -- Threat Scoring
    threat_score INTEGER DEFAULT 0, -- 0-100
    confidence_level VARCHAR(20) DEFAULT 'low', -- 'low', 'medium', 'high'
    
    -- Bahrain Relevance
    bahrain_score INTEGER DEFAULT 0, -- 0-100
    bahrain_keywords TEXT, -- JSON array of matched keywords
    targeted_sector VARCHAR(50), -- 'banking', 'telecom', 'government', 'general'
    
    -- Technical Analysis
    domain_age_days INTEGER,
    tld VARCHAR(10),
    subdomain_count INTEGER DEFAULT 0,
    suspicious_patterns TEXT, -- JSON array of detected patterns
    
    -- Enrichment Data
    virustotal_detections INTEGER DEFAULT 0,
    virustotal_total INTEGER DEFAULT 0,
    abuse_confidence INTEGER DEFAULT 0,
    geolocation_country VARCHAR(3),
    
    -- Metadata
    tags TEXT, -- JSON array of tags
    notes TEXT,
    analyst_reviewed BOOLEAN DEFAULT FALSE,
    
    INDEX idx_indicator_type (indicator_type),
    INDEX idx_bahrain_score (bahrain_score),
    INDEX idx_threat_score (threat_score),
    INDEX idx_first_seen (first_seen),
    INDEX idx_targeted_sector (targeted_sector)
);

-- Bahrain Brand Patterns Table
CREATE TABLE bahrain_brands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    brand_name VARCHAR(100) NOT NULL,
    sector VARCHAR(50) NOT NULL,
    official_domains TEXT, -- JSON array of legitimate domains
    common_typos TEXT, -- JSON array of common typosquatting patterns
    keywords TEXT, -- JSON array of brand-related keywords
    risk_weight INTEGER DEFAULT 1, -- Multiplier for scoring
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Analysis History Table
CREATE TABLE analysis_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_id INTEGER,
    analysis_type VARCHAR(50), -- 'automated', 'manual', 'enrichment'
    analysis_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    previous_threat_score INTEGER,
    new_threat_score INTEGER,
    previous_bahrain_score INTEGER,
    new_bahrain_score INTEGER,
    changes_made TEXT, -- JSON object describing changes
    analyst_id VARCHAR(50),
    
    FOREIGN KEY (indicator_id) REFERENCES threat_indicators(id)
);

-- Dashboard Statistics Cache
CREATE TABLE dashboard_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stat_date DATE NOT NULL,
    total_indicators INTEGER DEFAULT 0,
    high_threat_count INTEGER DEFAULT 0,
    bahrain_relevant_count INTEGER DEFAULT 0,
    new_indicators_today INTEGER DEFAULT 0,
    top_sectors TEXT, -- JSON object with sector counts
    threat_trends TEXT, -- JSON object with trend data
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(stat_date)
);

-- Insert default Bahrain brands and sectors
INSERT INTO bahrain_brands (brand_name, sector, official_domains, common_typos, keywords, risk_weight) VALUES
('Benefit', 'banking', '["benefit.bh", "benefit-bh.com"]', '["benef1t", "benefit-pay", "benefitpay"]', '["benefit", "payment", "transfer", "بنفت"]', 3),
('Batelco', 'telecom', '["batelco.bh", "batelco.com"]', '["bate1co", "batelc0", "battelco"]', '["batelco", "mobile", "internet", "باتلكو"]', 3),
('STC Bahrain', 'telecom', '["stc.bh", "stc-bahrain.com"]', '["stc-bh", "stcbahrain", "stc-pay"]', '["stc", "viva", "telecom", "اس تي سي"]', 3),
('NBB', 'banking', '["nbbonline.com", "nbb.bh"]', '["nbb-online", "nbbank", "nbb-bh"]', '["nbb", "national", "bank", "البنك الأهلي"]', 3),
('BBK', 'banking', '["bbkonline.com", "bbk.bh"]', '["bbk-online", "bbkbank", "bbk-bh"]', '["bbk", "bahrain", "kuwait", "بنك البحرين والكويت"]', 3),
('Government of Bahrain', 'government', '["bahrain.bh", "gov.bh", "egov.bh"]', '["bahrain-gov", "gov-bh", "egov-bahrain"]', '["government", "ministry", "egov", "حكومة البحرين"]', 4);
