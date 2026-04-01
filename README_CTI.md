# PhishSecure Bahrain - Cyber Threat Intelligence Platform

A comprehensive **Cyber Threat Intelligence (CTI) platform** focused on monitoring phishing threats targeting Bahrain organizations. This platform provides real-time threat analysis with Bahrain-specific relevance scoring for banking, telecom, and government sectors.

## 🎯 Platform Overview

**PhishSecure Bahrain CTI** is a threat intelligence platform that:

- **Collects** phishing indicators from public threat intelligence sources
- **Analyzes** domains/URLs/IPs for threat levels and Bahrain relevance
- **Scores** threats based on local brand impersonation and sector targeting
- **Visualizes** threat data through modern dashboards and analytics
- **Provides** actionable intelligence for cybersecurity teams

## 🏗️ Architecture

### Backend (Flask + SQLite)
- **CTI API** (`app_cti.py`) - Main Flask application with RESTful endpoints
- **Threat Collector** - Ingests indicators from URLhaus and demo data
- **Bahrain Scorer** - Custom relevance scoring for local organizations
- **Threat Analyzer** - Technical analysis of domains, URLs, and IPs
- **Database Models** - SQLite with threat indicators and analysis history

### Frontend (Next.js + TypeScript)
- **CTI Dashboard** (`/cti-dashboard`) - Real-time threat statistics and trends
- **Indicators Browser** (`/indicators`) - Searchable threat indicator database
- **Domain Analyzer** (`/analyze`) - Individual domain analysis interface
- **Modern UI** - Cybersecurity-themed design with data visualizations

## 🚀 Quick Start

### 1. Backend Setup
```bash
cd backend

# Install dependencies
pip install -r requirements_cti.txt

# Initialize database
python -c "from database.models import DatabaseManager; DatabaseManager().init_db()"

# Start CTI backend
python app_cti.py
```

### 2. Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Set environment variables
cp .env.local.example .env.local
# Edit .env.local and set NEXT_PUBLIC_CTI_API_URL=http://localhost:5000

# Start frontend
npm run dev
```

### 3. Access the Platform
- **Homepage**: http://localhost:3000
- **CTI Dashboard**: http://localhost:3000/cti-dashboard
- **Domain Analysis**: http://localhost:3000/analyze
- **Threat Indicators**: http://localhost:3000/indicators

## 📊 Features

### CTI Dashboard
- **Real-time Statistics** - Total indicators, high threats, Bahrain relevance
- **Threat Trends** - Daily patterns and sector breakdown
- **Recent Threats** - Live feed of high-priority indicators
- **Demo Data Collection** - Generate sample data for testing

### Domain Analysis
- **Threat Scoring** - 0-100 scale threat assessment
- **Bahrain Relevance** - Local organization targeting analysis
- **Technical Details** - Domain structure, TLD, and age analysis
- **Actionable Recommendations** - Clear next steps for security teams

### Threat Indicators
- **Comprehensive Database** - Domains, URLs, and IP addresses
- **Advanced Filtering** - By type, sector, threat score, and relevance
- **Detailed Views** - Full technical analysis and metadata
- **Pagination** - Efficient browsing of large datasets

## 🇧🇭 Bahrain Focus

### Monitored Sectors
- **Banking** - NBB, ABC Bank, Ahli United Bank, Bank of Bahrain and Kuwait
- **Telecom** - Batelco, STC Bahrain, VIVA Bahrain
- **Government** - eGovernment, Ministry websites, public services
- **Business** - Major corporations and local brands

### Relevance Scoring
- **Brand Keywords** - Detection of impersonated local brands
- **Arabic Support** - Arabic brand names and terms
- **TLD Analysis** - Suspicious use of .bh and regional domains
- **Sector Classification** - Automatic categorization by target sector

## 🔧 Configuration

### Environment Variables
```bash
# Frontend (.env.local)
NEXT_PUBLIC_CTI_API_URL=http://localhost:5000

# Backend (config.py)
DATABASE_PATH=./cti_database.db
DEMO_MODE=true
COLLECTION_INTERVAL_HOURS=6
```

### Database Schema
- **threat_indicators** - Main threat data with scores and metadata
- **bahrain_brands** - Local brand keywords and patterns
- **analysis_history** - Historical analysis results
- **dashboard_stats** - Cached dashboard statistics

## 🛡️ Security Features

### Threat Analysis
- **Multi-factor Scoring** - Combines technical and contextual indicators
- **Confidence Levels** - High/Medium/Low confidence assessments
- **False Positive Reduction** - Bahrain-specific whitelisting
- **Threat Attribution** - Source and campaign identification

### Data Protection
- **Local Storage** - SQLite database for sensitive threat data
- **API Security** - CORS protection and input validation
- **Rate Limiting** - Protection against abuse
- **Audit Logging** - Analysis history and user actions

## 📈 API Endpoints

### Dashboard
- `GET /api/dashboard/stats` - Dashboard statistics
- `GET /api/dashboard/trends` - Threat trends data

### Analysis
- `POST /api/analysis/domain` - Analyze single domain
- `POST /api/analysis/bulk` - Bulk analysis

### Indicators
- `GET /api/indicators/list` - List threat indicators
- `GET /api/indicators/{id}` - Get indicator details

### Collection
- `POST /api/collection/run` - Trigger data collection
- `GET /api/collection/status` - Collection status

## 🎮 Demo Mode

The platform includes demo mode for testing and demonstrations:

1. **Demo Data Generation** - Creates realistic threat indicators
2. **Bahrain-focused Examples** - Local brand impersonation scenarios
3. **Sector Distribution** - Balanced targeting across sectors
4. **Safe Testing** - No external API calls required

## 🔄 Data Sources

### Current Sources
- **URLhaus** - Malware and phishing URL database
- **Demo Generator** - Synthetic Bahrain-focused threats

### Planned Sources
- **VirusTotal** - Domain and URL reputation
- **WHOIS** - Domain registration data
- **Custom Feeds** - Local threat intelligence

## 🚨 Alerting & Response

### Threat Levels
- **Critical (80-100)** - Immediate action required
- **High (60-79)** - Monitor closely
- **Medium (40-59)** - Investigate further
- **Low (0-39)** - Minimal concern

### Recommended Actions
- **Immediate Block** - High threat with local relevance
- **Monitor Closely** - Elevated threat level
- **Investigate** - Potential threat identified
- **Low Priority** - Minimal threat detected

## 🛠️ Development

### Adding New Features
1. **Backend** - Extend Flask API in `app_cti.py`
2. **Frontend** - Add React components in `pages/`
3. **Database** - Update models in `database/models.py`
4. **Scoring** - Modify `services/bahrain_scorer.py`

### Testing
```bash
# Backend tests
cd backend
python -m pytest tests/

# Frontend tests
cd frontend
npm test
```

## 📝 License

This project is developed for cybersecurity research and protection of Bahrain's digital infrastructure.

## 🤝 Contributing

Contributions welcome! Please focus on:
- Bahrain-specific threat intelligence
- Local brand and organization protection
- Arabic language support
- Regional threat patterns

---

**PhishSecure Bahrain CTI Platform** - Protecting Bahrain's Digital Infrastructure 🇧🇭🛡️
