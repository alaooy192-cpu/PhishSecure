# PhishSecure - Phishing Email Analyzer

A web-based application that uses AI-powered machine learning and threat intelligence to detect phishing **email domains** based on patterns and structure. Users can paste an email address, and the system will analyze the **sender domain** for phishing indicators and return a risk assessment with global threat context.

---

## Live Demo
[Visit the app on Vercel]

---

## Features

### Core Detection
- Analyze **sender domain** for phishing indicators
- Typosquatting detection (e.g. `paypa1.com` instead of `paypal.com`)
- Homoglyph detection (lookalike characters)
- Suspicious TLD identification (`.ru`, `.tk`, `.xyz`, etc.)
- Domain structure analysis (hyphens, digits, length)
- Subdomain abuse detection
- Entropy analysis for random-looking domains

### Threat Intelligence Layer
- **VirusTotal Integration**: Real-time domain reputation checks
- **WHOIS Lookup**: Domain age and registration info
- **Campaign Detection**: Identifies if threat is part of active phishing campaign
- **Business Context**: Organizational impact assessment and recommended actions

### Analysis Output
- Verdict: `phishing` or `legitimate`
- Confidence score
- Detailed flags and indicators
- Threat status: Clear / Monitor / Suspicious / Active Campaign / Critical
- Risk level assessment

---

## Tech Stack

### Backend (Flask API)
- Python 3, Flask
- scikit-learn, XGBoost
- VirusTotal API integration
- WHOIS lookup (python-whois)
- Feature engineering and heuristics

### Frontend (Next.js)
- Next.js + React
- Framer Motion animations
- Real-time analysis display
- Threat intelligence visualization

---

## How It Works

1. User inputs a sender email address
2. The system extracts the **email domain**
3. The backend extracts features:
   - TF-IDF n-gram vectorization
   - Digit and hyphen counts
   - Domain suffix analysis
   - Typosquatting distance (Levenshtein to known brands)
   - Homoglyph detection
   - Entropy calculation
4. Threat intelligence enrichment:
   - VirusTotal domain reputation
   - WHOIS domain age lookup
   - Campaign likelihood analysis
5. Predictions are made using:
   - ML classifiers (Logistic Regression, XGBoost)
   - Rule-based phishing heuristics
   - Threat intelligence correlation
6. The verdict, confidence score, and threat context are returned

---

## Project Structure

```
PhishSecure/
├── backend/
│   ├── app.py                    # Flask API
│   ├── email_utils.py            # Core detection logic
│   ├── services/
│   │   └── threat_intel.py       # VirusTotal & WHOIS integration
│   ├── model/                    # ML models
│   └── requirements.txt
├── frontend/
│   ├── pages/
│   │   └── index.tsx             # Main application
│   ├── components/
│   │   ├── EmailInput.tsx        # Input form
│   │   └── ResultCard.tsx        # Analysis results display
│   └── utils/
│       └── api.ts                # API utilities
```

---

## Installation (Local)

### 1. Backend (Flask API)

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

### 2. Frontend (Next.js)

```bash
cd frontend
npm install
npm run dev
```

### 3. Environment Variables

Set the following environment variable for threat intelligence:
```
VIRUSTOTAL_API_KEY=your_api_key_here
```

---

## API Endpoints

### POST /analyze
Analyzes an email address for phishing indicators.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "verdict": "phishing",
  "confidence": 85,
  "flags": ["Suspicious TLD", "Domain contains numbers"],
  "threat_intel": {
    "virustotal": { "malicious_count": 5, "total_engines": 70 },
    "whois": { "age_days": 7, "creation_date": "2024-01-01" },
    "threat_status": "active_campaign",
    "campaign_likelihood": "high",
    "risk_level": "critical"
  },
  "business_context": {
    "organizational_impact": "high",
    "recommended_actions": ["Block domain immediately", "Alert security team"]
  }
}
```

---

## Detection Capabilities

| Feature | Description |
|---------|-------------|
| Typosquatting | Detects brand impersonation (paypa1, micr0soft) |
| Homoglyphs | Identifies lookalike characters (Cyrillic, special chars) |
| Subdomain Abuse | Flags brand names in subdomains of malicious domains |
| TLD Risk | Categorizes TLDs by risk level |
| Domain Age | New domains flagged as higher risk |
| Entropy Analysis | Detects randomly generated domains |
| VirusTotal | Cross-references with 70+ security engines |
| Campaign Detection | Correlates indicators to identify active attacks |

---

## License
MIT License
