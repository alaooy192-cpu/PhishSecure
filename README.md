# PhishSecure Bahrain — Cyber Threat Intelligence Platform

A full-stack Cyber Threat Intelligence (CTI) platform focused on monitoring phishing threats targeting Bahrain's banking, telecom, government, and business sectors. It collects real threat indicators from live public feeds, scores them for Bahrain relevance, and presents them through a modern Next.js dashboard.

**Live Frontend:** Deployed on Vercel  
**Live Backend:** Deployed on Render at `https://phishsecure.onrender.com`

---

## Architecture Overview

```
Browser (Next.js on Vercel)
       │
       │ HTTP/REST (NEXT_PUBLIC_CTI_API_URL)
       ▼
Flask API (app_cti.py on Render :5000)
       │
       ├── SQLite Database (cti_database.db)
       ├── services/ (threat collection, scoring, monitoring)
       └── External APIs (URLhaus, PhishTank, AbuseIPDB, Censys)
```

---

## File Structure

### Root
```
PhishSecure/
├── README.md                  # This file
├── .gitignore                 # Ignores *.db, *.pickle, venv, node_modules, .env
├── package.json               # Root-level package.json (Next.js workspace helper)
├── backend/                   # Python Flask API
└── frontend/                  # Next.js React application
```

---

### `backend/`

```
backend/
├── app_cti.py                 # MAIN ENTRY POINT — Flask app, all API routes
├── config.py                  # Configuration class (env vars, thresholds, API keys)
├── requirements.txt           # Python dependencies
├── render.yaml                # Render.com deployment config (start command, env vars, disk)
├── .env.example               # Template for required environment variables
├── database/
│   ├── models.py              # SQLAlchemy ORM models: ThreatIndicator, BahrainBrand, DashboardStats
│   └── schema.sql             # Raw SQL schema (reference only, models.py handles creation)
├── services/
│   ├── threat_collector.py    # Collects indicators from URLhaus and PhishTank (sync, requests)
│   ├── multi_intel_collector.py  # Async multi-source collector (aiohttp): URLhaus, PhishTank, AbuseIPDB, Censys, OTX, VirusTotal
│   ├── threat_analyzer.py     # Analyzes a domain/URL for threat signals (heuristics, structure)
│   ├── bahrain_scorer.py      # Scores indicators for Bahrain relevance (keywords, brands, sectors)
│   ├── continuous_monitor.py  # Background monitoring loop, runs collection on interval
│   ├── alert_manager.py       # Sends alerts via Slack, Teams, or email when threats exceed thresholds
│   ├── misp_integration.py    # Optional MISP (threat sharing platform) integration
│   ├── siem_integration.py    # Optional SIEM (Splunk/QRadar) webhook integration
│   └── takedown_manager.py    # Manages abuse/takedown reports for malicious domains
└── data/
    └── .gitkeep               # Keeps data/ folder tracked (DB file lives here on Render)
```

#### Key Backend File Details

**`app_cti.py`** — The only file that runs (`python app_cti.py`). Registers all Flask routes, initializes all services, and starts the continuous monitor. Route groups:
- `GET /` — Health check and service info
- `GET /api/dashboard/stats` — Aggregated counts, sector breakdown, recent high-priority threats
- `GET /api/dashboard/trends` — Daily threat trend data for the chart
- `GET /api/indicators/list` — Paginated, filterable list of threat indicators
- `GET /api/indicators/<id>` — Single indicator detail
- `POST /api/analysis/domain` — Analyze a domain for threat score and Bahrain relevance
- `POST /api/analysis/bulk` — Analyze multiple indicators at once
- `POST /api/collection/run` — Manually trigger a live threat collection cycle
- `GET /api/collection/status` — Last collection time and indicator count
- `GET /api/intelligence/sources` — Status of each intel source
- `POST /api/intelligence/collect` — Run multi-source async collection
- `POST /api/alerts/test` — Send a test alert
- `POST /api/takedown/request` — Submit a takedown request
- `POST /api/takedown/batch` — Batch takedown for high-score threats

**`config.py`** — Single `Config` class loaded from environment variables. Key settings:
- `DATABASE_PATH` — Path to SQLite file (default `./cti_database.db`)
- `USE_DEMO_DATA` — `false` (real APIs used)
- `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `CENSYS_API_KEY` — Intel API keys
- `HIGH_THREAT_THRESHOLD` — Score ≥70 = high threat
- `HIGH_BAHRAIN_RELEVANCE_THRESHOLD` — Score ≥60 = Bahrain-relevant
- `AUTO_START_MONITORING`, `MONITORING_INTERVAL_MINUTES` — Continuous monitor settings

**`database/models.py`** — SQLAlchemy ORM with three models:
- `ThreatIndicator` — Core table: `indicator_value`, `indicator_type` (domain/url/ip), `threat_score`, `bahrain_score`, `targeted_sector`, `source`, `confidence_level`, `tags` (JSON), `status`, `first_seen`, `last_updated`
- `BahrainBrand` — Known Bahrain brands/sectors used for relevance scoring: `brand_name`, `sector`, `official_domains`, `common_typos`, `keywords`, `risk_weight`
- `DashboardStats` — Cached stats snapshots

**`services/threat_collector.py`** — Synchronous collector using `requests`. Pulls from:
- URLhaus (`https://urlhaus-api.abuse.ch/v1/urls/recent/`) — no API key needed
- PhishTank (`http://data.phishtank.com/data/online-valid.json`) — public feed
Stores indicators via raw SQLite (`sqlite3`). Used by `POST /api/collection/run`.

**`services/multi_intel_collector.py`** — Async collector using `aiohttp`. Runs all sources concurrently:
- URLhaus (payloads feed)
- PhishTank (phishing URLs, filtered to last 24h)
- AbuseIPDB (IP abuse reports, requires `ABUSEIPDB_API_KEY`)
- Censys (internet asset discovery, requires `CENSYS_API_KEY`)
- AlienVault OTX (open threat exchange, requires `OTX_API_KEY`)
- VirusTotal (requires `VIRUSTOTAL_API_KEY`)
- DNS monitoring for new Bahrain-related domains
Stores via SQLAlchemy. Used by `POST /api/intelligence/collect`.

**`services/bahrain_scorer.py`** — Calculates `bahrain_score` (0–100) for any indicator based on: Bahrain brand keyword matches, `.bh` TLD, known Bahrain-targeted keywords (Arabic + English), sector detection (banking/telecom/government/business).

**`services/threat_analyzer.py`** — Heuristic analysis of domains/URLs: suspicious TLD list, digit/hyphen counts, domain length, brand impersonation patterns, entropy scoring.

**`services/continuous_monitor.py`** — Background thread that runs a collection + analysis cycle every `MONITORING_INTERVAL_MINUTES` minutes. Auto-starts on app launch if `AUTO_START_MONITORING=true`.

---

### `frontend/`

```
frontend/
├── pages/
│   ├── _app.tsx               # Next.js app wrapper (global styles, layout)
│   ├── _document.tsx          # Custom HTML document (meta tags, fonts)
│   ├── index.tsx              # Homepage — hero, 3 feature cards, sector grid
│   ├── cti-dashboard.tsx      # Main CTI dashboard — stats, trend chart, recent threats
│   ├── indicators.tsx         # Threat indicators browser — filterable, paginated table
│   ├── analyze.tsx            # Domain analysis page — manual domain lookup
│   ├── live-monitoring.tsx    # Live monitoring feed — real-time threat stream
│   └── dashboard.tsx          # Redirect shim — redirects /dashboard → /cti-dashboard
├── styles/
│   └── global.css             # Global CSS variables and base styles
├── utils/
│   ├── cti-api.ts             # PRIMARY API UTIL — all fetch functions + TypeScript types for CTI backend
│   └── api.ts                 # Legacy wrapper — re-exports cti-api.ts, contains old interfaces
├── next.config.js             # Next.js config (env var forwarding)
├── tailwind.config.js         # Tailwind CSS config
├── tsconfig.json              # TypeScript config
└── package.json               # Frontend dependencies (Next.js, Framer Motion, Lucide React, Tailwind)
```

#### Key Frontend File Details

**`pages/index.tsx`** — Homepage. Shows platform branding, 3 navigation cards (Dashboard `◫`, Domain Analysis `◐`, Threat Indicators `☰`), and sector coverage grid (Banking `$`, Telecom `☎`, Government `⌂`, Business `⊞`). Animated particles background via dynamic import.

**`pages/cti-dashboard.tsx`** — Main dashboard. Polls `/api/dashboard/stats` and `/api/dashboard/trends` every 30 seconds. Shows: total indicators, high-threat count, Bahrain-relevant count, new-today count, bar chart of daily trends, sector breakdown, and recent high-priority threat cards. Has a "Collect Threats" button that calls `POST /api/collection/run`. Sector icons use `getSectorIcon()` returning Unicode symbols.

**`pages/indicators.tsx`** — Paginated table of all threat indicators. Filters: type (domain/url/ip) and sector via `CustomDropdown` component (dark-themed, defined inline). Clicking a row opens a side panel with full indicator details. Calls `GET /api/indicators/list`.

**`pages/analyze.tsx`** — Manual domain analysis. User types a domain, calls `POST /api/analysis/domain`, displays threat score, Bahrain relevance, matched keywords, sector, and recommended action.

**`pages/live-monitoring.tsx`** — Real-time threat monitoring feed. Polls for new indicators and displays them in a stream.

**`utils/cti-api.ts`** — The primary API utility. Exports:
- TypeScript interfaces: `CTIDashboardStats`, `ThreatTrends`, `ThreatIndicator`, `IndicatorsResponse`, `DomainAnalysisResult`, `CollectionResult`
- Async fetch functions: `fetchCTIDashboardStats`, `fetchThreatTrends`, `fetchThreatIndicators`, `fetchIndicatorDetails`, `analyzeDomain`, `analyzeBulk`, `triggerCollection`, `getCollectionStatus`, `checkCTIBackendHealth`
- Utility functions: `getThreatLevelColor`, `getBahrainRelevanceColor`, `formatDate`, `formatThreatLevel`, `getRecommendedActionDescription`
- Base URL from `NEXT_PUBLIC_CTI_API_URL` env var (falls back to `http://localhost:5000`)

---

## Environment Variables

### Backend (set in Render dashboard or `.env`)
| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_PATH` | `./cti_database.db` | SQLite database file path |
| `USE_DEMO_DATA` | `false` | Use live APIs (false) or skip real collection |
| `ABUSEIPDB_API_KEY` | hardcoded in config | IP reputation lookups |
| `CENSYS_API_KEY` | hardcoded in config | Internet asset discovery |
| `VIRUSTOTAL_API_KEY` | — | Domain/URL reputation (optional) |
| `OTX_API_KEY` | — | AlienVault OTX feed (optional) |
| `AUTO_START_MONITORING` | `true` | Start background monitor on launch |
| `MONITORING_INTERVAL_MINUTES` | `15` | How often to auto-collect |
| `HIGH_THREAT_THRESHOLD` | `70` | Score threshold for "high threat" |
| `HIGH_BAHRAIN_RELEVANCE_THRESHOLD` | `60` | Score threshold for "Bahrain relevant" |

### Frontend (set in Vercel dashboard or `.env.local`)
| Variable | Description |
|----------|-------------|
| `NEXT_PUBLIC_CTI_API_URL` | Full URL of deployed backend (e.g. `https://phishsecure.onrender.com`) |

---

## Local Development

### Backend
```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
python app_cti.py            # Starts on http://localhost:5000
```

### Frontend
```bash
cd frontend
npm install
# Create .env.local with:
# NEXT_PUBLIC_CTI_API_URL=http://localhost:5000
npm run dev                  # Starts on http://localhost:3000
```

---

## Deployment

### Backend → Render (Web Service)
- **Root Directory:** `backend`
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `python app_cti.py`
- **Env Vars:** Set `DATABASE_PATH`, `ABUSEIPDB_API_KEY`, `CENSYS_API_KEY` in Render dashboard
- Config file: `backend/render.yaml`

### Frontend → Vercel
- **Root Directory:** `frontend` (or repo root if `package.json` is there)
- **Framework:** Next.js (auto-detected)
- **Env Var:** `NEXT_PUBLIC_CTI_API_URL=https://phishsecure.onrender.com`

---

## Data Flow

```
1. App starts → app_cti.py initializes DB, starts continuous_monitor background thread
2. Monitor thread → calls threat_collector.run_collection_cycle() every 15 min
3. Collector → fetches from URLhaus/PhishTank → stores raw indicators in DB
4. Analyzer → bahrain_scorer assigns bahrain_score to each indicator
5. Frontend polls /api/dashboard/stats every 30s → renders charts and cards
6. User clicks "Collect Threats" → POST /api/collection/run → immediate cycle
7. User analyzes domain → POST /api/analysis/domain → threat_analyzer + bahrain_scorer → result
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend framework | Next.js 13 + React + TypeScript |
| Frontend styling | Tailwind CSS + inline styles |
| Animations | Framer Motion |
| Icons | Lucide React + Unicode symbols |
| Backend | Python 3, Flask, Flask-CORS |
| ORM | SQLAlchemy 2.0 |
| Database | SQLite (file-based, persistent disk on Render) |
| Async HTTP | aiohttp |
| DNS | dnspython |
| WHOIS | python-whois |
| ML/Stats | scikit-learn, scipy, numpy |
| Deployment (BE) | Render (Web Service, free tier) |
| Deployment (FE) | Vercel |

---
