# PhishSecure Bahrain CTI - Live Deployment Guide

Deploy the **PhishSecure Bahrain CTI Platform** globally for real-time threat monitoring accessible from anywhere.

## 🌍 **Live Deployment Options**

### Option 1: Railway (Recommended - Easiest)

**Backend Deployment:**
1. **Create Railway Account**: https://railway.app
2. **Connect GitHub**: Link your repository
3. **Deploy Backend**:
   ```bash
   # Push to GitHub first
   git add .
   git commit -m "Deploy PhishSecure Bahrain CTI"
   git push origin main
   ```
4. **Railway will automatically**:
   - Detect Python app in `/backend`
   - Install dependencies from `requirements_cti.txt`
   - Start with `python app_cti.py`
   - Provide live URL: `https://phishsecure-bahrain-cti.up.railway.app`

**Frontend Deployment:**
1. **Deploy to Vercel**: https://vercel.com
2. **Import GitHub repo**
3. **Configure**:
   - Framework: Next.js
   - Root Directory: `frontend`
   - Environment Variable: `NEXT_PUBLIC_CTI_API_URL=https://phishsecure-bahrain-cti.up.railway.app`

### Option 2: Render.com

**Backend:**
1. **Create Render Account**: https://render.com
2. **New Web Service** from GitHub
3. **Settings**:
   - Environment: Python
   - Build Command: `pip install -r requirements_cti.txt`
   - Start Command: `python app_cti.py`
   - Auto-Deploy: Yes

**Frontend:**
1. **New Static Site** on Render
2. **Settings**:
   - Build Command: `cd frontend && npm install && npm run build && npm run export`
   - Publish Directory: `frontend/out`

### Option 3: Heroku

**Backend:**
```bash
# Install Heroku CLI
heroku create phishsecure-bahrain-cti
heroku config:set FLASK_ENV=production
heroku config:set AUTO_START_MONITORING=true
git subtree push --prefix backend heroku main
```

## 🚀 **Quick Deploy (Railway + Vercel)**

**Step 1: Deploy Backend to Railway**
```bash
# 1. Push to GitHub
git add .
git commit -m "PhishSecure Bahrain CTI Platform"
git push origin main

# 2. Go to https://railway.app
# 3. "New Project" > "Deploy from GitHub repo"
# 4. Select your repo > Deploy backend folder
# 5. Railway auto-detects Python and deploys
# 6. Get live URL: https://your-app.up.railway.app
```

**Step 2: Deploy Frontend to Vercel**
```bash
# 1. Go to https://vercel.com
# 2. "New Project" > Import from GitHub
# 3. Select your repo
# 4. Framework: Next.js
# 5. Root Directory: frontend
# 6. Add Environment Variable:
#    NEXT_PUBLIC_CTI_API_URL = https://your-railway-backend-url
# 7. Deploy
```

## 🌐 **Live URLs After Deployment**

**Frontend (Public Access):**
- `https://phishsecure-bahrain.vercel.app` - Main CTI Platform
- `https://phishsecure-bahrain.vercel.app/live-monitoring` - Real-time monitoring
- `https://phishsecure-bahrain.vercel.app/cti-dashboard` - Threat dashboard
- `https://phishsecure-bahrain.vercel.app/analyze` - Domain analysis

**Backend API:**
- `https://phishsecure-bahrain-cti.up.railway.app` - CTI API
- `https://phishsecure-bahrain-cti.up.railway.app/api/monitoring/status` - Live monitoring status
- `https://phishsecure-bahrain-cti.up.railway.app/api/dashboard/stats` - Real-time stats

## ⚡ **Automatic Features After Deployment**

**Continuous Monitoring:**
- ✅ **Auto-starts** when backend deploys
- ✅ **Collects threats** every 15 minutes from URLhaus
- ✅ **Analyzes Bahrain relevance** automatically
- ✅ **Generates alerts** for critical threats
- ✅ **24/7 operation** with cloud hosting

**Global Accessibility:**
- ✅ **Accessible from anywhere** in the world
- ✅ **Real-time updates** every 30 seconds
- ✅ **Live threat monitoring** for Bahrain organizations
- ✅ **Mobile responsive** interface

## 🇧🇭 **Live Bahrain Threat Intelligence**

**What It Monitors:**
- **Banking Threats**: NBB, ABC Bank, BBK, Ahli United Bank
- **Telecom Threats**: Batelco, STC Bahrain, VIVA Bahrain
- **Government Threats**: eGovernment, ministry websites
- **Business Threats**: Major Bahrain corporations

**Real-time Capabilities:**
- **Threat Collection**: New threats every 15 minutes
- **Bahrain Scoring**: Automatic relevance calculation
- **Critical Alerts**: Immediate notifications for high-priority threats
- **Live Dashboard**: Real-time statistics and trends

## 🔧 **Environment Configuration**

**Production Environment Variables:**
```bash
# Backend (Railway/Render)
FLASK_ENV=production
AUTO_START_MONITORING=true
HIGH_THREAT_THRESHOLD=70
HIGH_BAHRAIN_RELEVANCE_THRESHOLD=60
DEBUG=false

# Frontend (Vercel/Netlify)
NEXT_PUBLIC_CTI_API_URL=https://your-backend-url
```

## 📊 **Monitoring After Deployment**

**Check Live Status:**
1. **Visit**: `https://your-frontend-url/live-monitoring`
2. **Verify**: Green "ACTIVE" status indicator
3. **Monitor**: Real-time threat statistics
4. **Alerts**: Critical threat notifications

**API Health Check:**
```bash
curl https://your-backend-url/
# Should return: {"service": "PhishSecure Bahrain CTI Platform", "status": "operational"}
```

## 🚨 **Critical Threat Alerts**

**Alert Criteria:**
- **Threat Score**: 80+ (out of 100)
- **Bahrain Relevance**: 70+ (out of 100)
- **Sectors**: Banking, Telecom, Government priority

**Alert Delivery:**
- **Live Dashboard**: Real-time alert feed
- **API Endpoint**: `/api/monitoring/alerts`
- **Severity Levels**: Critical, High, Medium, Low

## 🔒 **Security Features**

**Production Security:**
- **HTTPS Encryption**: All communications encrypted
- **CORS Protection**: Secure cross-origin requests
- **Input Validation**: All API inputs validated
- **Rate Limiting**: Protection against abuse

## 📈 **Scaling**

**Automatic Scaling:**
- **Railway**: Auto-scales based on traffic
- **Vercel**: Global CDN with edge caching
- **Database**: SQLite for development, PostgreSQL for production scale

---

**🎯 Result: Live, globally accessible CTI platform monitoring Bahrain threats 24/7 from anywhere in the world!**
