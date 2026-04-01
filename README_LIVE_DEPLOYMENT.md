# 🌍 PhishSecure Bahrain CTI - LIVE Global Deployment

**Deploy your CTI platform globally in 5 minutes** - accessible from anywhere to monitor Bahrain threats 24/7.

## 🚀 **Instant Live Deployment**

### **Option 1: Railway + Vercel (Recommended)**

**Backend (Railway) - 2 minutes:**
1. **Push to GitHub**:
   ```bash
   git add .
   git commit -m "PhishSecure Bahrain CTI Live"
   git push origin main
   ```

2. **Deploy to Railway**:
   - Go to https://railway.app
   - Click "New Project" → "Deploy from GitHub repo"
   - Select your repository → Deploy from `/backend` folder
   - **Live URL**: `https://phishsecure-bahrain-cti.up.railway.app`

**Frontend (Vercel) - 2 minutes:**
1. **Deploy to Vercel**:
   - Go to https://vercel.com
   - Click "New Project" → Import from GitHub
   - Framework: **Next.js**
   - Root Directory: **frontend**
   - Environment Variable: `NEXT_PUBLIC_CTI_API_URL=https://phishsecure-bahrain-cti.up.railway.app`
   - **Live URL**: `https://phishsecure-bahrain.vercel.app`

### **Option 2: One-Click Deploy Buttons**

**Backend:**
[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template?template=https://github.com/your-repo/PhishSecure-4&plugins=postgresql&envs=FLASK_ENV,AUTO_START_MONITORING&FLASK_ENVDesc=Production+environment&AUTO_START_MONITORINGDesc=Start+monitoring+automatically)

**Frontend:**
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/your-repo/PhishSecure-4&project-name=phishsecure-bahrain-cti&repository-name=phishsecure-bahrain-cti&root-directory=frontend&env=NEXT_PUBLIC_CTI_API_URL&envDescription=Backend+API+URL&envLink=https://railway.app)

## 🌐 **Live Access URLs**

**After deployment, your platform will be live at:**

- **🏠 Homepage**: `https://phishsecure-bahrain.vercel.app`
- **🔴 Live Monitoring**: `https://phishsecure-bahrain.vercel.app/live-monitoring`
- **📊 CTI Dashboard**: `https://phishsecure-bahrain.vercel.app/cti-dashboard`
- **🔍 Domain Analysis**: `https://phishsecure-bahrain.vercel.app/analyze`
- **🛡️ Threat Indicators**: `https://phishsecure-bahrain.vercel.app/indicators`

**API Endpoints:**
- **📡 API Base**: `https://phishsecure-bahrain-cti.up.railway.app`
- **📈 Live Stats**: `https://phishsecure-bahrain-cti.up.railway.app/api/monitoring/live-stats`
- **🚨 Alerts**: `https://phishsecure-bahrain-cti.up.railway.app/api/monitoring/alerts`

## ⚡ **What Happens After Deployment**

**Automatic 24/7 Operations:**
- ✅ **Continuous monitoring starts immediately**
- ✅ **Collects new threats every 15 minutes** from URLhaus
- ✅ **Analyzes Bahrain relevance** for all threats automatically
- ✅ **Generates critical alerts** for high-priority Bahrain threats
- ✅ **Updates live dashboard** every 30 seconds
- ✅ **Accessible globally** from any device, anywhere

**Real-time Bahrain Threat Intelligence:**
- 🏦 **Banking**: NBB, ABC Bank, BBK, Ahli United Bank monitoring
- 📱 **Telecom**: Batelco, STC Bahrain, VIVA Bahrain protection
- 🏛️ **Government**: eGovernment and ministry website security
- 🏢 **Business**: Major Bahrain corporation threat detection

## 🔧 **Production Configuration**

**Environment Variables (Auto-configured):**
```bash
# Backend (Railway)
FLASK_ENV=production
AUTO_START_MONITORING=true
HIGH_THREAT_THRESHOLD=70
HIGH_BAHRAIN_RELEVANCE_THRESHOLD=60
DEBUG=false

# Frontend (Vercel)
NEXT_PUBLIC_CTI_API_URL=https://phishsecure-bahrain-cti.up.railway.app
```

## 📊 **Live Monitoring Features**

**Real-time Dashboard:**
- **Total Threats**: Live count of all threats in database
- **Recent Threats**: New threats detected in last hour
- **Critical Bahrain**: High-priority threats targeting Bahrain
- **Alert Feed**: Real-time critical threat notifications

**Continuous Collection:**
- **URLhaus Integration**: Automatic threat collection every 15 minutes
- **Bahrain Analysis**: Custom scoring for local relevance
- **Sector Classification**: Banking, telecom, government categorization
- **Alert Generation**: Automatic notifications for critical threats

## 🚨 **Critical Alert System**

**Alert Criteria:**
- **Threat Score**: 80+ (High threat level)
- **Bahrain Relevance**: 70+ (High local relevance)
- **Target Sectors**: Banking, telecom, government priority

**Alert Delivery:**
- **Live Dashboard**: Real-time alert feed with severity indicators
- **API Access**: `/api/monitoring/alerts` endpoint
- **Severity Levels**: Critical, High, Medium, Low classification

## 🔒 **Security & Performance**

**Production Security:**
- **HTTPS Encryption**: All communications secured
- **CORS Protection**: Secure cross-origin requests
- **Input Validation**: All API inputs sanitized
- **Rate Limiting**: Protection against abuse

**Global Performance:**
- **CDN Distribution**: Vercel global edge network
- **Auto-scaling**: Railway automatic resource scaling
- **Database Optimization**: Efficient SQLite with indexing
- **Caching**: Smart caching for dashboard data

## 📱 **Mobile Access**

**Responsive Design:**
- ✅ **Mobile-optimized** interface
- ✅ **Touch-friendly** controls
- ✅ **Real-time updates** on mobile
- ✅ **Full functionality** on all devices

## 🌍 **Global Accessibility**

**Access from Anywhere:**
- ✅ **Bahrain**: Local cybersecurity teams
- ✅ **Regional**: GCC security operations centers
- ✅ **International**: Global threat researchers
- ✅ **Mobile**: Field security personnel

## 📈 **Monitoring Health**

**Check Live Status:**
```bash
# Health check
curl https://phishsecure-bahrain-cti.up.railway.app/

# Live monitoring status
curl https://phishsecure-bahrain-cti.up.railway.app/api/monitoring/status

# Recent alerts
curl https://phishsecure-bahrain-cti.up.railway.app/api/monitoring/alerts
```

## 🔄 **Continuous Updates**

**Auto-deployment:**
- **Code changes**: Automatic deployment on git push
- **Threat intelligence**: Real-time updates every 15 minutes
- **Dashboard data**: Live refresh every 30 seconds
- **Security patches**: Automatic platform updates

---

## 🎯 **Result**

**Your PhishSecure Bahrain CTI platform will be:**
- 🌍 **Live globally** - accessible from anywhere
- 🔴 **Monitoring 24/7** - continuous threat collection
- 🇧🇭 **Bahrain-focused** - local organization protection
- ⚡ **Real-time** - instant threat detection and alerts
- 📱 **Mobile-ready** - full functionality on all devices

**Deploy now and start protecting Bahrain's digital infrastructure immediately!**
