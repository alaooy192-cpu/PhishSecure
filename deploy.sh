#!/bin/bash
# PhishSecure Bahrain CTI - One-Click Deployment Script

echo "🚀 Deploying PhishSecure Bahrain CTI Platform..."
echo "🇧🇭 Live threat monitoring for Bahrain organizations"

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "📝 Initializing Git repository..."
    git init
    git add .
    git commit -m "Initial commit: PhishSecure Bahrain CTI Platform"
fi

# Deploy to Railway (Backend)
echo "🔧 Deploying backend to Railway..."
echo "1. Go to https://railway.app"
echo "2. Click 'New Project' > 'Deploy from GitHub repo'"
echo "3. Select this repository"
echo "4. Choose 'backend' folder"
echo "5. Railway will auto-deploy Python app"
echo ""
echo "⚡ Backend will be live at: https://phishsecure-bahrain-cti.up.railway.app"
echo ""

# Deploy to Vercel (Frontend)
echo "🌐 Deploying frontend to Vercel..."
echo "1. Go to https://vercel.com"
echo "2. Click 'New Project' > Import from GitHub"
echo "3. Select this repository"
echo "4. Set Framework: Next.js"
echo "5. Set Root Directory: frontend"
echo "6. Add Environment Variable:"
echo "   NEXT_PUBLIC_CTI_API_URL = https://phishsecure-bahrain-cti.up.railway.app"
echo ""
echo "🌍 Frontend will be live at: https://phishsecure-bahrain.vercel.app"
echo ""

echo "✅ Deployment URLs:"
echo "🔴 Live Monitoring: https://phishsecure-bahrain.vercel.app/live-monitoring"
echo "📊 CTI Dashboard: https://phishsecure-bahrain.vercel.app/cti-dashboard"
echo "🔍 Domain Analysis: https://phishsecure-bahrain.vercel.app/analyze"
echo "🛡️ Threat Indicators: https://phishsecure-bahrain.vercel.app/indicators"
echo ""
echo "🇧🇭 Your CTI platform will monitor Bahrain threats 24/7 from anywhere!"
