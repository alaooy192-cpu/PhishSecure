# 📧 Phishing Email Analyzer

A web-based application that uses AI-powered machine learning to detect phishing **email domains** based on patterns and structure. Users can paste an email address, and the system will analyze the **sender domain** for phishing indicators and return a risk assessment.

---

## 🚀 Live Demo
🌐 [Visit the app on Vercel]  

---

## 🧠 Features

- Paste sender email.
- Analyze **sender domain** only (not full content)
- Extract domain-based indicators:
  - Typosquatting (e.g. `paypa1.com` instead of `paypal.com`)
  - Suspicious TLDs (`.ru`, `.tk`, `.xyz`, etc.)
  - Use of hyphens and digits in domain
  - Unusual domain length (e.g. `support-login-secure-verify.com`)
- Combines **ML classifiers + rule-based detection**
- Returns verdict (`phishing` or `legitimate`), confidence score, and reasons

---

## 🛠️ Tech Stack

### 🔍 Backend (Flask API)
- Python 3, Flask
- scikit-learn (Logistic Regression)
- XGBoost (Gradient boosting)
- Feature engineering
- Hosted on **Render**

### 💻 Frontend (Web App)
- Next.js + Tailwind CSS
- Email/domain input + upload interface
- Fetches analysis results from the API
- Hosted on **Vercel**

---

## 🧪 How It Works

1. User inputs a sender email address
2. The frontend extracts the **email domain**
3. The backend extracts features:
   - TF-IDF n-gram vectorization
   - Digit and hyphen counts
   - Domain suffix (e.g. `.ru`)
   - Domain length
   - Typosquatting distance (e.g. edit distance to known brands)
4. Predictions are made using:
   - Logistic Regression
   - XGBoost Classifier
   - Rule-based phishing heuristics
5. The system applies a **voting ensemble**
6. The verdict and confidence score are returned

---

## 📁 Project Structure

```
phishing-email-analyzer/
├── backend/
│   ├── app.py                    # Flask API
│   ├── phishing_voting_model.pkl # Trained ML ensemble
│   ├── vectorizer.pkl            # TF-IDF vectorizer
│   ├── utils.py                  # Feature extraction functions
│   └── requirements.txt
├── frontend/
│   ├── pages/
│   │   ├── index.tsx             # Input form
│   │   └── result.tsx            # Verdict display
│   ├── components/
│   └── tailwind.config.js
```

---

## 📦 Installation (Local)

### 1. Backend (Flask API)

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

### 2. Frontend (Next.js)

```bash
cd frontend
npm install
npm run dev
```

---

## 📚 Training the Model

This project uses custom-trained phishing detection models based on sender domain features extracted from real email datasets.

### Dataset Sources:
- 📎 Kaggle Phishing Email Datasets

### Features:
- Character-level TF-IDF of domain name
- Digit count, hyphen count, domain suffix
- Domain length
- Typosquatting similarity (Levenshtein distance to known brands)
- Rule-based blacklist for suspicious TLDs

### Models:
- Logistic Regression
- XGBoost Classifier
- Combined with rule-based filtering using suspicious suffixes

### Ensemble:
- Soft voting classifier
- Boosted with rule-based override:
  - If domain ends with .ru, .tk, .xyz, etc. → flagged phishing automatically

### 📁 Model Files
- `phishing_voting_model.pkl`: Trained ensemble model (LogReg + XGBoost)
- `vectorizer.pkl`: TF-IDF vectorizer for domain processing

These are loaded by the Flask API on request.

---

## 👤 Author
Walaa Mohamed
