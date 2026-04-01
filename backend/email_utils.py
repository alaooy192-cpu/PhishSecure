import re
import os
import pickle
import numpy as np
import math
from scipy.sparse import hstack

# ==================== ENHANCED HEURISTICS ====================

# Expanded list of trusted brands commonly targeted by phishing
TRUSTED_BRANDS = [
    'paypal', 'microsoft', 'apple', 'amazon', 'google', 'facebook', 'netflix',
    'instagram', 'twitter', 'linkedin', 'dropbox', 'adobe', 'spotify', 'slack',
    'zoom', 'github', 'gitlab', 'bitbucket', 'stripe', 'square', 'venmo',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'usbank', 'capitalone',
    'americanexpress', 'discover', 'hsbc', 'barclays', 'santander',
    'dhl', 'fedex', 'ups', 'usps', 'royalmail',
    'ebay', 'alibaba', 'aliexpress', 'walmart', 'target', 'bestbuy',
    'office365', 'outlook', 'hotmail', 'yahoo', 'aol', 'icloud',
    'coinbase', 'binance', 'kraken', 'blockchain',
    'whatsapp', 'telegram', 'signal', 'discord', 'tiktok', 'snapchat'
]

# Homoglyph mappings (characters that look similar)
HOMOGLYPHS = {
    'a': ['@', '4', 'а', 'ạ', 'à', 'á', 'â', 'ã', 'ä'],
    'b': ['8', 'ḅ', 'ь', 'в'],
    'c': ['(', 'ç', 'с', 'ċ'],
    'd': ['ḍ', 'ԁ'],
    'e': ['3', 'є', 'ė', 'ē', 'ę', 'ě', 'é', 'è', 'ê', 'ë'],
    'g': ['9', 'ġ', 'ğ'],
    'h': ['һ', 'ḥ'],
    'i': ['1', 'l', '!', '|', 'і', 'ị', 'ì', 'í', 'î', 'ï'],
    'k': ['κ', 'ḳ'],
    'l': ['1', 'i', '|', 'ł', 'ḷ'],
    'm': ['rn', 'ṃ', 'м'],
    'n': ['ñ', 'ń', 'ň', 'ṇ', 'п'],
    'o': ['0', 'ο', 'о', 'ọ', 'ò', 'ó', 'ô', 'õ', 'ö', 'ø'],
    'p': ['ρ', 'р', 'ṗ'],
    'r': ['ṛ', 'г'],
    's': ['5', '$', 'ṣ', 'ś', 'š', 'ş'],
    't': ['7', '+', 'ṭ', 'ţ', 'т'],
    'u': ['ụ', 'ù', 'ú', 'û', 'ü', 'μ'],
    'v': ['ν', 'ṿ'],
    'w': ['vv', 'ẉ', 'ш', 'щ'],
    'x': ['×', 'х', 'ẋ'],
    'y': ['ý', 'ÿ', 'у', 'ỵ'],
    'z': ['ż', 'ź', 'ž', 'ẓ']
}

# Suspicious keywords commonly used in phishing domains (removed overly common words)
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'sign-in', 'logon', 'log-on',
    'secure', 'security', 'verify', 'verification', 'validate', 'validation',
    'account', 'accounts', 'update', 'confirm', 'confirmation',
    'password', 'credential', 'auth', 'authenticate', 'authentication',
    'suspend', 'suspended', 'locked', 'unlock', 'restore', 'recover', 'recovery',
    'alert', 'warning', 'urgent', 'immediate', 'action', 'required',
    'billing', 'invoice', 'payment', 'pay', 'wallet', 'bank', 'banking',
    'support', 'help', 'helpdesk', 'service', 'customer', 'client',
    'webmail', 'inbox',
    'online', 'web', 'portal', 'access', 'member', 'user'
]

# TLD risk categories
HIGH_RISK_TLDS = ['tk', 'gq', 'ml', 'cf', 'ga', 'pw', 'cc', 'ws', 'click', 'link', 'work', 'date']
MEDIUM_RISK_TLDS = ['xyz', 'top', 'biz', 'info', 'online', 'site', 'website', 'space', 'fun', 'icu', 'buzz', 'live']
TRUSTED_TLDS = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'app', 'dev']

# Known legitimate domains (whitelist)
KNOWN_LEGITIMATE_DOMAINS = [
    'google.com', 'gmail.com', 'youtube.com', 'microsoft.com', 'outlook.com', 'live.com',
    'apple.com', 'icloud.com', 'amazon.com', 'aws.amazon.com', 'facebook.com', 'fb.com',
    'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 'github.com', 'gitlab.com',
    'dropbox.com', 'adobe.com', 'spotify.com', 'netflix.com', 'paypal.com',
    'stripe.com', 'slack.com', 'zoom.us', 'discord.com', 'reddit.com',
    'yahoo.com', 'aol.com', 'hotmail.com', 'msn.com'
]

def levenshtein_distance(s1, s2):
    """Calculate Levenshtein distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def calculate_entropy(text):
    """Calculate Shannon entropy of a string (higher = more random)"""
    if not text:
        return 0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def detect_homoglyphs(domain):
    """Detect if domain uses homoglyph characters to mimic a brand"""
    domain_lower = domain.lower()
    
    for brand in TRUSTED_BRANDS:
        # Check if domain contains characters that could be homoglyphs of brand
        normalized = domain_lower
        for char, glyphs in HOMOGLYPHS.items():
            for glyph in glyphs:
                normalized = normalized.replace(glyph, char)
        
        # If normalizing homoglyphs reveals a brand name
        if brand in normalized and brand not in domain_lower:
            return True, brand
        
        # Check for common substitutions like paypa1, g00gle, amaz0n
        if brand in domain_lower:
            continue
        
        # Check Levenshtein distance for near-matches
        domain_parts = re.split(r'[.-]', domain_lower)
        for part in domain_parts:
            if len(part) >= 4 and len(brand) >= 4:
                distance = levenshtein_distance(part, brand)
                # If very similar (1-2 char difference) and not exact match
                if 0 < distance <= 2 and len(part) >= len(brand) - 1:
                    return True, brand
    
    return False, None

def detect_subdomain_abuse(domain):
    """Detect if a brand name is used as subdomain of a malicious domain"""
    parts = domain.lower().split('.')
    
    if len(parts) < 3:
        return False, None
    
    # Check if any subdomain contains a brand name but the main domain doesn't
    main_domain = '.'.join(parts[-2:])  # e.g., "malicious-site.com"
    subdomains = parts[:-2]  # e.g., ["paypal", "secure"]
    
    for subdomain in subdomains:
        for brand in TRUSTED_BRANDS:
            if brand in subdomain:
                # Check if main domain is NOT the legitimate brand domain
                if brand not in main_domain:
                    return True, brand
    
    return False, None

def detect_suspicious_keywords(domain):
    """Detect suspicious keywords in domain"""
    domain_lower = domain.lower()
    found_keywords = []
    
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain_lower:
            found_keywords.append(keyword)
    
    return found_keywords

def is_punycode_suspicious(domain):
    """Check if domain uses punycode (internationalized domain) suspiciously"""
    # Punycode domains start with 'xn--'
    if 'xn--' in domain.lower():
        return True
    
    # Check for non-ASCII characters
    try:
        domain.encode('ascii')
        return False
    except UnicodeEncodeError:
        return True

def analyze_domain_structure(domain):
    """Analyze domain structure for suspicious patterns"""
    flags = []
    score_penalty = 0
    
    domain_lower = domain.lower()
    parts = domain_lower.split('.')
    domain_without_tld = '.'.join(parts[:-1]) if len(parts) > 1 else domain_lower
    
    # Check for excessive subdomains
    if len(parts) > 4:
        flags.append(f"Excessive subdomains ({len(parts) - 1} levels)")
        score_penalty += 15
    
    # Check for very long subdomain chains
    if len(domain) > 50:
        flags.append("Extremely long domain name")
        score_penalty += 20
    
    # Check for random-looking strings (high entropy)
    for part in parts[:-1]:  # Exclude TLD
        if len(part) > 6:
            entropy = calculate_entropy(part)
            if entropy > 3.5:  # High entropy suggests random string
                flags.append(f"Random-looking subdomain: {part}")
                score_penalty += 15
                break
    
    # Check for IP-like patterns in domain
    if re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', domain_lower):
        flags.append("IP address pattern in domain")
        score_penalty += 25
    
    # Check for date patterns (often used in phishing)
    if re.search(r'20[2-3]\d[-.]?(0[1-9]|1[0-2])[-.]?(0[1-9]|[12]\d|3[01])', domain_lower):
        flags.append("Date pattern in domain (common in phishing)")
        score_penalty += 20
    
    # Check for UUID-like patterns
    if re.search(r'[a-f0-9]{8}[-]?[a-f0-9]{4}[-]?[a-f0-9]{4}', domain_lower):
        flags.append("UUID-like pattern in domain")
        score_penalty += 20
    
    # Check for base64-like strings
    if re.search(r'[a-zA-Z0-9+/]{20,}={0,2}', domain_without_tld):
        flags.append("Encoded string pattern in domain")
        score_penalty += 15
    
    return flags, score_penalty

# ==================== END ENHANCED HEURISTICS ====================

# Paths to the model and tokenizer
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model', 'phishing_lstm_model.h5')
TOKENIZER_PATH = os.path.join(os.path.dirname(__file__), 'model', 'tokenizer.pickle')

# Mock classes for when the real model isn't available
class MockTokenizer:
    def __init__(self):
        self.vocabulary = set(['com', 'net', 'org', 'io', 'co', 'edu', 'gov', 'tk', 'xyz', 'ru'])
    
    def transform(self, domains):
        # Create a simple feature for each domain based on TLD
        from scipy.sparse import csr_matrix
        import numpy as np
        
        features = np.zeros((len(domains), len(self.vocabulary)))
        for i, domain in enumerate(domains):
            tld = domain.split('.')[-1] if '.' in domain else ''
            if tld in self.vocabulary:
                idx = list(self.vocabulary).index(tld)
                features[i, idx] = 1
        
        return csr_matrix(features)

class MockModel:
    def __init__(self):
        pass
    
    def predict_proba(self, X):
        # Simple heuristic: more features = more suspicious
        import numpy as np
        # Extract the dense part of X if it's a sparse matrix
        if hasattr(X, 'toarray'):
            X_dense = X.toarray()
        else:
            X_dense = X
            
        # Simple domain-based scoring
        # For our mock model, we'll use a simpler approach based on the domain features
        scores = np.zeros((X_dense.shape[0], 2))
        
        for i in range(X_dense.shape[0]):
            # Start with a moderate phishing probability
            phish_prob = 0.5
            
            # Use the metadata features if available to adjust the score
            if X_dense.shape[1] >= 4:
                num_digits = X_dense[i, -4] if X_dense.shape[1] > 3 else 0
                num_specials = X_dense[i, -3] if X_dense.shape[1] > 2 else 0
                domain_length = X_dense[i, -2] if X_dense.shape[1] > 1 else 0
                typosquat = X_dense[i, -1] if X_dense.shape[1] > 0 else 0
                
                # Adjust score based on these features
                # More digits and special chars increase phishing probability
                phish_prob += num_digits * 0.05
                phish_prob += num_specials * 0.03
                
                # Very long domains are more suspicious
                if domain_length > 20:
                    phish_prob += 0.1
                    
                # Typosquatting is a strong indicator of phishing
                if typosquat > 0:
                    phish_prob += 0.3
            
            # Known legitimate domains
            known_legitimate = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com']
            if any(domain == legit for legit in known_legitimate):
                phish_prob = 0.1  # Low phishing probability
            
            # Known phishing patterns
            if 'paypal' in str(X_dense) and '1' in str(X_dense):  # Simple check for paypal1
                phish_prob = 0.9  # High phishing probability
            
            # Ensure probability is between 0.1 and 0.9
            phish_prob = max(0.1, min(0.9, phish_prob))     
            
            # Normalize to a probability
            scores[i, 0] = 1 - phish_prob  # Probability of legitimate
            scores[i, 1] = phish_prob      # Probability of phishing
        
        return scores

# Load the model and tokenizer
def load_model_and_tokenizer():
    """Load the saved model and tokenizer or create mock versions"""
    try:
        # Try to load the real model and tokenizer
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        with open(TOKENIZER_PATH, 'rb') as f:
            tokenizer = pickle.load(f)
        print("Loaded real model and tokenizer")
        return model, tokenizer
    except Exception as e:
        print(f"Error loading model or tokenizer: {e}. Using mock model instead.")
        # Create mock versions
        return MockModel(), MockTokenizer()

# Extract domain from email address
def extract_domain(email):
    """Extract domain from an email address"""
    match = re.search(r'@([\w\.-]+)', str(email))
    return match.group(1) if match else "unknown"

# Extract features from domain
def extract_domain_features(domain):
    """Extract features from a domain name with enhanced analysis"""
    # Basic features
    suffix = domain.split('.')[-1].lower()
    num_digits = sum(c.isdigit() for c in domain)
    num_specials = domain.count('-') + domain.count('.')
    domain_length = len(domain)
    
    # Enhanced typosquatting detection using multiple methods
    typosquat = 0
    typosquat_brand = None
    
    # Method 1: Original digit-stripping check
    stripped = re.sub(r'\d', '', domain.lower())
    for brand in TRUSTED_BRANDS:
        if brand in domain.lower() and brand not in stripped:
            typosquat = 1
            typosquat_brand = brand
            break
    
    # Method 2: Homoglyph detection
    if not typosquat:
        is_homoglyph, brand = detect_homoglyphs(domain)
        if is_homoglyph:
            typosquat = 1
            typosquat_brand = brand
    
    # Method 3: Subdomain abuse detection
    subdomain_abuse, abused_brand = detect_subdomain_abuse(domain)
    
    # Suspicious keywords
    suspicious_keywords = detect_suspicious_keywords(domain)
    
    # Punycode/IDN check
    is_punycode = is_punycode_suspicious(domain)
    
    # Domain structure analysis
    structure_flags, structure_penalty = analyze_domain_structure(domain)
    
    # Calculate entropy of domain (excluding TLD)
    domain_without_tld = domain.rsplit('.', 1)[0] if '.' in domain else domain
    entropy = calculate_entropy(domain_without_tld)
    
    return {
        'num_digits': num_digits,
        'num_specials': num_specials,
        'domain_length': domain_length,
        'typosquat': typosquat,
        'typosquat_brand': typosquat_brand,
        'suffix': suffix,
        'subdomain_abuse': subdomain_abuse,
        'abused_brand': abused_brand,
        'suspicious_keywords': suspicious_keywords,
        'is_punycode': is_punycode,
        'structure_flags': structure_flags,
        'structure_penalty': structure_penalty,
        'entropy': entropy
    }

def extract_flags(email_content):
    """Extract potential phishing flags from email content or domain with enhanced detection"""
    flags = []
    
    # Try to extract domain from email content
    email_match = re.search(r'[\w\.-]+@([\w\.-]+)', email_content)
    if email_match:
        domain = email_match.group(1)
        
        # Check for suspicious domain features
        features = extract_domain_features(domain)
        
        # Check for high-risk TLDs
        if features['suffix'] in HIGH_RISK_TLDS:
            flags.append(f"High-risk TLD: .{features['suffix']} (commonly used in phishing)")
        elif features['suffix'] in MEDIUM_RISK_TLDS:
            flags.append(f"Medium-risk TLD: .{features['suffix']}")
        
        # Check for excessive digits
        if features['num_digits'] > 4:
            flags.append(f"Domain contains excessive digits ({features['num_digits']} found)")
        elif features['num_digits'] > 0:
            domain_without_tld = domain.rsplit('.', 1)[0] if '.' in domain else domain
            if any(char.isdigit() for char in domain_without_tld):
                flags.append("Domain contains numbers (potential phishing indicator)")
        
        # Check for typosquatting with brand info
        if features['typosquat'] == 1:
            brand = features.get('typosquat_brand', 'trusted brand')
            flags.append(f"Possible typosquatting of '{brand}'")
        
        # Check for subdomain abuse
        if features['subdomain_abuse']:
            brand = features.get('abused_brand', 'trusted brand')
            flags.append(f"Subdomain abuse: '{brand}' used as subdomain of suspicious domain")
        
        # Check for suspicious keywords
        if features['suspicious_keywords']:
            keywords = ', '.join(features['suspicious_keywords'][:3])  # Show max 3
            flags.append(f"Suspicious keywords in domain: {keywords}")
        
        # Check for punycode/IDN
        if features['is_punycode']:
            flags.append("Internationalized domain (IDN/Punycode) - may be used to spoof legitimate sites")
        
        # Add structure-based flags
        flags.extend(features['structure_flags'])
        
        # Check for very long domain names
        if features['domain_length'] > 40:
            flags.append(f"Unusually long domain name ({features['domain_length']} characters)")
        elif features['domain_length'] > 30:
            flags.append("Long domain name")
        
        # Check for high entropy (random-looking)
        if features['entropy'] > 4.0:
            flags.append("Domain appears randomly generated")
    
    # Check for IP addresses in domain
    if re.search(r'@\d+\.\d+\.\d+\.\d+', email_content):
        flags.append("Email from IP address instead of domain (highly suspicious)")
    
    return flags

def predict_phishing(email_content):
    """Predict if an email is phishing based on its domain with threat intelligence"""
    # Try to extract email address from content
    email_match = re.search(r'[\w\.-]+@([\w\.-]+)', email_content)
    
    if not email_match:
        # If no email found, return error
        return {
            "verdict": "error",
            "confidence": 0,
            "flags": ["No valid email address found"]
        }
    
    # Extract domain
    domain = email_match.group(1)
    
    # Quick check for obvious phishing patterns
    domain_without_tld = domain.rsplit('.', 1)[0] if '.' in domain else domain
    popular_brands = ['paypal', 'microsoft', 'apple', 'amazon', 'google', 'facebook']
    for brand in popular_brands:
        if brand in domain_without_tld.lower() and any(char.isdigit() for char in domain_without_tld):
            # Direct detection of brand name with numbers - highly suspicious pattern
            base_result = {
                "verdict": "phishing",
                "confidence": 30,  # Lower confidence score for phishing (more certain it's phishing)
                "flags": [f"Suspicious domain: contains '{brand}' with numbers (common phishing tactic)"]
            }
            # Enrich with threat intelligence
            try:
                from services.threat_intel import threat_intel_service
                return threat_intel_service.enrich_analysis(domain, base_result)
            except ImportError:
                # Fallback if threat intel not available
                return base_result
    
    # Extract features
    features = extract_domain_features(domain)
    
    # Load model and tokenizer
    model, tokenizer = load_model_and_tokenizer()
    
    if model is None or tokenizer is None:
        # Fallback to rule-based approach if model loading fails
        base_result = predict_phishing_rule_based(domain, features)
        # Enrich with threat intelligence
        try:
            from services.threat_intel import threat_intel_service
            return threat_intel_service.enrich_analysis(domain, base_result)
        except ImportError:
            return base_result
    
    try:
        # Transform domain using tokenizer
        X_tfidf = tokenizer.transform([domain])
        
        # Create feature matrix
        X_meta = np.array([[features['num_digits'], features['num_specials'], 
                          features['domain_length'], features['typosquat']]])
        X_combined = hstack([X_tfidf, X_meta])
        
        # Get prediction probability
        prediction_proba = model.predict_proba(X_combined)[0][1]  # Probability of class 1 (phishing)
        
        # Convert to percentage
        phishing_score = float(prediction_proba) * 100
        
        # Rule-based boost for suspicious TLDs
        suspicious_tlds = ['tk', 'xyz', 'cn', 'ru', 'top', 'gq', 'ml', 'cf', 'biz']
        if features['suffix'] in suspicious_tlds:
            phishing_score = max(phishing_score, 70)  # Boost score if suspicious TLD
        
        # Determine verdict based on threshold (60% or above)
        # If phishing_score is 60% or above, it should be classified as phishing
        is_phishing = phishing_score >= 60
        
        # Extract flags
        flags = extract_flags(email_content)
        
        # Print debug info
        print(f"[DEBUG] Domain: {domain}, Score: {phishing_score:.2f}%, Verdict: {'phishing' if is_phishing else 'legitimate'}")
        
        # For phishing emails (score >= 60%), confidence is phishing_score
        # For legitimate emails (score < 60%), confidence is 100 - phishing_score
        confidence = round(phishing_score if is_phishing else (100 - phishing_score), 2)
        
        base_result = {
            "verdict": "phishing" if is_phishing else "legitimate",
            "confidence": confidence,
            "flags": flags
        }
        
        # Enrich with threat intelligence
        try:
            from services.threat_intel import threat_intel_service
            return threat_intel_service.enrich_analysis(domain, base_result)
        except ImportError:
            return base_result
        
    except Exception as e:
        print(f"Error during prediction: {e}")
        # Fallback to rule-based approach
        base_result = predict_phishing_rule_based(domain, features)
        # Enrich with threat intelligence
        try:
            from services.threat_intel import threat_intel_service
            return threat_intel_service.enrich_analysis(domain, base_result)
        except ImportError:
            return base_result

def predict_phishing_rule_based(domain, features):
    """Enhanced rule-based prediction with smarter heuristics"""
    # Start with a neutral score
    phishing_score = 70  # Default score - slightly suspicious
    
    domain_lower = domain.lower()
    domain_without_tld = domain.rsplit('.', 1)[0].lower() if '.' in domain else domain_lower
    
    # ===== WHITELIST CHECK =====
    # Known legitimate domains get high scores
    if domain_lower in KNOWN_LEGITIMATE_DOMAINS:
        phishing_score = 95  # Very likely legitimate
    elif any(domain_lower.endswith('.' + tld) for tld in ['edu', 'gov', 'mil']):
        phishing_score = 90  # Government/education domains
    
    # ===== TYPOSQUATTING DETECTION =====
    if features['typosquat'] == 1:
        brand = features.get('typosquat_brand', 'unknown')
        phishing_score = 25  # Very likely phishing
        print(f"[DEBUG] Typosquatting detected for brand: {brand}")
    
    # ===== SUBDOMAIN ABUSE =====
    if features.get('subdomain_abuse', False):
        phishing_score = min(phishing_score, 30)  # Very suspicious
        print(f"[DEBUG] Subdomain abuse detected for brand: {features.get('abused_brand')}")
    
    # ===== PUNYCODE/IDN =====
    if features.get('is_punycode', False):
        phishing_score -= 25  # Suspicious
    
    # ===== TLD RISK =====
    if features['suffix'] in HIGH_RISK_TLDS:
        phishing_score -= 25
    elif features['suffix'] in MEDIUM_RISK_TLDS:
        phishing_score -= 15
    elif features['suffix'] in TRUSTED_TLDS and not features['typosquat']:
        phishing_score += 5  # Small boost for trusted TLDs
    
    # ===== SUSPICIOUS KEYWORDS =====
    suspicious_keywords = features.get('suspicious_keywords', [])
    if len(suspicious_keywords) >= 3:
        phishing_score -= 25  # Multiple suspicious keywords
    elif len(suspicious_keywords) >= 2:
        phishing_score -= 15
    elif len(suspicious_keywords) >= 1:
        phishing_score -= 8
    
    # ===== STRUCTURE PENALTIES =====
    structure_penalty = features.get('structure_penalty', 0)
    phishing_score -= structure_penalty
    
    # ===== DIGIT ANALYSIS =====
    if features['num_digits'] > 5:
        phishing_score -= 20
    elif features['num_digits'] > 2:
        phishing_score -= 10
    
    # Numbers in domain (excluding TLD) are suspicious
    if any(char.isdigit() for char in domain_without_tld):
        phishing_score -= 15
        
        # Brand + numbers = very suspicious
        for brand in TRUSTED_BRANDS:
            if brand in domain_without_tld:
                phishing_score -= 25
                break
    
    # ===== DOMAIN LENGTH =====
    if features['domain_length'] > 50:
        phishing_score -= 20
    elif features['domain_length'] > 35:
        phishing_score -= 10
    
    # ===== SPECIAL CHARACTERS =====
    if features['num_specials'] > 5:
        phishing_score -= 15
    elif features['num_specials'] > 3:
        phishing_score -= 8
    
    # ===== ENTROPY (RANDOMNESS) =====
    entropy = features.get('entropy', 0)
    if entropy > 4.0:
        phishing_score -= 20  # Very random-looking
    elif entropy > 3.5:
        phishing_score -= 10
    
    # ===== BRAND + SUSPICIOUS KEYWORD COMBO =====
    for brand in TRUSTED_BRANDS:
        if brand in domain_lower:
            # Check if it's NOT the legitimate domain
            legitimate_patterns = [f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.io"]
            if not any(domain_lower == pattern or domain_lower.endswith('.' + pattern) for pattern in legitimate_patterns):
                # Brand name in non-legitimate domain
                phishing_score = min(phishing_score, 35)
                
                # Brand + suspicious keyword = very bad
                if any(kw in domain_lower for kw in ['support', 'security', 'login', 'verify', 'account', 'update', 'secure']):
                    phishing_score = min(phishing_score, 20)
    
    # ===== COMMON PHISHING PATTERNS =====
    # Pattern: brand-keyword.tld (e.g., microsoft-support.xyz)
    if re.search(r'(microsoft|apple|google|amazon|paypal|netflix)[-.]?(support|security|login|verify|account)', domain_lower):
        if domain_lower not in KNOWN_LEGITIMATE_DOMAINS:
            phishing_score = min(phishing_score, 25)
    
    # Pattern: keyword-brand.tld (e.g., secure-paypal.com)
    if re.search(r'(secure|login|verify|account|update)[-.]?(microsoft|apple|google|amazon|paypal|netflix)', domain_lower):
        phishing_score = min(phishing_score, 25)
    
    # ===== FINAL SCORE NORMALIZATION =====
    phishing_score = max(0, min(100, phishing_score))
    
    # Extract flags
    flags = extract_flags(f"@{domain}")
    
    # Determine verdict based on threshold (60% or above)
    is_phishing = phishing_score >= 60
    
    # Calculate confidence
    confidence = round(phishing_score if is_phishing else (100 - phishing_score), 2)
    
    # Print debug info
    print(f"[DEBUG] Rule-based - Domain: {domain}, Score: {phishing_score:.2f}%, Verdict: {'phishing' if is_phishing else 'legitimate'}, Confidence: {confidence}%")
    
    base_result = {
        "verdict": "phishing" if is_phishing else "legitimate",
        "confidence": confidence,
        "flags": flags
    }
    
    # Enrich with threat intelligence
    try:
        from services.threat_intel import threat_intel_service
        return threat_intel_service.enrich_analysis(domain, base_result)
    except ImportError:
        return base_result
