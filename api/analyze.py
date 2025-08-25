from http.server import BaseHTTPRequestHandler
import json
import re

def extract_domain_features(domain):
    suffix = domain.split('.')[-1]
    num_digits = sum(c.isdigit() for c in domain)
    num_specials = domain.count('-') + domain.count('.')
    domain_length = len(domain)
    
    trusted_brands = ['paypal', 'netflix', 'apple', 'microsoft', 'amazon', 'google', 'facebook']
    stripped = re.sub(r'\d', '', domain.lower())
    typosquat = int(any(brand in domain.lower() and brand not in stripped for brand in trusted_brands))
    
    return {
        'num_digits': num_digits,
        'num_specials': num_specials,
        'domain_length': domain_length,
        'typosquat': typosquat,
        'suffix': suffix
    }

def extract_flags(email_content):
    flags = []
    email_match = re.search(r'[\w\.-]+@([\w\.-]+)', email_content)
    
    if email_match:
        domain = email_match.group(1)
        features = extract_domain_features(domain)
        
        suspicious_tlds = ['tk', 'xyz', 'cn', 'ru', 'top', 'gq', 'ml', 'cf', 'biz']
        if features['suffix'] in suspicious_tlds:
            flags.append(f"Suspicious TLD: .{features['suffix']}")
        
        if features['num_digits'] > 4:
            flags.append("Domain contains excessive digits")
        
        domain_without_tld = domain.rsplit('.', 1)[0] if '.' in domain else domain
        if any(char.isdigit() for char in domain_without_tld):
            flags.append("Domain contains numbers (potential phishing indicator)")
        
        if features['typosquat'] == 1:
            flags.append("Possible typosquatting of trusted brand")
        
        if features['domain_length'] > 30:
            flags.append("Unusually long domain name")
    
    return flags

def predict_phishing_simple(email_content):
    email_match = re.search(r'[\w\.-]+@([\w\.-]+)', email_content)
    
    if not email_match:
        return {
            "verdict": "error",
            "confidence": 0,
            "flags": ["No valid email address found"]
        }
    
    domain = email_match.group(1)
    features = extract_domain_features(domain)
    
    phishing_score = 70
    
    known_legitimate = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'github.com']
    if domain.lower() in known_legitimate:
        phishing_score = 90
    
    domain_without_tld = domain.rsplit('.', 1)[0] if '.' in domain else domain
    popular_brands = ['paypal', 'microsoft', 'apple', 'amazon', 'google', 'facebook']
    for brand in popular_brands:
        if brand in domain_without_tld.lower() and any(char.isdigit() for char in domain_without_tld):
            phishing_score = 30
            break
    
    high_risk_tlds = ['tk', 'gq', 'ml', 'cf']
    if features['suffix'] in high_risk_tlds:
        phishing_score -= 30
    
    if any(char.isdigit() for char in domain_without_tld):
        phishing_score -= 25
    
    phishing_score = max(10, min(90, phishing_score))
    
    is_phishing = phishing_score <= 60
    flags = extract_flags(email_content)
    confidence = round(100 - phishing_score if is_phishing else phishing_score, 2)
    
    return {
        "verdict": "phishing" if is_phishing else "legitimate",
        "confidence": confidence,
        "flags": flags
    }

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
            
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            email = data.get('email')
            if not email:
                self.wfile.write(json.dumps({"error": "No email address provided"}).encode())
                return
            
            if '@' not in email:
                self.wfile.write(json.dumps({"error": "Invalid email format"}).encode())
                return
            
            result = predict_phishing_simple(email)
            self.wfile.write(json.dumps(result).encode())
            
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps({"status": "API is running"}).encode())
