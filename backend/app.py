from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import re

# Import directly from email_utils for domain-based analysis
from email_utils import predict_phishing, extract_flags

# Import new services
from services.email_auth import email_auth_service
from services.threat_attribution import threat_attribution_service
from services.org_dashboard import org_dashboard_service

# Init Flask app
app = Flask(__name__)
CORS(app)  

@app.route("/")
def home():
    return "Phishing Email Analyzer API is running."

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        email_address = data.get("email")
        department = data.get("department", "General")
        user = data.get("user", "Anonymous")
        
        # Check if we have an email address
        if not email_address:
            return jsonify({"error": "No email address provided"}), 400
            
        # Ensure the input is formatted as an email address if it's not already
        if '@' not in email_address:
            return jsonify({"error": "Invalid email format. Must include @ symbol"}), 400

        # Extract domain
        domain = email_address.split('@')[1] if '@' in email_address else email_address

        # Use the predict_phishing function directly for domain-based analysis
        result = predict_phishing(email_address)
        
        # Add email authentication analysis
        try:
            result['email_authentication'] = email_auth_service.get_full_auth_report(domain)
        except Exception as e:
            print(f"Email auth error: {e}")
            result['email_authentication'] = {'error': str(e)}
        
        # Add threat attribution analysis
        try:
            whois_data = result.get('threat_intel', {}).get('whois', {})
            result['threat_attribution'] = threat_attribution_service.get_full_attribution(domain, whois_data)
        except Exception as e:
            print(f"Threat attribution error: {e}")
            result['threat_attribution'] = {'error': str(e)}
        
        # Record analysis in dashboard
        try:
            org_dashboard_service.record_analysis(email_address, domain, result, department, user)
        except Exception as e:
            print(f"Dashboard recording error: {e}")
        
        # Return full result including all new data
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== EMAIL AUTHENTICATION ENDPOINTS ====================

@app.route("/auth/check", methods=["POST"])
def check_email_auth():
    """Check email authentication (SPF/DKIM/DMARC) for a domain"""
    try:
        data = request.get_json()
        domain = data.get("domain")
        
        if not domain:
            # Try to extract from email
            email = data.get("email", "")
            if '@' in email:
                domain = email.split('@')[1]
            else:
                return jsonify({"error": "No domain or email provided"}), 400
        
        result = email_auth_service.get_full_auth_report(domain)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== THREAT ATTRIBUTION ENDPOINTS ====================

@app.route("/attribution/analyze", methods=["POST"])
def analyze_attribution():
    """Get threat attribution analysis for a domain"""
    try:
        data = request.get_json()
        domain = data.get("domain")
        
        if not domain:
            email = data.get("email", "")
            if '@' in email:
                domain = email.split('@')[1]
            else:
                return jsonify({"error": "No domain or email provided"}), 400
        
        whois_data = data.get("whois_data", {})
        result = threat_attribution_service.get_full_attribution(domain, whois_data)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== ORGANIZATION DASHBOARD ENDPOINTS ====================

@app.route("/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    """Get organization dashboard statistics"""
    try:
        days = request.args.get("days", 30, type=int)
        stats = org_dashboard_service.get_dashboard_stats(days)
        return jsonify(stats)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/dashboard/history", methods=["GET"])
def get_analysis_history():
    """Get paginated analysis history"""
    try:
        limit = request.args.get("limit", 50, type=int)
        offset = request.args.get("offset", 0, type=int)
        verdict = request.args.get("verdict", None)
        
        history = org_dashboard_service.get_analysis_history(limit, offset, verdict)
        return jsonify(history)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/dashboard/timeline", methods=["GET"])
def get_threat_timeline():
    """Get threat timeline data"""
    try:
        days = request.args.get("days", 7, type=int)
        timeline = org_dashboard_service.get_threat_timeline(days)
        return jsonify({"timeline": timeline})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/dashboard/demo", methods=["POST"])
def add_demo_data():
    """Add demo data for testing"""
    try:
        result = org_dashboard_service.add_demo_data()
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/dashboard/clear", methods=["POST"])
def clear_dashboard():
    """Clear analysis history"""
    try:
        result = org_dashboard_service.clear_history()
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
