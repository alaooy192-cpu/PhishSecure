"""
Organization Dashboard Service for PhishSecure
Tracks analysis history and provides aggregate threat statistics
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict
import threading


class OrganizationDashboardService:
    def __init__(self, data_file: str = None):
        # Use a JSON file for persistence (simple approach, no database needed)
        self.data_file = data_file or os.path.join(
            os.path.dirname(__file__), '..', 'data', 'analysis_history.json'
        )
        self._ensure_data_dir()
        self._lock = threading.Lock()
        self._load_data()
    
    def _ensure_data_dir(self):
        """Ensure data directory exists"""
        data_dir = os.path.dirname(self.data_file)
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
    
    def _load_data(self):
        """Load analysis history from file"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as f:
                    self.data = json.load(f)
            else:
                self.data = {
                    'analyses': [],
                    'organization': {
                        'name': 'My Organization',
                        'created_at': datetime.now().isoformat()
                    }
                }
                self._save_data()
        except Exception as e:
            print(f"Error loading data: {e}")
            self.data = {'analyses': [], 'organization': {'name': 'My Organization'}}
    
    def _save_data(self):
        """Save analysis history to file"""
        try:
            with self._lock:
                with open(self.data_file, 'w') as f:
                    json.dump(self.data, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving data: {e}")
    
    def record_analysis(self, email: str, domain: str, result: Dict, 
                       department: Optional[str] = None, user: Optional[str] = None) -> Dict:
        """Record a new analysis in the history"""
        analysis_record = {
            'id': len(self.data['analyses']) + 1,
            'timestamp': datetime.now().isoformat(),
            'email': email,
            'domain': domain,
            'verdict': result.get('verdict', 'unknown'),
            'confidence': result.get('confidence', 0),
            'risk_level': result.get('threat_intel', {}).get('risk_level', 'unknown'),
            'threat_status': result.get('threat_intel', {}).get('threat_status', 'unknown'),
            'flags_count': len(result.get('flags', [])),
            'department': department or 'General',
            'user': user or 'Anonymous',
            'phishing_kit': None,
            'geographic_origin': None
        }
        
        # Add attribution data if available
        if 'threat_attribution' in result:
            attr = result['threat_attribution']
            if attr.get('phishing_kit', {}).get('has_kit_match'):
                analysis_record['phishing_kit'] = attr['phishing_kit']['highest_match']['kit_name']
            if attr.get('geographic_origin', {}).get('likely_regions'):
                analysis_record['geographic_origin'] = attr['geographic_origin']['likely_regions']
        
        self.data['analyses'].append(analysis_record)
        self._save_data()
        
        return analysis_record
    
    def get_dashboard_stats(self, days: int = 30) -> Dict:
        """Get aggregate statistics for the dashboard"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        # Filter analyses within the time period
        recent_analyses = [
            a for a in self.data['analyses']
            if datetime.fromisoformat(a['timestamp']) > cutoff_date
        ]
        
        total_analyses = len(recent_analyses)
        
        if total_analyses == 0:
            return self._empty_stats(days)
        
        # Calculate statistics
        phishing_count = sum(1 for a in recent_analyses if a['verdict'] == 'phishing')
        legitimate_count = sum(1 for a in recent_analyses if a['verdict'] == 'legitimate')
        
        # Risk level distribution
        risk_distribution = defaultdict(int)
        for a in recent_analyses:
            risk_distribution[a.get('risk_level', 'unknown')] += 1
        
        # Threat status distribution
        threat_distribution = defaultdict(int)
        for a in recent_analyses:
            threat_distribution[a.get('threat_status', 'unknown')] += 1
        
        # Department breakdown
        department_stats = defaultdict(lambda: {'total': 0, 'phishing': 0})
        for a in recent_analyses:
            dept = a.get('department', 'General')
            department_stats[dept]['total'] += 1
            if a['verdict'] == 'phishing':
                department_stats[dept]['phishing'] += 1
        
        # Most targeted departments
        dept_risk = [
            {
                'department': dept,
                'total_analyses': stats['total'],
                'phishing_attempts': stats['phishing'],
                'risk_percentage': round((stats['phishing'] / stats['total']) * 100, 1) if stats['total'] > 0 else 0
            }
            for dept, stats in department_stats.items()
        ]
        dept_risk.sort(key=lambda x: x['phishing_attempts'], reverse=True)
        
        # Top threats (domains)
        domain_threats = defaultdict(lambda: {'count': 0, 'verdict': 'legitimate'})
        for a in recent_analyses:
            if a['verdict'] == 'phishing':
                domain_threats[a['domain']]['count'] += 1
                domain_threats[a['domain']]['verdict'] = 'phishing'
        
        top_threats = [
            {'domain': domain, 'attempts': data['count']}
            for domain, data in domain_threats.items()
        ]
        top_threats.sort(key=lambda x: x['attempts'], reverse=True)
        
        # Phishing kit distribution
        kit_distribution = defaultdict(int)
        for a in recent_analyses:
            if a.get('phishing_kit'):
                kit_distribution[a['phishing_kit']] += 1
        
        # Geographic distribution
        geo_distribution = defaultdict(int)
        for a in recent_analyses:
            if a.get('geographic_origin'):
                for region in a['geographic_origin']:
                    geo_distribution[region] += 1
        
        # Daily trend
        daily_trend = defaultdict(lambda: {'total': 0, 'phishing': 0})
        for a in recent_analyses:
            date = datetime.fromisoformat(a['timestamp']).strftime('%Y-%m-%d')
            daily_trend[date]['total'] += 1
            if a['verdict'] == 'phishing':
                daily_trend[date]['phishing'] += 1
        
        # Sort daily trend by date
        sorted_trend = [
            {'date': date, **stats}
            for date, stats in sorted(daily_trend.items())
        ]
        
        # Calculate threat score (0-100)
        threat_score = self._calculate_threat_score(recent_analyses)
        
        return {
            'period_days': days,
            'total_analyses': total_analyses,
            'phishing_detected': phishing_count,
            'legitimate_emails': legitimate_count,
            'phishing_rate': round((phishing_count / total_analyses) * 100, 1) if total_analyses > 0 else 0,
            'threat_score': threat_score,
            'threat_level': self._get_threat_level(threat_score),
            'risk_distribution': dict(risk_distribution),
            'threat_status_distribution': dict(threat_distribution),
            'department_breakdown': dept_risk[:10],  # Top 10 departments
            'top_threats': top_threats[:10],  # Top 10 threat domains
            'phishing_kit_distribution': dict(kit_distribution),
            'geographic_distribution': dict(geo_distribution),
            'daily_trend': sorted_trend[-30:],  # Last 30 days
            'recent_critical': self._get_recent_critical(recent_analyses),
            'summary': self._generate_summary(total_analyses, phishing_count, threat_score, dept_risk)
        }
    
    def _empty_stats(self, days: int) -> Dict:
        """Return empty stats structure"""
        return {
            'period_days': days,
            'total_analyses': 0,
            'phishing_detected': 0,
            'legitimate_emails': 0,
            'phishing_rate': 0,
            'threat_score': 0,
            'threat_level': 'minimal',
            'risk_distribution': {},
            'threat_status_distribution': {},
            'department_breakdown': [],
            'top_threats': [],
            'phishing_kit_distribution': {},
            'geographic_distribution': {},
            'daily_trend': [],
            'recent_critical': [],
            'summary': 'No analyses recorded yet. Start analyzing emails to see statistics.'
        }
    
    def _calculate_threat_score(self, analyses: List[Dict]) -> int:
        """Calculate overall threat score (0-100)"""
        if not analyses:
            return 0
        
        score = 0
        
        # Factor 1: Phishing rate (up to 40 points)
        phishing_count = sum(1 for a in analyses if a['verdict'] == 'phishing')
        phishing_rate = phishing_count / len(analyses)
        score += min(phishing_rate * 100, 40)
        
        # Factor 2: Critical/high risk analyses (up to 30 points)
        critical_count = sum(1 for a in analyses if a.get('risk_level') in ['critical', 'high'])
        critical_rate = critical_count / len(analyses)
        score += min(critical_rate * 75, 30)
        
        # Factor 3: Active campaigns detected (up to 20 points)
        campaign_count = sum(1 for a in analyses if a.get('threat_status') in ['active_campaign', 'critical'])
        campaign_rate = campaign_count / len(analyses)
        score += min(campaign_rate * 100, 20)
        
        # Factor 4: Trend (up to 10 points) - more recent phishing = higher score
        recent = analyses[-10:] if len(analyses) >= 10 else analyses
        recent_phishing = sum(1 for a in recent if a['verdict'] == 'phishing')
        recent_rate = recent_phishing / len(recent)
        score += min(recent_rate * 25, 10)
        
        return min(round(score), 100)
    
    def _get_threat_level(self, score: int) -> str:
        """Convert threat score to threat level"""
        if score >= 75:
            return 'critical'
        elif score >= 50:
            return 'high'
        elif score >= 25:
            return 'medium'
        elif score >= 10:
            return 'low'
        else:
            return 'minimal'
    
    def _get_recent_critical(self, analyses: List[Dict], limit: int = 5) -> List[Dict]:
        """Get most recent critical/high-risk analyses"""
        critical = [
            a for a in analyses 
            if a.get('risk_level') in ['critical', 'high'] or a.get('threat_status') in ['critical', 'active_campaign']
        ]
        critical.sort(key=lambda x: x['timestamp'], reverse=True)
        return critical[:limit]
    
    def _generate_summary(self, total: int, phishing: int, threat_score: int, 
                         dept_risk: List[Dict]) -> str:
        """Generate human-readable summary"""
        if total == 0:
            return "No email analyses recorded in this period."
        
        summary_parts = []
        
        # Overall stats
        summary_parts.append(f"Your organization analyzed {total} emails, detecting {phishing} phishing attempts.")
        
        # Threat level
        if threat_score >= 75:
            summary_parts.append("CRITICAL: Your organization is under active attack. Immediate action required.")
        elif threat_score >= 50:
            summary_parts.append("HIGH ALERT: Significant phishing activity detected. Review security measures.")
        elif threat_score >= 25:
            summary_parts.append("Moderate threat level. Continue monitoring and maintain security awareness.")
        else:
            summary_parts.append("Low threat level. Security posture appears healthy.")
        
        # Most targeted department
        if dept_risk and dept_risk[0]['phishing_attempts'] > 0:
            top_dept = dept_risk[0]
            summary_parts.append(
                f"Most targeted: {top_dept['department']} department with {top_dept['phishing_attempts']} phishing attempts."
            )
        
        return " ".join(summary_parts)
    
    def get_analysis_history(self, limit: int = 50, offset: int = 0, 
                            verdict_filter: Optional[str] = None) -> Dict:
        """Get paginated analysis history"""
        analyses = self.data['analyses']
        
        # Apply filter
        if verdict_filter:
            analyses = [a for a in analyses if a['verdict'] == verdict_filter]
        
        # Sort by timestamp (newest first)
        analyses = sorted(analyses, key=lambda x: x['timestamp'], reverse=True)
        
        # Paginate
        total = len(analyses)
        paginated = analyses[offset:offset + limit]
        
        return {
            'total': total,
            'limit': limit,
            'offset': offset,
            'has_more': offset + limit < total,
            'analyses': paginated
        }
    
    def get_threat_timeline(self, days: int = 7) -> List[Dict]:
        """Get hourly threat timeline for the specified days"""
        cutoff = datetime.now() - timedelta(days=days)
        
        timeline = defaultdict(lambda: {'total': 0, 'phishing': 0, 'critical': 0})
        
        for a in self.data['analyses']:
            ts = datetime.fromisoformat(a['timestamp'])
            if ts > cutoff:
                hour_key = ts.strftime('%Y-%m-%d %H:00')
                timeline[hour_key]['total'] += 1
                if a['verdict'] == 'phishing':
                    timeline[hour_key]['phishing'] += 1
                if a.get('risk_level') in ['critical', 'high']:
                    timeline[hour_key]['critical'] += 1
        
        return [
            {'timestamp': ts, **data}
            for ts, data in sorted(timeline.items())
        ]
    
    def clear_history(self) -> Dict:
        """Clear all analysis history (for testing/reset)"""
        self.data['analyses'] = []
        self._save_data()
        return {'status': 'success', 'message': 'Analysis history cleared'}
    
    def add_demo_data(self) -> Dict:
        """Add demo data for testing the dashboard"""
        import random
        
        departments = ['Finance', 'HR', 'IT', 'Sales', 'Marketing', 'Executive', 'Operations']
        domains_legitimate = ['google.com', 'microsoft.com', 'amazon.com', 'linkedin.com', 'github.com']
        domains_phishing = [
            'paypa1-secure.com', 'microsoft-verify.xyz', 'amazon-alert.tk',
            'google-security.ml', 'apple-id-verify.cf', 'netflix-update.gq',
            'bank-secure-login.top', 'account-verify.buzz', 'urgent-action.icu'
        ]
        kits = ['LogoKit', 'Kr3pto', 'EvilProxy', 'Caffeine', '16Shop', None, None]
        regions = [['Russia'], ['China'], ['Nigeria'], ['Romania'], None, None]
        
        # Generate 50 demo analyses over the past 30 days
        for i in range(50):
            days_ago = random.randint(0, 30)
            hours_ago = random.randint(0, 23)
            timestamp = datetime.now() - timedelta(days=days_ago, hours=hours_ago)
            
            is_phishing = random.random() < 0.35  # 35% phishing rate
            
            if is_phishing:
                domain = random.choice(domains_phishing)
                verdict = 'phishing'
                confidence = random.randint(65, 95)
                risk_level = random.choice(['high', 'critical', 'medium'])
                threat_status = random.choice(['active_campaign', 'suspicious', 'critical'])
            else:
                domain = random.choice(domains_legitimate)
                verdict = 'legitimate'
                confidence = random.randint(70, 98)
                risk_level = random.choice(['minimal', 'low'])
                threat_status = 'clear'
            
            analysis = {
                'id': len(self.data['analyses']) + 1,
                'timestamp': timestamp.isoformat(),
                'email': f"user@{domain}",
                'domain': domain,
                'verdict': verdict,
                'confidence': confidence,
                'risk_level': risk_level,
                'threat_status': threat_status,
                'flags_count': random.randint(0, 5) if is_phishing else 0,
                'department': random.choice(departments),
                'user': f"user{random.randint(1, 20)}",
                'phishing_kit': random.choice(kits) if is_phishing else None,
                'geographic_origin': random.choice(regions) if is_phishing else None
            }
            
            self.data['analyses'].append(analysis)
        
        self._save_data()
        return {'status': 'success', 'message': f'Added 50 demo analyses', 'total': len(self.data['analyses'])}


# Singleton instance
org_dashboard_service = OrganizationDashboardService()
