"""
Threat Intelligence Collection Service
Collects phishing indicators from public sources like URLhaus, PhishTank, etc.
"""

import requests
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import time
import logging
from urllib.parse import urlparse

class ThreatCollector:
    def __init__(self, db_path: str = "phishsecure.db"):
        self.db_path = db_path
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PhishSecure-Bahrain-CTI/1.0'
        })
        
        # Configure logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Rate limiting
        self.last_request_time = {}
        self.min_request_interval = 2  # seconds between requests

    def collect_from_urlhaus(self, limit: int = 100) -> List[Dict]:
        """
        Collect recent malicious URLs from URLhaus
        Free API, no key required
        """
        self.logger.info("Collecting threats from URLhaus...")
        
        try:
            # Rate limiting
            self._rate_limit('urlhaus')
            
            # Get recent URLs (last 3 days)
            url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            data = {"days": 3}
            
            response = self.session.post(url, data=data, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            
            if result.get('query_status') != 'ok':
                self.logger.error(f"URLhaus API error: {result}")
                return []
            
            urls = result.get('urls', [])[:limit]
            
            # Process and normalize the data
            indicators = []
            for url_data in urls:
                try:
                    indicator = self._process_urlhaus_entry(url_data)
                    if indicator:
                        indicators.append(indicator)
                except Exception as e:
                    self.logger.error(f"Error processing URLhaus entry: {e}")
                    continue
            
            self.logger.info(f"Collected {len(indicators)} indicators from URLhaus")
            return indicators
            
        except Exception as e:
            self.logger.error(f"Error collecting from URLhaus: {e}")
            return []

    def collect_from_phishtank(self, limit: int = 50) -> List[Dict]:
        """
        Collect from PhishTank (requires free API key)
        Note: This is a demo implementation - you'd need to register for an API key
        """
        self.logger.info("Collecting threats from PhishTank...")
        
        try:
            # Rate limiting
            self._rate_limit('phishtank')
            
            # PhishTank API endpoint (requires API key)
            # For demo purposes, we'll simulate this or use their public data
            url = "http://data.phishtank.com/data/online-valid.json"
            
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Process limited number of entries
            indicators = []
            for entry in data[:limit]:
                try:
                    indicator = self._process_phishtank_entry(entry)
                    if indicator:
                        indicators.append(indicator)
                except Exception as e:
                    self.logger.error(f"Error processing PhishTank entry: {e}")
                    continue
            
            self.logger.info(f"Collected {len(indicators)} indicators from PhishTank")
            return indicators
            
        except Exception as e:
            self.logger.error(f"Error collecting from PhishTank: {e}")
            return []

    def collect_demo_data(self) -> List[Dict]:
        """
        Generate demo threat data for testing
        This ensures the system works even without live API access
        """
        self.logger.info("Generating demo threat data...")
        
        demo_indicators = [
            {
                'indicator_type': 'domain',
                'indicator_value': 'benefit-pay.tk',
                'source': 'demo',
                'threat_score': 85,
                'first_seen': datetime.now() - timedelta(hours=2),
                'tags': ['phishing', 'banking', 'bahrain']
            },
            {
                'indicator_type': 'url',
                'indicator_value': 'http://batelco-login.info/secure/login.php',
                'source': 'demo',
                'threat_score': 78,
                'first_seen': datetime.now() - timedelta(hours=5),
                'tags': ['phishing', 'telecom', 'credential-theft']
            },
            {
                'indicator_type': 'domain',
                'indicator_value': 'nbb-online-banking.ru',
                'source': 'demo',
                'threat_score': 92,
                'first_seen': datetime.now() - timedelta(hours=1),
                'tags': ['phishing', 'banking', 'high-confidence']
            },
            {
                'indicator_type': 'domain',
                'indicator_value': 'bahrain-government.ml',
                'source': 'demo',
                'threat_score': 88,
                'first_seen': datetime.now() - timedelta(minutes=30),
                'tags': ['phishing', 'government', 'impersonation']
            },
            {
                'indicator_type': 'url',
                'indicator_value': 'https://stc-bh.tk/payment/verify',
                'source': 'demo',
                'threat_score': 81,
                'first_seen': datetime.now() - timedelta(hours=3),
                'tags': ['phishing', 'telecom', 'payment-fraud']
            }
        ]
        
        return demo_indicators

    def store_indicators(self, indicators: List[Dict]) -> int:
        """
        Store collected indicators in the database
        Returns number of new indicators stored
        """
        if not indicators:
            return 0
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            new_count = 0
            
            for indicator in indicators:
                try:
                    # Check if indicator already exists
                    cursor.execute(
                        "SELECT id FROM threat_indicators WHERE indicator_value = ?",
                        (indicator['indicator_value'],)
                    )
                    
                    if cursor.fetchone():
                        # Update existing indicator
                        cursor.execute("""
                            UPDATE threat_indicators 
                            SET last_updated = ?, threat_score = ?, tags = ?
                            WHERE indicator_value = ?
                        """, (
                            datetime.now(),
                            indicator.get('threat_score', 0),
                            json.dumps(indicator.get('tags', [])),
                            indicator['indicator_value']
                        ))
                    else:
                        # Insert new indicator
                        cursor.execute("""
                            INSERT INTO threat_indicators 
                            (indicator_type, indicator_value, first_seen, source, threat_score, tags)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            indicator['indicator_type'],
                            indicator['indicator_value'],
                            indicator.get('first_seen', datetime.now()),
                            indicator['source'],
                            indicator.get('threat_score', 0),
                            json.dumps(indicator.get('tags', []))
                        ))
                        new_count += 1
                        
                except Exception as e:
                    self.logger.error(f"Error storing indicator {indicator['indicator_value']}: {e}")
                    continue
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Stored {new_count} new indicators")
            return new_count
            
        except Exception as e:
            self.logger.error(f"Database error: {e}")
            return 0

    def run_collection_cycle(self, use_demo: bool = False) -> Dict:
        """
        Run a complete collection cycle from all sources
        """
        self.logger.info("Starting threat collection cycle...")
        
        all_indicators = []
        sources_used = []
        
        if use_demo:
            # Use demo data for reliable testing
            demo_data = self.collect_demo_data()
            all_indicators.extend(demo_data)
            sources_used.append('demo')
        else:
            # Collect from real sources
            try:
                urlhaus_data = self.collect_from_urlhaus(limit=50)
                all_indicators.extend(urlhaus_data)
                sources_used.append('urlhaus')
            except Exception as e:
                self.logger.error(f"URLhaus collection failed: {e}")
            
            try:
                # PhishTank collection (commented out as it requires API key)
                # phishtank_data = self.collect_from_phishtank(limit=25)
                # all_indicators.extend(phishtank_data)
                # sources_used.append('phishtank')
                pass
            except Exception as e:
                self.logger.error(f"PhishTank collection failed: {e}")
        
        # Store all collected indicators
        new_count = self.store_indicators(all_indicators)
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'sources_used': sources_used,
            'total_collected': len(all_indicators),
            'new_indicators': new_count,
            'status': 'success'
        }
        
        self.logger.info(f"Collection cycle complete: {result}")
        return result

    def _process_urlhaus_entry(self, entry: Dict) -> Optional[Dict]:
        """Process a single URLhaus entry into our format"""
        try:
            url = entry.get('url', '')
            if not url:
                return None
            
            # Extract domain from URL
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Determine indicator type
            indicator_type = 'url' if len(url) > len(domain) + 10 else 'domain'
            indicator_value = url if indicator_type == 'url' else domain
            
            # Calculate basic threat score based on URLhaus data
            threat_score = 70  # Base score for URLhaus entries
            
            # Adjust based on threat type
            threat_type = entry.get('threat', '').lower()
            if 'malware' in threat_type:
                threat_score += 10
            if 'phishing' in threat_type:
                threat_score += 15
            
            # Parse date
            date_added = entry.get('date_added')
            first_seen = datetime.fromisoformat(date_added.replace('Z', '+00:00')) if date_added else datetime.now()
            
            return {
                'indicator_type': indicator_type,
                'indicator_value': indicator_value,
                'source': 'urlhaus',
                'threat_score': min(100, threat_score),
                'first_seen': first_seen,
                'tags': ['phishing', threat_type] if threat_type else ['phishing']
            }
            
        except Exception as e:
            self.logger.error(f"Error processing URLhaus entry: {e}")
            return None

    def _process_phishtank_entry(self, entry: Dict) -> Optional[Dict]:
        """Process a single PhishTank entry into our format"""
        try:
            url = entry.get('url', '')
            if not url:
                return None
            
            # Extract domain
            parsed = urlparse(url)
            domain = parsed.netloc
            
            return {
                'indicator_type': 'url',
                'indicator_value': url,
                'source': 'phishtank',
                'threat_score': 75,  # PhishTank entries are generally high confidence
                'first_seen': datetime.now(),
                'tags': ['phishing', 'verified']
            }
            
        except Exception as e:
            self.logger.error(f"Error processing PhishTank entry: {e}")
            return None

    def _rate_limit(self, source: str):
        """Simple rate limiting to be respectful to APIs"""
        now = time.time()
        last_request = self.last_request_time.get(source, 0)
        
        time_since_last = now - last_request
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time[source] = time.time()


# Scheduler for automated collection
class ThreatCollectionScheduler:
    def __init__(self, collector: ThreatCollector):
        self.collector = collector
        self.logger = logging.getLogger(__name__)

    def schedule_collection(self, interval_hours: int = 6, use_demo: bool = False):
        """
        Schedule regular threat collection
        For production, you'd use APScheduler or similar
        """
        self.logger.info(f"Scheduling collection every {interval_hours} hours")
        
        # For demo purposes, just run once
        result = self.collector.run_collection_cycle(use_demo=use_demo)
        return result


# Example usage
if __name__ == "__main__":
    collector = ThreatCollector()
    
    # Run collection with demo data
    result = collector.run_collection_cycle(use_demo=True)
    print(f"Collection result: {result}")
