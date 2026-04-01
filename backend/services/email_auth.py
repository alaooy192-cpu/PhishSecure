"""
Email Authentication Service for PhishSecure
Checks SPF, DKIM, and DMARC records and explains them in plain English
"""

import dns.resolver
import re
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class AuthRecord:
    """Represents an email authentication record"""
    exists: bool
    raw_record: Optional[str]
    status: str  # 'pass', 'fail', 'partial', 'none'
    explanation: str
    technical_details: List[str]


class EmailAuthService:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def check_spf(self, domain: str) -> AuthRecord:
        """
        Check SPF (Sender Policy Framework) record
        SPF specifies which mail servers are allowed to send email for a domain
        """
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=spf1'):
                    # Parse SPF record
                    details = self._parse_spf(txt_record)
                    
                    # Determine status based on SPF policy
                    if '-all' in txt_record:
                        status = 'pass'
                        explanation = f"[PASS] {domain} has strict SPF protection. Only authorized servers can send emails from this domain."
                    elif '~all' in txt_record:
                        status = 'partial'
                        explanation = f"[WARNING] {domain} has SPF but with soft fail policy. Unauthorized emails may still be delivered."
                    elif '?all' in txt_record:
                        status = 'partial'
                        explanation = f"[WARNING] {domain} has SPF but with neutral policy. This provides weak protection."
                    elif '+all' in txt_record:
                        status = 'fail'
                        explanation = f"[FAIL] {domain} allows ANY server to send emails! This is a major security risk."
                    else:
                        status = 'partial'
                        explanation = f"[WARNING] {domain} has SPF but the policy is unclear."
                    
                    return AuthRecord(
                        exists=True,
                        raw_record=txt_record,
                        status=status,
                        explanation=explanation,
                        technical_details=details
                    )
            
            # No SPF record found
            return AuthRecord(
                exists=False,
                raw_record=None,
                status='none',
                explanation=f"[FAIL] {domain} has NO SPF record. Anyone can send emails pretending to be from this domain!",
                technical_details=["No SPF record found in DNS"]
            )
            
        except dns.resolver.NXDOMAIN:
            return AuthRecord(
                exists=False,
                raw_record=None,
                status='fail',
                explanation=f"[FAIL] Domain {domain} does not exist in DNS!",
                technical_details=["Domain not found (NXDOMAIN)"]
            )
        except dns.resolver.NoAnswer:
            return AuthRecord(
                exists=False,
                raw_record=None,
                status='none',
                explanation=f"[FAIL] {domain} has no SPF record configured.",
                technical_details=["No TXT records found"]
            )
        except Exception as e:
            return AuthRecord(
                exists=False,
                raw_record=None,
                status='fail',
                explanation=f"[WARNING] Could not check SPF for {domain}.",
                technical_details=[f"DNS lookup error: {str(e)}"]
            )
    
    def _parse_spf(self, spf_record: str) -> List[str]:
        """Parse SPF record into human-readable details"""
        details = []
        
        # Check for include mechanisms
        includes = re.findall(r'include:([^\s]+)', spf_record)
        if includes:
            details.append(f"Authorized senders: {', '.join(includes)}")
        
        # Check for IP addresses
        ip4s = re.findall(r'ip4:([^\s]+)', spf_record)
        if ip4s:
            details.append(f"Authorized IPv4: {', '.join(ip4s)}")
        
        ip6s = re.findall(r'ip6:([^\s]+)', spf_record)
        if ip6s:
            details.append(f"Authorized IPv6: {', '.join(ip6s)}")
        
        # Check for 'a' and 'mx' mechanisms
        if ' a ' in spf_record or spf_record.endswith(' a') or ' a:' in spf_record:
            details.append("Domain's A record IPs are authorized")
        
        if ' mx ' in spf_record or spf_record.endswith(' mx') or ' mx:' in spf_record:
            details.append("Domain's mail servers (MX) are authorized")
        
        # Policy
        if '-all' in spf_record:
            details.append("Policy: REJECT unauthorized senders (strict)")
        elif '~all' in spf_record:
            details.append("Policy: SOFTFAIL unauthorized senders (permissive)")
        elif '?all' in spf_record:
            details.append("Policy: NEUTRAL (no opinion on unauthorized)")
        elif '+all' in spf_record:
            details.append("Policy: ALLOW ALL (dangerous!)")
        
        return details
    
    def check_dmarc(self, domain: str) -> AuthRecord:
        """
        Check DMARC (Domain-based Message Authentication, Reporting & Conformance) record
        DMARC tells receiving servers what to do with emails that fail SPF/DKIM
        """
        dmarc_domain = f"_dmarc.{domain}"
        
        try:
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=DMARC1'):
                    details = self._parse_dmarc(txt_record)
                    
                    # Check policy
                    policy_match = re.search(r'p=(\w+)', txt_record)
                    policy = policy_match.group(1) if policy_match else 'none'
                    
                    if policy == 'reject':
                        status = 'pass'
                        explanation = f"[PASS] {domain} has strict DMARC. Emails failing authentication are REJECTED."
                    elif policy == 'quarantine':
                        status = 'partial'
                        explanation = f"[WARNING] {domain} has DMARC with quarantine policy. Suspicious emails go to spam."
                    else:  # none
                        status = 'partial'
                        explanation = f"[WARNING] {domain} has DMARC but only monitors - doesn't block fake emails."
                    
                    return AuthRecord(
                        exists=True,
                        raw_record=txt_record,
                        status=status,
                        explanation=explanation,
                        technical_details=details
                    )
            
            return AuthRecord(
                exists=False,
                raw_record=None,
                status='none',
                explanation=f"[FAIL] {domain} has NO DMARC policy. The domain owner has no control over spoofed emails.",
                technical_details=["No DMARC record found"]
            )
            
        except dns.resolver.NXDOMAIN:
            return AuthRecord(
                exists=False,
                raw_record=None,
                status='none',
                explanation=f"[FAIL] {domain} has no DMARC record configured.",
                technical_details=["DMARC subdomain not found"]
            )
        except dns.resolver.NoAnswer:
            return AuthRecord(
                exists=False,
                raw_record=None,
                status='none',
                explanation=f"[FAIL] {domain} has no DMARC policy.",
                technical_details=["No DMARC TXT record"]
            )
        except Exception as e:
            return AuthRecord(
                exists=False,
                raw_record=None,
                status='fail',
                explanation=f"[WARNING] Could not check DMARC for {domain}.",
                technical_details=[f"DNS lookup error: {str(e)}"]
            )
    
    def _parse_dmarc(self, dmarc_record: str) -> List[str]:
        """Parse DMARC record into human-readable details"""
        details = []
        
        # Policy
        policy_match = re.search(r'p=(\w+)', dmarc_record)
        if policy_match:
            policy = policy_match.group(1)
            policy_map = {
                'none': 'Monitor only (no action)',
                'quarantine': 'Send to spam folder',
                'reject': 'Reject/block email'
            }
            details.append(f"Policy: {policy_map.get(policy, policy)}")
        
        # Subdomain policy
        sp_match = re.search(r'sp=(\w+)', dmarc_record)
        if sp_match:
            details.append(f"Subdomain policy: {sp_match.group(1)}")
        
        # Percentage
        pct_match = re.search(r'pct=(\d+)', dmarc_record)
        if pct_match:
            details.append(f"Applied to {pct_match.group(1)}% of emails")
        
        # Reporting
        rua_match = re.search(r'rua=([^;\s]+)', dmarc_record)
        if rua_match:
            details.append("Aggregate reports enabled")
        
        ruf_match = re.search(r'ruf=([^;\s]+)', dmarc_record)
        if ruf_match:
            details.append("Forensic reports enabled")
        
        return details
    
    def check_dkim_selector(self, domain: str, selector: str = "default") -> AuthRecord:
        """
        Check DKIM (DomainKeys Identified Mail) record
        DKIM adds a digital signature to emails to verify they haven't been tampered with
        Note: DKIM requires knowing the selector, which varies by sender
        """
        # Common selectors to try
        selectors_to_try = [selector, "default", "google", "selector1", "selector2", "k1", "mail", "email"]
        
        for sel in selectors_to_try:
            dkim_domain = f"{sel}._domainkey.{domain}"
            
            try:
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                
                for rdata in answers:
                    txt_record = str(rdata).strip('"')
                    if 'v=DKIM1' in txt_record or 'k=rsa' in txt_record or 'p=' in txt_record:
                        details = self._parse_dkim(txt_record, sel)
                        
                        # Check if key is present
                        if 'p=' in txt_record:
                            key_match = re.search(r'p=([^;\s]+)', txt_record)
                            if key_match and key_match.group(1):
                                return AuthRecord(
                                    exists=True,
                                    raw_record=txt_record[:100] + "..." if len(txt_record) > 100 else txt_record,
                                    status='pass',
                                    explanation=f"[PASS] {domain} has DKIM configured (selector: {sel}). Emails are digitally signed.",
                                    technical_details=details
                                )
                        
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception:
                continue
        
        return AuthRecord(
            exists=False,
            raw_record=None,
            status='none',
            explanation=f"[WARNING] Could not find DKIM record for {domain}. This doesn't mean it's missing - DKIM selectors vary.",
            technical_details=["DKIM requires knowing the specific selector used by the sender", 
                             "Common selectors checked: " + ", ".join(selectors_to_try[:5])]
        )
    
    def _parse_dkim(self, dkim_record: str, selector: str) -> List[str]:
        """Parse DKIM record into human-readable details"""
        details = [f"Selector: {selector}"]
        
        # Key type
        if 'k=rsa' in dkim_record:
            details.append("Key type: RSA")
        elif 'k=ed25519' in dkim_record:
            details.append("Key type: Ed25519 (modern)")
        
        # Check for testing mode
        if 't=y' in dkim_record:
            details.append("[WARNING] Testing mode enabled")
        
        # Check key length (rough estimate from base64)
        key_match = re.search(r'p=([^;\s]+)', dkim_record)
        if key_match:
            key_len = len(key_match.group(1))
            if key_len > 300:
                details.append("Key strength: Strong (2048+ bit)")
            elif key_len > 150:
                details.append("Key strength: Standard (1024 bit)")
            else:
                details.append("[WARNING] Key strength: Weak")
        
        return details
    
    def check_mx(self, domain: str) -> Dict:
        """Check if domain has MX records (can receive email)"""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mx_records = []
            
            for rdata in answers:
                mx_records.append({
                    'priority': rdata.preference,
                    'host': str(rdata.exchange).rstrip('.')
                })
            
            mx_records.sort(key=lambda x: x['priority'])
            
            return {
                'exists': True,
                'records': mx_records,
                'explanation': f"[PASS] {domain} can receive emails via {len(mx_records)} mail server(s).",
                'primary_mx': mx_records[0]['host'] if mx_records else None
            }
            
        except dns.resolver.NXDOMAIN:
            return {
                'exists': False,
                'records': [],
                'explanation': f"[FAIL] Domain {domain} does not exist!",
                'primary_mx': None
            }
        except dns.resolver.NoAnswer:
            return {
                'exists': False,
                'records': [],
                'explanation': f"[WARNING] {domain} has no mail servers configured. It cannot receive emails.",
                'primary_mx': None
            }
        except Exception as e:
            return {
                'exists': False,
                'records': [],
                'explanation': f"[WARNING] Could not check MX records: {str(e)}",
                'primary_mx': None
            }
    
    def get_full_auth_report(self, domain: str) -> Dict:
        """
        Get a complete email authentication report for a domain
        """
        spf = self.check_spf(domain)
        dmarc = self.check_dmarc(domain)
        dkim = self.check_dkim_selector(domain)
        mx = self.check_mx(domain)
        
        # Calculate overall authentication score
        score = 0
        max_score = 100
        
        # SPF scoring (30 points)
        if spf.status == 'pass':
            score += 30
        elif spf.status == 'partial':
            score += 15
        
        # DMARC scoring (40 points)
        if dmarc.status == 'pass':
            score += 40
        elif dmarc.status == 'partial':
            score += 20
        
        # DKIM scoring (20 points)
        if dkim.status == 'pass':
            score += 20
        elif dkim.status == 'partial':
            score += 10
        
        # MX scoring (10 points)
        if mx['exists']:
            score += 10
        
        # Determine overall status
        if score >= 80:
            overall_status = 'strong'
            overall_explanation = f"[STRONG] {domain} has STRONG email authentication. Spoofing this domain is very difficult."
        elif score >= 50:
            overall_status = 'moderate'
            overall_explanation = f"[WARNING] {domain} has MODERATE email authentication. Some protections are in place but could be improved."
        elif score >= 20:
            overall_status = 'weak'
            overall_explanation = f"[WARNING] {domain} has WEAK email authentication. It's relatively easy to spoof emails from this domain."
        else:
            overall_status = 'none'
            overall_explanation = f"[FAIL] {domain} has NO email authentication. Anyone can easily send fake emails pretending to be from this domain!"
        
        # Generate plain English summary
        summary = self._generate_summary(domain, spf, dmarc, dkim, mx, score)
        
        return {
            'domain': domain,
            'overall_score': score,
            'overall_status': overall_status,
            'overall_explanation': overall_explanation,
            'summary': summary,
            'spf': {
                'exists': spf.exists,
                'status': spf.status,
                'explanation': spf.explanation,
                'technical_details': spf.technical_details,
                'raw_record': spf.raw_record
            },
            'dmarc': {
                'exists': dmarc.exists,
                'status': dmarc.status,
                'explanation': dmarc.explanation,
                'technical_details': dmarc.technical_details,
                'raw_record': dmarc.raw_record
            },
            'dkim': {
                'exists': dkim.exists,
                'status': dkim.status,
                'explanation': dkim.explanation,
                'technical_details': dkim.technical_details,
                'raw_record': dkim.raw_record
            },
            'mx': mx
        }
    
    def _generate_summary(self, domain: str, spf: AuthRecord, dmarc: AuthRecord, 
                         dkim: AuthRecord, mx: Dict, score: int) -> str:
        """Generate a plain English summary of the authentication status"""
        
        if score >= 80:
            return (f"{domain} is well-protected against email spoofing. "
                   f"It uses SPF to define authorized senders, DMARC to enforce policies, "
                   f"and DKIM to digitally sign emails. This makes it very hard for attackers "
                   f"to send fake emails pretending to be from this domain.")
        
        elif score >= 50:
            issues = []
            if spf.status != 'pass':
                issues.append("SPF could be stricter")
            if dmarc.status != 'pass':
                issues.append("DMARC policy could be stronger")
            if dkim.status != 'pass':
                issues.append("DKIM may not be fully configured")
            
            return (f"{domain} has some email authentication in place, but there are gaps. "
                   f"Issues: {', '.join(issues)}. "
                   f"An attacker might be able to send spoofed emails in some cases.")
        
        elif score >= 20:
            return (f"{domain} has minimal email authentication. "
                   f"Most email providers won't verify if an email actually came from this domain. "
                   f"Be cautious - it's relatively easy for attackers to impersonate this sender.")
        
        else:
            return (f"[WARNING] WARNING: {domain} has virtually no email authentication! "
                   f"This means ANYONE can send emails that appear to come from {domain}. "
                   f"Treat emails from this domain with extreme caution.")


# Singleton instance
email_auth_service = EmailAuthService()
