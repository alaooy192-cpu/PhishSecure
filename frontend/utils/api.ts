/**
 * Legacy API utilities - redirects to CTI API
 * Use cti-api.ts for new CTI functionality
 */

// Re-export CTI API functions for backward compatibility
export * from './cti-api';

// Legacy interfaces (deprecated)
export interface EmailAuthRecord {
  exists: boolean;
  status: 'pass' | 'partial' | 'fail' | 'none';
  explanation: string;
  technical_details: string[];
  raw_record?: string;
}

export interface EmailAuthentication {
  domain: string;
  overall_score: number;
  overall_status: 'strong' | 'moderate' | 'weak' | 'none';
  overall_explanation: string;
  summary: string;
  spf: EmailAuthRecord;
  dmarc: EmailAuthRecord;
  dkim: EmailAuthRecord;
  mx: {
    exists: boolean;
    records: Array<{ priority: number; host: string }>;
    explanation: string;
    primary_mx?: string;
  };
  error?: string;
}

export interface PhishingKitMatch {
  kit_name: string;
  description: string;
  match_score: number;
  matched_indicators: string[];
  typical_targets: string[];
  threat_level: string;
  ttps: string[];
  first_seen: string;
}

export interface ThreatAttribution {
  domain: string;
  attribution_confidence: 'high' | 'medium' | 'low' | 'minimal';
  confidence_score: number;
  summary: string;
  indicators: string[];
  phishing_kit: {
    matches: PhishingKitMatch[];
    has_kit_match: boolean;
    highest_match?: PhishingKitMatch;
  };
  registrar_analysis: {
    risk_level: string;
    explanation: string;
    registrar?: string;
    indicator?: string;
  };
  tld_analysis: {
    tld: string;
    risk_level: string;
    explanation: string;
    recommendation?: string;
  };
  geographic_origin: {
    likely_regions: string[];
    indicators: string[];
    geo_risk: string;
    bulletproof_hosting_likely: boolean;
  };
  attack_patterns: {
    patterns: Array<{
      type: string;
      description: string;
      keywords?: string[];
      brand?: string;
    }>;
    pattern_count: number;
    primary_attack_type?: string;
  };
  timestamp: string;
  error?: string;
}

export interface AnalysisResult {
  verdict: 'phishing' | 'legitimate' | 'error';
  confidence: number; // 0-100
  flags: string[];
  threat_intel?: {
    virustotal: {
      success: boolean;
      malicious_count?: number;
      suspicious_count?: number;
      total_engines?: number;
      threat_percentage?: number;
      error?: string;
    };
    whois: {
      success: boolean;
      age_days?: number;
      creation_date?: string;
      registrar?: string;
      error?: string;
    };
    threat_status: 'clear' | 'monitor' | 'suspicious' | 'active_campaign' | 'critical';
    campaign_likelihood: 'low' | 'medium' | 'high' | 'very_high';
    threat_indicators: string[];
    risk_level: 'minimal' | 'low' | 'medium' | 'high' | 'critical';
    last_checked: string;
  };
  business_context?: {
    organizational_impact: 'low' | 'medium' | 'high';
    recommended_actions: string[];
    threat_timeline: 'unknown' | 'recent' | 'active';
    global_context: 'local' | 'emerging_threat' | 'known_threat';
  };
  email_authentication?: EmailAuthentication;
  threat_attribution?: ThreatAttribution;
}

export interface DashboardStats {
  period_days: number;
  total_analyses: number;
  phishing_detected: number;
  legitimate_emails: number;
  phishing_rate: number;
  threat_score: number;
  threat_level: 'minimal' | 'low' | 'medium' | 'high' | 'critical';
  risk_distribution: Record<string, number>;
  threat_status_distribution: Record<string, number>;
  department_breakdown: Array<{
    department: string;
    total_analyses: number;
    phishing_attempts: number;
    risk_percentage: number;
  }>;
  top_threats: Array<{
    domain: string;
    attempts: number;
  }>;
  phishing_kit_distribution: Record<string, number>;
  geographic_distribution: Record<string, number>;
  daily_trend: Array<{
    date: string;
    total: number;
    phishing: number;
  }>;
  recent_critical: Array<{
    id: number;
    timestamp: string;
    email: string;
    domain: string;
    verdict: string;
    risk_level: string;
    department: string;
  }>;
  summary: string;
}

/**
 * Analyzes an email for phishing indicators
 * @param emailContent The email address to analyze
 * @returns Analysis result with verdict, confidence score, and flags
 */
export const analyzeEmail = async (emailContent: string): Promise<AnalysisResult> => {
  try {
    // Replace with your actual backend URL when deployed
    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:5000';
    
    const response = await fetch(`${backendUrl}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email: emailContent }),
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();
    return {
      verdict: data.verdict || 'legitimate',
      confidence: data.confidence || 0,
      flags: data.flags || [],
      threat_intel: data.threat_intel,
      business_context: data.business_context,
      email_authentication: data.email_authentication,
      threat_attribution: data.threat_attribution
    };
  } catch (error) {
    console.error('Error analyzing email:', error);
    
    // Mock response when backend is unavailable
    const domain = emailContent.split('@')[1]?.toLowerCase() || '';
    const suspiciousDomains = ['tempmail', 'guerrillamail', '10minutemail', 'mailinator'];
    const isPhishing = suspiciousDomains.some(sus => domain.includes(sus)) || 
                      domain.includes('phish') || 
                      domain.length > 20;
    
    return {
      verdict: isPhishing ? 'phishing' : 'legitimate',
      confidence: isPhishing ? 85 : 75,
      flags: isPhishing ? ['Suspicious domain detected', 'Known temporary email service'] : ['Domain appears legitimate']
    };
  }
};

/**
 * Fetch dashboard statistics
 */
export const fetchDashboardStats = async (days: number = 30): Promise<DashboardStats> => {
  const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:5000';
  
  const response = await fetch(`${backendUrl}/dashboard/stats?days=${days}`);
  
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  
  return response.json();
};

/**
 * Add demo data for testing
 */
export const addDemoData = async (): Promise<{ status: string; message: string }> => {
  const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:5000';
  
  const response = await fetch(`${backendUrl}/dashboard/demo`, {
    method: 'POST'
  });
  
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  
  return response.json();
};

/**
 * Clear dashboard history
 */
export const clearDashboardHistory = async (): Promise<{ status: string; message: string }> => {
  const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:5000';
  
  const response = await fetch(`${backendUrl}/dashboard/clear`, {
    method: 'POST'
  });
  
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  
  return response.json();
};