/**
 * CTI API utilities for PhishSecure Bahrain
 * Handles communication with the CTI backend
 */

const CTI_API_BASE = process.env.NEXT_PUBLIC_CTI_API_URL || 'http://localhost:5000';

// Types
export interface CTIDashboardStats {
  period_days: number;
  total_indicators: number;
  high_threat_count: number;
  bahrain_relevant_count: number;
  new_indicators_today: number;
  sector_breakdown: Record<string, number>;
  recent_high_priority: Array<{
    id: number;
    indicator: string;
    type: string;
    threat_score: number;
    bahrain_score: number;
    sector: string;
    first_seen: string;
  }>;
  updated_at: string;
}

export interface ThreatTrends {
  period_days: number;
  daily_trends: Array<{
    date: string;
    total_threats: number;
    high_priority: number;
  }>;
}

export interface ThreatIndicator {
  id: number;
  indicator_type: string;
  indicator_value: string;
  threat_score: number;
  bahrain_score: number;
  confidence_level: string;
  targeted_sector: string;
  source: string;
  first_seen: string;
  last_updated: string;
  tags: string[];
  status: string;
}

export interface IndicatorsResponse {
  indicators: ThreatIndicator[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    has_more: boolean;
  };
}

export interface DomainAnalysisResult {
  domain: string;
  analysis_timestamp: string;
  threat_analysis: {
    threat_score: number;
    confidence_level: string;
    flags: string[];
    technical_analysis: any;
  };
  bahrain_relevance: {
    bahrain_score: number;
    confidence_level: string;
    primary_sector: string;
    matched_keywords: string[];
    explanation: string;
  };
  overall_assessment: {
    threat_level: string;
    bahrain_relevance_level: string;
    recommended_action: string;
  };
}

export interface CollectionResult {
  timestamp: string;
  sources_used: string[];
  total_collected: number;
  new_indicators: number;
  status: string;
}

// API Functions

/**
 * Fetch CTI dashboard statistics
 */
export async function fetchCTIDashboardStats(days: number = 7): Promise<CTIDashboardStats> {
  const response = await fetch(`${CTI_API_BASE}/api/dashboard/stats?days=${days}`);
  
  if (!response.ok) {
    throw new Error(`Failed to fetch dashboard stats: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Fetch threat trends data
 */
export async function fetchThreatTrends(days: number = 7): Promise<ThreatTrends> {
  const response = await fetch(`${CTI_API_BASE}/api/dashboard/trends?days=${days}`);
  
  if (!response.ok) {
    throw new Error(`Failed to fetch threat trends: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Fetch threat indicators with filtering and pagination
 */
export async function fetchThreatIndicators(params: {
  limit?: number;
  offset?: number;
  type?: string;
  sector?: string;
  min_threat_score?: number;
  min_bahrain_score?: number;
} = {}): Promise<IndicatorsResponse> {
  const searchParams = new URLSearchParams();
  
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      searchParams.append(key, value.toString());
    }
  });
  
  const response = await fetch(`${CTI_API_BASE}/api/indicators/list?${searchParams}`);
  
  if (!response.ok) {
    throw new Error(`Failed to fetch indicators: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Fetch detailed information about a specific indicator
 */
export async function fetchIndicatorDetails(id: number): Promise<ThreatIndicator> {
  const response = await fetch(`${CTI_API_BASE}/api/indicators/${id}`);
  
  if (!response.ok) {
    throw new Error(`Failed to fetch indicator details: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Analyze a domain for threats and Bahrain relevance
 */
export async function analyzeDomain(domain: string): Promise<DomainAnalysisResult> {
  const response = await fetch(`${CTI_API_BASE}/api/analysis/domain`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ domain }),
  });
  
  if (!response.ok) {
    throw new Error(`Failed to analyze domain: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Analyze multiple indicators in bulk
 */
export async function analyzeBulk(indicators: Array<{ value: string; type: string }>): Promise<any> {
  const response = await fetch(`${CTI_API_BASE}/api/analysis/bulk`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ indicators }),
  });
  
  if (!response.ok) {
    throw new Error(`Failed to perform bulk analysis: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Trigger threat intelligence collection
 */
export async function triggerCollection(useDemo: boolean = true): Promise<CollectionResult> {
  const response = await fetch(`${CTI_API_BASE}/api/collection/run`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ use_demo: useDemo }),
  });
  
  if (!response.ok) {
    throw new Error(`Failed to trigger collection: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Get collection status
 */
export async function getCollectionStatus(): Promise<any> {
  const response = await fetch(`${CTI_API_BASE}/api/collection/status`);
  
  if (!response.ok) {
    throw new Error(`Failed to get collection status: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Check if CTI backend is available
 */
export async function checkCTIBackendHealth(): Promise<boolean> {
  try {
    const response = await fetch(`${CTI_API_BASE}/`, {
      method: 'GET',
      timeout: 5000,
    } as any);
    
    return response.ok;
  } catch (error) {
    console.error('CTI Backend health check failed:', error);
    return false;
  }
}

/**
 * Utility function to get threat level color
 */
export function getThreatLevelColor(score: number): string {
  if (score >= 80) return '#dc2626'; // Critical
  if (score >= 60) return '#ef4444'; // High
  if (score >= 40) return '#f59e0b'; // Medium
  return '#3b82f6'; // Low
}

/**
 * Utility function to get Bahrain relevance color
 */
export function getBahrainRelevanceColor(score: number): string {
  if (score >= 70) return '#dc2626'; // High relevance
  if (score >= 40) return '#f59e0b'; // Medium relevance
  return '#10b981'; // Low relevance
}

/**
 * Utility function to get sector icon
 */
export function getSectorIcon(sector: string): string {
  switch (sector) {
    case 'banking': return '[B]';
    case 'telecom': return '[T]';
    case 'government': return '[G]';
    case 'business': return '[Biz]';
    default: return '[?]';
  }
}

/**
 * Format date for display
 */
export function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

/**
 * Format threat level for display
 */
export function formatThreatLevel(level: string): string {
  return level.charAt(0).toUpperCase() + level.slice(1);
}

/**
 * Get recommended action description
 */
export function getRecommendedActionDescription(action: string): string {
  switch (action) {
    case 'immediate_block':
      return 'Block immediately - High threat with local relevance';
    case 'monitor_closely':
      return 'Monitor closely - Elevated threat level detected';
    case 'investigate':
      return 'Investigate further - Potential threat identified';
    case 'low_priority':
      return 'Low priority - Minimal threat detected';
    default:
      return 'Review manually';
  }
}
