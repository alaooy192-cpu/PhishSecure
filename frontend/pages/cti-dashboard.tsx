import Head from 'next/head';
import { motion } from 'framer-motion';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { 
  Shield, 
  AlertTriangle, 
  Globe, 
  TrendingUp, 
  Eye, 
  Database,
  MapPin,
  Building2,
  Clock,
  Search,
} from 'lucide-react';

// CTI API functions
const CTI_API_BASE = process.env.NEXT_PUBLIC_CTI_API_URL || 'http://localhost:5000';

interface CTIDashboardStats {
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

interface ThreatTrends {
  period_days: number;
  daily_trends: Array<{
    date: string;
    total_threats: number;
    high_priority: number;
  }>;
}

export default function CTIDashboard() {
  const [stats, setStats] = useState<CTIDashboardStats | null>(null);
  const [trends, setTrends] = useState<ThreatTrends | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [period, setPeriod] = useState(7);

  const loadDashboardData = async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Load dashboard stats
      const statsResponse = await fetch(`${CTI_API_BASE}/api/dashboard/stats?days=${period}`);
      if (!statsResponse.ok) throw new Error('Failed to load dashboard stats');
      const statsData = await statsResponse.json();
      setStats(statsData);

      // Load trends
      const trendsResponse = await fetch(`${CTI_API_BASE}/api/dashboard/trends?days=${period}`);
      if (!trendsResponse.ok) throw new Error('Failed to load trends');
      const trendsData = await trendsResponse.json();
      setTrends(trendsData);

    } catch (err) {
      setError('Failed to load CTI dashboard. Make sure the backend is running on port 5000.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const [lastRefreshed, setLastRefreshed] = useState<string>('');
  const [collecting, setCollecting] = useState(false);

  const triggerCollection = async () => {
    setCollecting(true);
    try {
      await fetch(`${CTI_API_BASE}/api/seed`, { method: 'POST' });
      await fetch(`${CTI_API_BASE}/api/collection/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ use_demo: false })
      });
      setTimeout(loadDashboardData, 2000);
    } catch (err) {
      console.error('Failed to trigger collection:', err);
    } finally {
      setCollecting(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
    setLastRefreshed(new Date().toLocaleTimeString());

    const interval = setInterval(() => {
      loadDashboardData();
      setLastRefreshed(new Date().toLocaleTimeString());
    }, 30000);

    return () => clearInterval(interval);
  }, [period]);

  const getThreatLevelColor = (score: number) => {
    if (score >= 80) return '#dc2626'; // Critical
    if (score >= 60) return '#ef4444'; // High
    if (score >= 40) return '#f59e0b'; // Medium
    return '#3b82f6'; // Low
  };

  const getBahrainRelevanceColor = (score: number) => {
    if (score >= 70) return '#dc2626'; // High relevance
    if (score >= 40) return '#f59e0b'; // Medium relevance
    return '#10b981'; // Low relevance
  };

  const getSectorIcon = (sector: string) => {
    switch (sector) {
      case 'banking': return '$';
      case 'telecom': return '☎';
      case 'government': return '⌂';
      case 'business': return '⊞';
      default: return '?';
    }
  };

  return (
    <div className="min-h-screen text-white" style={{ 
      background: 'linear-gradient(135deg, #0a0e12 0%, #1a1f2e 50%, #0a0e12 100%)' 
    }}>
      <Head>
        <title>PhishSecure Bahrain | CTI Dashboard</title>
        <meta name="description" content="Cyber Threat Intelligence Dashboard for Bahrain" />
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet" />
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet" />
      </Head>

      {/* Header */}
      <header style={{ 
        padding: '1.5rem',
        borderBottom: '1px solid rgba(59, 130, 246, 0.2)',
        background: 'rgba(10, 14, 18, 0.8)',
        backdropFilter: 'blur(10px)'
      }}>
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          maxWidth: '90rem', 
          margin: '0 auto'
        }}>
          <Link href="/" style={{ textDecoration: 'none' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
              <div style={{ 
                background: 'linear-gradient(to right, #4ade80, #10b981)', 
                padding: '0.5rem', 
                borderRadius: '0.5rem'
              }}>
                <Shield size={20} />
              </div>
              <div>
                <h2 style={{ 
                  fontSize: '1.5rem', 
                  fontWeight: 'bold',
                  background: 'linear-gradient(to right, #4ade80, #10b981)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  margin: 0
                }}>PhishSecure Bahrain</h2>
                <p style={{ 
                  fontSize: '0.75rem', 
                  color: '#64748b', 
                  margin: 0,
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>Cyber Threat Intelligence</p>
              </div>
            </div>
          </Link>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <select
              value={period}
              onChange={(e) => setPeriod(Number(e.target.value))}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '0.5rem',
                color: 'white',
                fontSize: '0.875rem',
                cursor: 'pointer'
              }}
            >
              <option value={7} style={{ backgroundColor: '#1a1f2e', color: '#ffffff' }}>Last 7 days</option>
              <option value={30} style={{ backgroundColor: '#1a1f2e', color: '#ffffff' }}>Last 30 days</option>
              <option value={90} style={{ backgroundColor: '#1a1f2e', color: '#ffffff' }}>Last 90 days</option>
            </select>
            
            {lastRefreshed && (
              <span style={{ fontSize: '0.75rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Clock size={12} />
                Live · {lastRefreshed}
              </span>
            )}

            <button
              onClick={triggerCollection}
              disabled={collecting}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: collecting ? 'rgba(139, 92, 246, 0.1)' : 'rgba(139, 92, 246, 0.2)',
                border: '1px solid rgba(139, 92, 246, 0.4)',
                borderRadius: '0.5rem',
                color: collecting ? '#6d4fb5' : '#a78bfa',
                fontSize: '0.875rem',
                cursor: collecting ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem'
              }}
            >
              <Database size={16} />
              {collecting ? 'Collecting...' : 'Collect Threats'}
            </button>

            <Link href="/indicators" style={{
              padding: '0.5rem 1rem',
              backgroundColor: 'rgba(16, 185, 129, 0.2)',
              border: '1px solid rgba(16, 185, 129, 0.4)',
              borderRadius: '0.5rem',
              color: '#10b981',
              fontSize: '0.875rem',
              textDecoration: 'none',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <Search size={16} />
              View Indicators
            </Link>
          </div>
        </div>
      </header>

      <main style={{ padding: '2rem', maxWidth: '90rem', margin: '0 auto' }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '4rem' }}>
            <div style={{ 
              width: '40px', 
              height: '40px', 
              border: '3px solid rgba(74, 222, 128, 0.3)',
              borderTop: '3px solid #4ade80',
              borderRadius: '50%',
              animation: 'spin 1s linear infinite',
              margin: '0 auto 1rem'
            }}></div>
            <p style={{ color: 'var(--text-secondary)' }}>Loading threat intelligence...</p>
          </div>
        ) : error ? (
          <div style={{ textAlign: 'center', padding: '4rem' }}>
            <AlertTriangle size={48} style={{ color: '#ef4444', margin: '0 auto 1rem' }} />
            <div style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#ef4444' }}>Connection Error</div>
            <p style={{ color: '#ef4444', marginBottom: '1rem' }}>{error}</p>
            <button
              onClick={loadDashboardData}
              style={{
                padding: '0.75rem 1.5rem',
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                border: '1px solid rgba(59, 130, 246, 0.4)',
                borderRadius: '0.5rem',
                color: '#60a5fa',
                cursor: 'pointer'
              }}
            >
              Retry Connection
            </button>
          </div>
        ) : stats ? (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            {/* Page Title */}
            <div style={{ marginBottom: '2rem' }}>
              <h1 style={{ 
                fontSize: '2.5rem', 
                fontWeight: 700, 
                fontFamily: '"Space Grotesk", sans-serif',
                marginBottom: '0.5rem',
                background: 'linear-gradient(to right, #4ade80, #10b981)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent'
              }}>
                Bahrain Threat Intelligence
              </h1>
              <p style={{ color: 'var(--text-secondary)', fontSize: '1rem' }}>
                Real-time monitoring of phishing threats targeting Bahrain organizations
              </p>
            </div>

            {/* Top Stats Cards */}
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', 
              gap: '1.5rem',
              marginBottom: '2rem'
            }}>
              {/* Total Indicators */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '1rem',
                position: 'relative',
                overflow: 'hidden'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                  <Globe size={24} style={{ color: '#60a5fa' }} />
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    Total Indicators
                  </span>
                </div>
                <div style={{ 
                  fontSize: '3rem', 
                  fontWeight: 700, 
                  fontFamily: '"JetBrains Mono", monospace',
                  color: '#60a5fa'
                }}>
                  {stats.total_indicators}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  Domains, URLs & IPs tracked
                </div>
              </div>

              {/* High Threat Count */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                borderRadius: '1rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                  <AlertTriangle size={24} style={{ color: '#ef4444' }} />
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    High Threat
                  </span>
                </div>
                <div style={{ 
                  fontSize: '3rem', 
                  fontWeight: 700, 
                  fontFamily: '"JetBrains Mono", monospace',
                  color: '#ef4444'
                }}>
                  {stats.high_threat_count}
                </div>
                <div style={{ fontSize: '0.75rem', color: '#ef4444' }}>
                  Critical threats detected
                </div>
              </div>

              {/* Bahrain Relevant */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                borderRadius: '1rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                  <MapPin size={24} style={{ color: '#f59e0b' }} />
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    Bahrain Relevant
                  </span>
                </div>
                <div style={{ 
                  fontSize: '3rem', 
                  fontWeight: 700, 
                  fontFamily: '"JetBrains Mono", monospace',
                  color: '#f59e0b'
                }}>
                  {stats.bahrain_relevant_count}
                </div>
                <div style={{ fontSize: '0.75rem', color: '#f59e0b' }}>
                  Targeting local organizations
                </div>
              </div>

              {/* New Today */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                borderRadius: '1rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                  <Clock size={24} style={{ color: '#10b981' }} />
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    New Today
                  </span>
                </div>
                <div style={{ 
                  fontSize: '3rem', 
                  fontWeight: 700, 
                  fontFamily: '"JetBrains Mono", monospace',
                  color: '#10b981'
                }}>
                  {stats.new_indicators_today}
                </div>
                <div style={{ fontSize: '0.75rem', color: '#10b981' }}>
                  Fresh indicators collected
                </div>
              </div>
            </div>

            {/* Charts Row */}
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', 
              gap: '1.5rem',
              marginBottom: '2rem'
            }}>
              {/* Threat Trends */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(59, 130, 246, 0.2)',
                borderRadius: '1rem'
              }}>
                <h3 style={{ 
                  fontSize: '1.25rem', 
                  fontWeight: 600, 
                  marginBottom: '1rem', 
                  color: 'var(--text-bright)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}>
                  <TrendingUp size={20} />
                  Threat Trends
                </h3>
                {trends && trends.daily_trends.length > 0 ? (
                  <div style={{ display: 'flex', alignItems: 'flex-end', gap: '2px', height: '160px', overflowX: 'hidden' }}>
                    {trends.daily_trends.map((day, index) => {
                      const total = trends.daily_trends.length;
                      const labelEvery = total <= 7 ? 1 : total <= 30 ? 5 : 10;
                      const showLabel = index % labelEvery === 0 || index === total - 1;
                      const maxTotal = Math.max(...trends.daily_trends.map(d => d.total_threats), 1);
                      const height = (day.total_threats / maxTotal) * 100;
                      const highPriorityHeight = day.total_threats > 0 ? (day.high_priority / day.total_threats) * height : 0;
                      
                      return (
                        <div key={index} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 0 }}>
                          <div style={{ 
                            width: '100%', 
                            height: `${Math.max(height, 4)}%`,
                            backgroundColor: '#3b82f6',
                            borderRadius: '2px 2px 0 0',
                            position: 'relative'
                          }}>
                            <div style={{
                              position: 'absolute',
                              bottom: 0,
                              width: '100%',
                              height: `${highPriorityHeight}%`,
                              backgroundColor: '#ef4444',
                              borderRadius: '0 0 2px 2px'
                            }}></div>
                          </div>
                          <div style={{ 
                            fontSize: '0.6rem', 
                            color: showLabel ? '#94a3b8' : 'transparent',
                            marginTop: '4px',
                            whiteSpace: 'nowrap',
                            overflow: 'hidden'
                          }}>
                            {showLabel ? day.date.slice(5) : ''}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem' }}>
                    No trend data available
                  </div>
                )}
                <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem', fontSize: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <div style={{ width: '12px', height: '12px', backgroundColor: '#3b82f6', borderRadius: '2px' }}></div>
                    <span style={{ color: 'var(--text-secondary)' }}>Total Threats</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <div style={{ width: '12px', height: '12px', backgroundColor: '#ef4444', borderRadius: '2px' }}></div>
                    <span style={{ color: 'var(--text-secondary)' }}>High Priority</span>
                  </div>
                </div>
              </div>

              {/* Sector Breakdown */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(59, 130, 246, 0.2)',
                borderRadius: '1rem'
              }}>
                <h3 style={{ 
                  fontSize: '1.25rem', 
                  fontWeight: 600, 
                  marginBottom: '1rem', 
                  color: 'var(--text-bright)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}>
                  <Building2 size={20} />
                  Targeted Sectors
                </h3>
                {Object.keys(stats.sector_breakdown).length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    {Object.entries(stats.sector_breakdown)
                      .sort(([,a], [,b]) => b - a)
                      .slice(0, 5)
                      .map(([sector, count], index) => {
                        const maxCount = Math.max(...Object.values(stats.sector_breakdown));
                        const percentage = (count / maxCount) * 100;
                        
                        return (
                          <div key={index}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                              <span style={{ 
                                fontSize: '0.875rem', 
                                color: 'var(--text-primary)',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.5rem'
                              }}>
                                <span>{getSectorIcon(sector)}</span>
                                {sector.charAt(0).toUpperCase() + sector.slice(1)}
                              </span>
                              <span style={{ 
                                fontSize: '0.875rem', 
                                color: '#4ade80',
                                fontFamily: '"JetBrains Mono", monospace'
                              }}>
                                {count}
                              </span>
                            </div>
                            <div style={{ 
                              height: '8px', 
                              backgroundColor: 'rgba(59, 130, 246, 0.1)', 
                              borderRadius: '4px', 
                              overflow: 'hidden' 
                            }}>
                              <div style={{
                                height: '100%',
                                width: `${percentage}%`,
                                background: 'linear-gradient(to right, #4ade80, #10b981)',
                                borderRadius: '4px',
                                transition: 'width 0.5s ease'
                              }}></div>
                            </div>
                          </div>
                        );
                      })}
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem' }}>
                    No sector data available
                  </div>
                )}
              </div>
            </div>

            {/* Recent High Priority Threats */}
            <div style={{
              padding: '1.5rem',
              backgroundColor: 'rgba(10, 14, 18, 0.8)',
              border: '1px solid rgba(239, 68, 68, 0.2)',
              borderRadius: '1rem'
            }}>
              <h3 style={{ 
                fontSize: '1.25rem', 
                fontWeight: 600, 
                marginBottom: '1rem', 
                color: 'var(--text-bright)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem'
              }}>
                <Eye size={20} />
                Recent High-Priority Threats
              </h3>
              {stats.recent_high_priority.length > 0 ? (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
                  {stats.recent_high_priority.slice(0, 6).map((threat, index) => (
                    <div key={index} style={{
                      padding: '1rem',
                      backgroundColor: 'rgba(239, 68, 68, 0.05)',
                      border: '1px solid rgba(239, 68, 68, 0.2)',
                      borderRadius: '0.5rem'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                        <span style={{ 
                          fontSize: '0.875rem', 
                          color: '#fca5a5', 
                          fontFamily: '"JetBrains Mono", monospace',
                          wordBreak: 'break-all',
                          flex: 1,
                          marginRight: '0.5rem'
                        }}>
                          {threat.indicator}
                        </span>
                        <span style={{ 
                          fontSize: '0.625rem', 
                          color: getThreatLevelColor(threat.threat_score),
                          backgroundColor: `${getThreatLevelColor(threat.threat_score)}20`,
                          padding: '0.125rem 0.5rem',
                          borderRadius: '9999px',
                          textTransform: 'uppercase',
                          whiteSpace: 'nowrap'
                        }}>
                          {threat.type}
                        </span>
                      </div>
                      <div style={{ display: 'flex', gap: '1rem', marginBottom: '0.5rem' }}>
                        <div style={{ fontSize: '0.75rem' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>Threat: </span>
                          <span style={{ color: getThreatLevelColor(threat.threat_score), fontWeight: 600 }}>
                            {threat.threat_score}/100
                          </span>
                        </div>
                        <div style={{ fontSize: '0.75rem' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>Bahrain: </span>
                          <span style={{ color: getBahrainRelevanceColor(threat.bahrain_score), fontWeight: 600 }}>
                            {threat.bahrain_score}/100
                          </span>
                        </div>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.625rem', color: 'var(--text-secondary)' }}>
                        <span>{getSectorIcon(threat.sector)} {threat.sector}</span>
                        <span>{new Date(threat.first_seen).toLocaleDateString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem' }}>
                  No high-priority threats detected
                </div>
              )}
            </div>
          </motion.div>
        ) : null}
      </main>

      {/* Footer */}
      <footer style={{ 
        padding: '2rem 1rem',
        borderTop: '1px solid rgba(59, 130, 246, 0.2)',
        textAlign: 'center'
      }}>
        <div style={{ display: 'flex', justifyContent: 'center', gap: '2rem', fontSize: '0.875rem' }}>
          <Link href="/" style={{ color: '#60a5fa', textDecoration: 'none' }}>
            ← Back to Home
          </Link>
          <Link href="/analyze" style={{ color: '#60a5fa', textDecoration: 'none' }}>
            Domain Analysis
          </Link>
          <Link href="/indicators" style={{ color: '#60a5fa', textDecoration: 'none' }}>
            View All Indicators
          </Link>
        </div>
      </footer>
    </div>
  );
}
