import React, { useState, useEffect } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { 
  Activity, 
  Shield, 
  AlertTriangle, 
  Clock, 
  Target, 
  Zap,
  Play,
  Pause,
  RefreshCw,
  Bell,
  TrendingUp
} from 'lucide-react';

interface MonitoringStatus {
  is_running: boolean;
  last_collection: string | null;
  collection_count: number;
  alert_count: number;
  collection_interval_minutes: number;
  critical_threshold: number;
  bahrain_threshold: number;
}

interface LiveStats {
  total_threats: number;
  recent_threats_1h: number;
  critical_bahrain_threats: number;
  monitoring_active: boolean;
  last_collection: string | null;
  alert_count: number;
}

interface ThreatAlert {
  id: number;
  timestamp: string;
  indicator: string;
  type: string;
  severity: string;
  threat_score: number;
  bahrain_score: number;
  sector: string;
}

export default function LiveMonitoring() {
  const [monitoringStatus, setMonitoringStatus] = useState<MonitoringStatus | null>(null);
  const [liveStats, setLiveStats] = useState<LiveStats | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<ThreatAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const API_BASE = process.env.NEXT_PUBLIC_CTI_API_URL || 'http://localhost:5000';

  useEffect(() => {
    setMonitoringStatus({
      is_running: true,
      last_collection: new Date(Date.now() - 900000).toISOString(),
      collection_count: 142,
      alert_count: 37,
      collection_interval_minutes: 30,
      critical_threshold: 80,
      bahrain_threshold: 70
    });
    setLiveStats({
      total_threats: 248,
      recent_threats_1h: 7,
      critical_bahrain_threats: 12,
      monitoring_active: true,
      last_collection: new Date(Date.now() - 900000).toISOString(),
      alert_count: 37
    });
    setRecentAlerts([
      { id: 1, timestamp: new Date(Date.now() - 600000).toISOString(), indicator: 'nbbbahrain-secure.tk', type: 'domain', severity: 'critical', threat_score: 94, bahrain_score: 97, sector: 'banking' },
      { id: 2, timestamp: new Date(Date.now() - 1800000).toISOString(), indicator: 'benefit-pay.tk', type: 'domain', severity: 'critical', threat_score: 95, bahrain_score: 92, sector: 'banking' },
      { id: 3, timestamp: new Date(Date.now() - 3600000).toISOString(), indicator: 'bh-bankofbahrain.cc', type: 'domain', severity: 'critical', threat_score: 93, bahrain_score: 96, sector: 'banking' },
      { id: 4, timestamp: new Date(Date.now() - 5400000).toISOString(), indicator: '185.220.101.47', type: 'ip', severity: 'high', threat_score: 82, bahrain_score: 68, sector: 'government' },
      { id: 5, timestamp: new Date(Date.now() - 7200000).toISOString(), indicator: 'bahrain-gov-alert.xyz', type: 'domain', severity: 'high', threat_score: 79, bahrain_score: 88, sector: 'government' },
      { id: 6, timestamp: new Date(Date.now() - 9000000).toISOString(), indicator: 'nbb-secure.ru', type: 'domain', severity: 'critical', threat_score: 91, bahrain_score: 94, sector: 'banking' },
      { id: 7, timestamp: new Date(Date.now() - 10800000).toISOString(), indicator: 'batelco-login.info', type: 'domain', severity: 'high', threat_score: 88, bahrain_score: 85, sector: 'telecom' },
      { id: 8, timestamp: new Date(Date.now() - 12600000).toISOString(), indicator: 'isa-bahrain-portal.tk', type: 'domain', severity: 'high', threat_score: 77, bahrain_score: 91, sector: 'government' },
    ]);
    setLoading(false);
  }, []);

  const toggleMonitoring = () => {
    setMonitoringStatus(prev => prev ? { ...prev, is_running: !prev.is_running } : null);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return '#dc2626';
      case 'high': return '#ea580c';
      case 'medium': return '#d97706';
      case 'low': return '#65a30d';
      default: return '#6b7280';
    }
  };

  const formatTimeAgo = (timestamp: string) => {
    const now = new Date();
    const time = new Date(timestamp);
    const diffMs = now.getTime() - time.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  return (
    <div className="min-h-screen text-white" style={{
      background: 'linear-gradient(135deg, #0a0e12 0%, #1a1f2e 50%, #0a0e12 100%)'
    }}>
      <Head>
        <title>Live Monitoring | PhishSecure Bahrain CTI</title>
        <meta name="description" content="Real-time threat monitoring for Bahrain" />
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div style={{
                background: 'linear-gradient(to right, #4ade80, #10b981)',
                padding: '0.5rem',
                borderRadius: '0.5rem'
              }}>
                <Activity size={20} />
              </div>
              <div>
                <h2 style={{
                  fontSize: '1.5rem',
                  fontWeight: 'bold',
                  background: 'linear-gradient(to right, #4ade80, #10b981)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  margin: 0
                }}>Live Monitoring</h2>
                <p style={{
                  fontSize: '0.75rem',
                  color: '#64748b',
                  margin: 0
                }}>Real-time Threat Intelligence</p>
              </div>
            </div>
          </Link>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.5rem 1rem',
              borderRadius: '0.5rem',
              backgroundColor: monitoringStatus?.is_running ? 'rgba(34, 197, 94, 0.2)' : 'rgba(239, 68, 68, 0.2)',
              border: `1px solid ${monitoringStatus?.is_running ? 'rgba(34, 197, 94, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`
            }}>
              <div style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                backgroundColor: monitoringStatus?.is_running ? '#22c55e' : '#ef4444',
                animation: monitoringStatus?.is_running ? 'pulse 2s infinite' : 'none'
              }}></div>
              <span style={{ fontSize: '0.875rem', color: monitoringStatus?.is_running ? '#22c55e' : '#ef4444' }}>
                {monitoringStatus?.is_running ? 'ACTIVE' : 'STOPPED'}
              </span>
            </div>

            <button
              onClick={toggleMonitoring}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.5rem 1rem',
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                border: '1px solid rgba(59, 130, 246, 0.4)',
                borderRadius: '0.5rem',
                color: '#60a5fa',
                cursor: 'pointer'
              }}
            >
              {monitoringStatus?.is_running ? <Pause size={16} /> : <Play size={16} />}
              {monitoringStatus?.is_running ? 'Stop' : 'Start'}
            </button>
          </div>
        </div>
      </header>

      <main style={{ padding: '2rem', maxWidth: '90rem', margin: '0 auto' }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '4rem' }}>
            <RefreshCw className="animate-spin" size={32} style={{ margin: '0 auto 1rem', color: '#60a5fa' }} />
            <p style={{ color: '#94a3b8' }}>Loading monitoring data...</p>
          </div>
        ) : error ? (
          <div style={{ textAlign: 'center', padding: '4rem' }}>
            <AlertTriangle size={32} style={{ margin: '0 auto 1rem', color: '#ef4444' }} />
            <p style={{ color: '#ef4444', marginBottom: '1rem' }}>{error}</p>
          </div>
        ) : (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            {/* Live Stats Cards */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
              gap: '1.5rem',
              marginBottom: '2rem'
            }}>
              {/* Total Threats */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '1rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
                  <Shield style={{ color: '#60a5fa' }} size={20} />
                  <span style={{ fontSize: '0.875rem', color: '#94a3b8', textTransform: 'uppercase' }}>
                    Total Threats
                  </span>
                </div>
                <div style={{
                  fontSize: '2.5rem',
                  fontWeight: 'bold',
                  color: '#60a5fa',
                  fontFamily: '"JetBrains Mono", monospace'
                }}>
                  {liveStats?.total_threats || 0}
                </div>
                <p style={{ fontSize: '0.75rem', color: '#64748b', margin: 0 }}>
                  In threat database
                </p>
              </div>

              {/* Recent Threats */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(251, 191, 36, 0.3)',
                borderRadius: '1rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
                  <Clock style={{ color: '#fbbf24' }} size={20} />
                  <span style={{ fontSize: '0.875rem', color: '#94a3b8', textTransform: 'uppercase' }}>
                    Last Hour
                  </span>
                </div>
                <div style={{
                  fontSize: '2.5rem',
                  fontWeight: 'bold',
                  color: '#fbbf24',
                  fontFamily: '"JetBrains Mono", monospace'
                }}>
                  {liveStats?.recent_threats_1h || 0}
                </div>
                <p style={{ fontSize: '0.75rem', color: '#64748b', margin: 0 }}>
                  New threats detected
                </p>
              </div>

              {/* Critical Bahrain Threats */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                borderRadius: '1rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
                  <Target style={{ color: '#ef4444' }} size={20} />
                  <span style={{ fontSize: '0.875rem', color: '#94a3b8', textTransform: 'uppercase' }}>
                    Critical Bahrain
                  </span>
                </div>
                <div style={{
                  fontSize: '2.5rem',
                  fontWeight: 'bold',
                  color: '#ef4444',
                  fontFamily: '"JetBrains Mono", monospace'
                }}>
                  {liveStats?.critical_bahrain_threats || 0}
                </div>
                <p style={{ fontSize: '0.75rem', color: '#64748b', margin: 0 }}>
                  High-priority threats
                </p>
              </div>

              {/* Alert Count */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(139, 92, 246, 0.3)',
                borderRadius: '1rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
                  <Bell style={{ color: '#a78bfa' }} size={20} />
                  <span style={{ fontSize: '0.875rem', color: '#94a3b8', textTransform: 'uppercase' }}>
                    Alerts Generated
                  </span>
                </div>
                <div style={{
                  fontSize: '2.5rem',
                  fontWeight: 'bold',
                  color: '#a78bfa',
                  fontFamily: '"JetBrains Mono", monospace'
                }}>
                  {liveStats?.alert_count || 0}
                </div>
                <p style={{ fontSize: '0.75rem', color: '#64748b', margin: 0 }}>
                  Total alerts
                </p>
              </div>
            </div>

            {/* Monitoring Status */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
              gap: '1.5rem',
              marginBottom: '2rem'
            }}>
              {/* Monitoring Configuration */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                borderRadius: '1rem'
              }}>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '1rem', color: '#10b981' }}>
                  Monitoring Configuration
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#94a3b8' }}>Collection Interval:</span>
                    <span style={{ color: '#e2e8f0' }}>{monitoringStatus?.collection_interval_minutes}m</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#94a3b8' }}>Critical Threshold:</span>
                    <span style={{ color: '#e2e8f0' }}>{monitoringStatus?.critical_threshold}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#94a3b8' }}>Bahrain Threshold:</span>
                    <span style={{ color: '#e2e8f0' }}>{monitoringStatus?.bahrain_threshold}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#94a3b8' }}>Collections Run:</span>
                    <span style={{ color: '#e2e8f0' }}>{monitoringStatus?.collection_count}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#94a3b8' }}>Last Collection:</span>
                    <span style={{ color: '#e2e8f0' }}>
                      {monitoringStatus?.last_collection ? 
                        formatTimeAgo(monitoringStatus.last_collection) : 
                        'Never'
                      }
                    </span>
                  </div>
                </div>
              </div>

              {/* Recent Alerts */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                borderRadius: '1rem'
              }}>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '1rem', color: '#ef4444' }}>
                  Recent Critical Alerts
                </h3>
                <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
                  {recentAlerts.length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      {recentAlerts.slice(0, 10).map((alert) => (
                        <div key={alert.id} style={{
                          padding: '0.75rem',
                          backgroundColor: 'rgba(239, 68, 68, 0.1)',
                          border: '1px solid rgba(239, 68, 68, 0.2)',
                          borderRadius: '0.5rem'
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                            <span style={{
                              fontSize: '0.75rem',
                              color: getSeverityColor(alert.severity),
                              backgroundColor: `${getSeverityColor(alert.severity)}20`,
                              padding: '0.125rem 0.5rem',
                              borderRadius: '9999px',
                              textTransform: 'uppercase',
                              fontWeight: 600
                            }}>
                              {alert.severity}
                            </span>
                            <span style={{ fontSize: '0.625rem', color: '#64748b' }}>
                              {formatTimeAgo(alert.timestamp)}
                            </span>
                          </div>
                          <div style={{ fontSize: '0.875rem', color: '#fca5a5', fontFamily: '"JetBrains Mono", monospace', marginBottom: '0.25rem' }}>
                            {alert.indicator}
                          </div>
                          <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                            Threat: {alert.threat_score} | Bahrain: {alert.bahrain_score} | {alert.sector}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ textAlign: 'center', color: '#64748b', padding: '2rem' }}>
                      No recent alerts
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Navigation Links */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '1rem'
            }}>
              <Link href="/cti-dashboard" style={{
                display: 'block',
                padding: '1rem',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '0.5rem',
                color: '#60a5fa',
                textDecoration: 'none',
                textAlign: 'center'
              }}>
                <TrendingUp size={20} style={{ margin: '0 auto 0.5rem' }} />
                CTI Dashboard
              </Link>

              <Link href="/indicators" style={{
                display: 'block',
                padding: '1rem',
                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                borderRadius: '0.5rem',
                color: '#10b981',
                textDecoration: 'none',
                textAlign: 'center'
              }}>
                <Shield size={20} style={{ margin: '0 auto 0.5rem' }} />
                Threat Indicators
              </Link>

              <Link href="/analyze" style={{
                display: 'block',
                padding: '1rem',
                backgroundColor: 'rgba(139, 92, 246, 0.1)',
                border: '1px solid rgba(139, 92, 246, 0.3)',
                borderRadius: '0.5rem',
                color: '#a78bfa',
                textDecoration: 'none',
                textAlign: 'center'
              }}>
                <Zap size={20} style={{ margin: '0 auto 0.5rem' }} />
                Analyze Domain
              </Link>
            </div>
          </motion.div>
        )}
      </main>
    </div>
  );
}
