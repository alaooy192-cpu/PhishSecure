import Head from 'next/head';
import { motion } from 'framer-motion';
import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { 
  Shield, 
  AlertTriangle, 
  Globe, 
  Search, 
  Filter,
  Eye,
  ExternalLink,
  Calendar,
  MapPin,
  Building2,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
} from 'lucide-react';

const CTI_API_BASE = process.env.NEXT_PUBLIC_CTI_API_URL || 'http://localhost:5000';

function CustomDropdown({ value, onChange, options }: {
  value: string;
  onChange: (val: string) => void;
  options: { value: string; label: string }[];
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const selected = options.find(o => o.value === value);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  return (
    <div ref={ref} style={{ position: 'relative', minWidth: '140px' }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%',
          padding: '0.75rem 2.5rem 0.75rem 0.75rem',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          border: '1px solid rgba(59, 130, 246, 0.3)',
          borderRadius: '0.5rem',
          color: 'white',
          fontSize: '0.875rem',
          cursor: 'pointer',
          textAlign: 'left',
          position: 'relative'
        }}
      >
        {selected?.label}
        <span style={{ position: 'absolute', right: '0.5rem', top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }}>
          <ChevronDown size={14} color="#94a3b8" />
        </span>
      </button>
      {open && (
        <div style={{
          position: 'absolute',
          top: 'calc(100% + 4px)',
          left: 0,
          right: 0,
          backgroundColor: '#1a1f2e',
          border: '1px solid rgba(59, 130, 246, 0.4)',
          borderRadius: '0.5rem',
          overflow: 'hidden',
          zIndex: 50,
          boxShadow: '0 8px 24px rgba(0,0,0,0.5)'
        }}>
          {options.map(opt => (
            <div
              key={opt.value}
              onClick={() => { onChange(opt.value); setOpen(false); }}
              style={{
                padding: '0.625rem 0.75rem',
                color: opt.value === value ? '#4ade80' : '#e2e8f0',
                backgroundColor: opt.value === value ? 'rgba(74, 222, 128, 0.1)' : 'transparent',
                cursor: 'pointer',
                fontSize: '0.875rem',
                transition: 'background 0.15s'
              }}
              onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(59,130,246,0.15)')}
              onMouseLeave={e => (e.currentTarget.style.backgroundColor = opt.value === value ? 'rgba(74,222,128,0.1)' : 'transparent')}
            >
              {opt.label}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

interface ThreatIndicator {
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

interface IndicatorsResponse {
  indicators: ThreatIndicator[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    has_more: boolean;
  };
}

export default function IndicatorsPage() {
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [sectorFilter, setSectorFilter] = useState('');
  const [minThreatScore, setMinThreatScore] = useState('');
  const [minBahrainScore, setMinBahrainScore] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [selectedIndicator, setSelectedIndicator] = useState<ThreatIndicator | null>(null);

  const pageSize = 20;

  const loadIndicators = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const params = new URLSearchParams({
        limit: pageSize.toString(),
        offset: ((currentPage - 1) * pageSize).toString()
      });

      if (typeFilter) params.append('type', typeFilter);
      if (sectorFilter) params.append('sector', sectorFilter);
      if (minThreatScore) params.append('min_threat_score', minThreatScore);
      if (minBahrainScore) params.append('min_bahrain_score', minBahrainScore);

      const response = await fetch(`${CTI_API_BASE}/api/indicators/list?${params}`);
      if (!response.ok) throw new Error('Failed to load indicators');
      
      const data: IndicatorsResponse = await response.json();
      setIndicators(data.indicators);
      setTotalCount(data.pagination.total);

    } catch (err) {
      setError('Failed to load threat indicators. Make sure the CTI backend is running.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const loadIndicatorDetails = async (id: number) => {
    try {
      const response = await fetch(`${CTI_API_BASE}/api/indicators/${id}`);
      if (!response.ok) throw new Error('Failed to load indicator details');
      
      const data = await response.json();
      setSelectedIndicator(data);
    } catch (err) {
      console.error('Failed to load indicator details:', err);
    }
  };

  useEffect(() => {
    loadIndicators();
  }, [currentPage, typeFilter, sectorFilter, minThreatScore, minBahrainScore]);

  const getThreatLevelColor = (score: number) => {
    if (score >= 80) return '#dc2626';
    if (score >= 60) return '#ef4444';
    if (score >= 40) return '#f59e0b';
    return '#3b82f6';
  };

  const getBahrainRelevanceColor = (score: number) => {
    if (score >= 70) return '#dc2626';
    if (score >= 40) return '#f59e0b';
    return '#10b981';
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

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'domain': return <Globe size={16} />;
      case 'url': return <ExternalLink size={16} />;
      case 'ip': return <MapPin size={16} />;
      default: return <Shield size={16} />;
    }
  };

  const filteredIndicators = indicators.filter(indicator =>
    indicator.indicator_value.toLowerCase().includes(searchTerm.toLowerCase()) ||
    indicator.targeted_sector?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const totalPages = Math.ceil(totalCount / pageSize);

  return (
    <div className="min-h-screen text-white" style={{ 
      background: 'linear-gradient(135deg, #0a0e12 0%, #1a1f2e 50%, #0a0e12 100%)' 
    }}>
      <Head>
        <title>Threat Indicators | PhishSecure Bahrain CTI</title>
        <meta name="description" content="Browse and analyze threat indicators" />
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
          <Link href="/cti-dashboard" style={{ textDecoration: 'none' }}>
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
                }}>Threat Indicators</p>
              </div>
            </div>
          </Link>
          
          <Link href="/analyze" style={{
            padding: '0.5rem 1rem',
            backgroundColor: 'rgba(139, 92, 246, 0.2)',
            border: '1px solid rgba(139, 92, 246, 0.4)',
            borderRadius: '0.5rem',
            color: '#a78bfa',
            fontSize: '0.875rem',
            textDecoration: 'none',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}>
            <Search size={16} />
            Analyze Domain
          </Link>
        </div>
      </header>

      <main style={{ padding: '2rem', maxWidth: '90rem', margin: '0 auto' }}>
        {/* Page Title and Search */}
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
            Threat Indicators
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '1rem', marginBottom: '1.5rem' }}>
            Browse and analyze phishing threats targeting Bahrain organizations
          </p>

          {/* Search and Filters */}
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
            gap: '1rem',
            marginBottom: '1.5rem'
          }}>
            <div style={{ position: 'relative' }}>
              <Search size={20} style={{ 
                position: 'absolute', 
                left: '0.75rem', 
                top: '50%', 
                transform: 'translateY(-50%)',
                color: '#64748b'
              }} />
              <input
                type="text"
                placeholder="Search indicators..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  width: '100%',
                  padding: '0.75rem 0.75rem 0.75rem 2.5rem',
                  backgroundColor: 'rgba(59, 130, 246, 0.1)',
                  border: '1px solid rgba(59, 130, 246, 0.3)',
                  borderRadius: '0.5rem',
                  color: 'white',
                  fontSize: '0.875rem'
                }}
              />
            </div>

            <CustomDropdown
              value={typeFilter}
              onChange={setTypeFilter}
              options={[
                { value: '', label: 'All Types' },
                { value: 'domain', label: 'Domains' },
                { value: 'url', label: 'URLs' },
                { value: 'ip', label: 'IP Addresses' },
              ]}
            />

            <CustomDropdown
              value={sectorFilter}
              onChange={setSectorFilter}
              options={[
                { value: '', label: 'All Sectors' },
                { value: 'banking', label: 'Banking' },
                { value: 'telecom', label: 'Telecom' },
                { value: 'government', label: 'Government' },
                { value: 'business', label: 'Business' },
              ]}
            />

            <input
              type="number"
              placeholder="Min Threat Score"
              value={minThreatScore}
              onChange={(e) => setMinThreatScore(e.target.value)}
              min="0"
              max="100"
              style={{
                padding: '0.75rem',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '0.5rem',
                color: 'white',
                fontSize: '0.875rem'
              }}
            />

            <input
              type="number"
              placeholder="Min Bahrain Score"
              value={minBahrainScore}
              onChange={(e) => setMinBahrainScore(e.target.value)}
              min="0"
              max="100"
              style={{
                padding: '0.75rem',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '0.5rem',
                color: 'white',
                fontSize: '0.875rem'
              }}
            />
          </div>
        </div>

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
            <p style={{ color: 'var(--text-secondary)' }}>Loading threat indicators...</p>
          </div>
        ) : error ? (
          <div style={{ textAlign: 'center', padding: '4rem' }}>
            <AlertTriangle size={48} style={{ color: '#ef4444', margin: '0 auto 1rem' }} />
            <div style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#ef4444' }}>Error Loading Data</div>
            <p style={{ color: '#ef4444', marginBottom: '1rem' }}>{error}</p>
            <button
              onClick={loadIndicators}
              style={{
                padding: '0.75rem 1.5rem',
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                border: '1px solid rgba(59, 130, 246, 0.4)',
                borderRadius: '0.5rem',
                color: '#60a5fa',
                cursor: 'pointer'
              }}
            >
              Retry
            </button>
          </div>
        ) : (
          <>
            {/* Results Summary */}
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between', 
              alignItems: 'center', 
              marginBottom: '1.5rem',
              padding: '1rem',
              backgroundColor: 'rgba(10, 14, 18, 0.8)',
              border: '1px solid rgba(59, 130, 246, 0.2)',
              borderRadius: '0.5rem'
            }}>
              <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                Showing {filteredIndicators.length} of {totalCount} indicators
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <button
                  onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                  disabled={currentPage === 1}
                  style={{
                    padding: '0.5rem',
                    backgroundColor: currentPage === 1 ? 'rgba(59, 130, 246, 0.1)' : 'rgba(59, 130, 246, 0.2)',
                    border: '1px solid rgba(59, 130, 246, 0.3)',
                    borderRadius: '0.25rem',
                    color: currentPage === 1 ? '#64748b' : '#60a5fa',
                    cursor: currentPage === 1 ? 'not-allowed' : 'pointer'
                  }}
                >
                  <ChevronLeft size={16} />
                </button>
                <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                  disabled={currentPage === totalPages}
                  style={{
                    padding: '0.5rem',
                    backgroundColor: currentPage === totalPages ? 'rgba(59, 130, 246, 0.1)' : 'rgba(59, 130, 246, 0.2)',
                    border: '1px solid rgba(59, 130, 246, 0.3)',
                    borderRadius: '0.25rem',
                    color: currentPage === totalPages ? '#64748b' : '#60a5fa',
                    cursor: currentPage === totalPages ? 'not-allowed' : 'pointer'
                  }}
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            </div>

            {/* Indicators Grid */}
            {filteredIndicators.length > 0 ? (
              <div style={{ 
                display: 'grid', 
                gridTemplateColumns: 'repeat(auto-fill, minmax(400px, 1fr))', 
                gap: '1.5rem' 
              }}>
                {filteredIndicators.map((indicator) => (
                  <motion.div
                    key={indicator.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3 }}
                    style={{
                      padding: '1.5rem',
                      backgroundColor: 'rgba(10, 14, 18, 0.8)',
                      border: '1px solid rgba(59, 130, 246, 0.2)',
                      borderRadius: '1rem',
                      cursor: 'pointer',
                      transition: 'all 0.2s ease'
                    }}
                    whileHover={{ 
                      scale: 1.02,
                      borderColor: 'rgba(74, 222, 128, 0.4)'
                    }}
                    onClick={() => loadIndicatorDetails(indicator.id)}
                  >
                    {/* Header */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        {getTypeIcon(indicator.indicator_type)}
                        <span style={{ 
                          fontSize: '0.75rem', 
                          color: 'var(--text-secondary)',
                          textTransform: 'uppercase',
                          letterSpacing: '0.05em'
                        }}>
                          {indicator.indicator_type}
                        </span>
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <span style={{ 
                          fontSize: '0.625rem', 
                          color: getThreatLevelColor(indicator.threat_score),
                          backgroundColor: `${getThreatLevelColor(indicator.threat_score)}20`,
                          padding: '0.125rem 0.5rem',
                          borderRadius: '9999px',
                          textTransform: 'uppercase'
                        }}>
                          T: {indicator.threat_score}
                        </span>
                        <span style={{ 
                          fontSize: '0.625rem', 
                          color: getBahrainRelevanceColor(indicator.bahrain_score),
                          backgroundColor: `${getBahrainRelevanceColor(indicator.bahrain_score)}20`,
                          padding: '0.125rem 0.5rem',
                          borderRadius: '9999px',
                          textTransform: 'uppercase'
                        }}>
                          B: {indicator.bahrain_score}
                        </span>
                      </div>
                    </div>

                    {/* Indicator Value */}
                    <div style={{ 
                      fontSize: '1rem', 
                      color: '#fca5a5', 
                      fontFamily: '"JetBrains Mono", monospace',
                      wordBreak: 'break-all',
                      marginBottom: '1rem',
                      lineHeight: '1.4'
                    }}>
                      {indicator.indicator_value}
                    </div>

                    {/* Details */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
                        <span style={{ color: 'var(--text-secondary)' }}>Sector:</span>
                        <span style={{ color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                          <span>{getSectorIcon(indicator.targeted_sector)}</span>
                          {indicator.targeted_sector || 'General'}
                        </span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
                        <span style={{ color: 'var(--text-secondary)' }}>Source:</span>
                        <span style={{ color: 'var(--text-primary)' }}>{indicator.source}</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
                        <span style={{ color: 'var(--text-secondary)' }}>First Seen:</span>
                        <span style={{ color: 'var(--text-primary)' }}>
                          {new Date(indicator.first_seen).toLocaleDateString()}
                        </span>
                      </div>
                    </div>

                    {/* Tags */}
                    {indicator.tags.length > 0 && (
                      <div style={{ marginTop: '1rem' }}>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                          {indicator.tags.slice(0, 3).map((tag, index) => (
                            <span
                              key={index}
                              style={{
                                fontSize: '0.625rem',
                                color: '#a78bfa',
                                backgroundColor: 'rgba(139, 92, 246, 0.1)',
                                border: '1px solid rgba(139, 92, 246, 0.3)',
                                padding: '0.125rem 0.5rem',
                                borderRadius: '9999px'
                              }}
                            >
                              {tag}
                            </span>
                          ))}
                          {indicator.tags.length > 3 && (
                            <span style={{ fontSize: '0.625rem', color: 'var(--text-secondary)' }}>
                              +{indicator.tags.length - 3} more
                            </span>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Click to view details */}
                    <div style={{ 
                      marginTop: '1rem', 
                      fontSize: '0.625rem', 
                      color: '#4ade80',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.25rem'
                    }}>
                      <Eye size={12} />
                      Click for detailed analysis
                    </div>
                  </motion.div>
                ))}
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '4rem' }}>
                <Search size={48} style={{ color: '#64748b', margin: '0 auto 1rem' }} />
                <div style={{ fontSize: '1.5rem', marginBottom: '1rem', color: 'var(--text-secondary)' }}>
                  No indicators found
                </div>
                <p style={{ color: 'var(--text-secondary)' }}>
                  Try adjusting your search criteria or filters
                </p>
              </div>
            )}
          </>
        )}
      </main>

      {/* Indicator Details Modal */}
      {selectedIndicator && (
        <div style={{
          position: 'fixed',
          inset: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 50,
          padding: '2rem'
        }} onClick={() => setSelectedIndicator(null)}>
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            style={{
              backgroundColor: 'rgba(10, 14, 18, 0.95)',
              border: '1px solid rgba(59, 130, 246, 0.3)',
              borderRadius: '1rem',
              padding: '2rem',
              maxWidth: '600px',
              width: '100%',
              maxHeight: '80vh',
              overflowY: 'auto'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
              <h3 style={{ 
                fontSize: '1.5rem', 
                fontWeight: 600, 
                color: 'var(--text-bright)',
                margin: 0
              }}>
                Threat Indicator Details
              </h3>
              <button
                onClick={() => setSelectedIndicator(null)}
                style={{
                  padding: '0.5rem',
                  backgroundColor: 'rgba(239, 68, 68, 0.2)',
                  border: '1px solid rgba(239, 68, 68, 0.4)',
                  borderRadius: '0.25rem',
                  color: '#ef4444',
                  cursor: 'pointer'
                }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                  Indicator
                </label>
                <div style={{ 
                  fontSize: '1.125rem', 
                  color: '#fca5a5', 
                  fontFamily: '"JetBrains Mono", monospace',
                  wordBreak: 'break-all',
                  marginTop: '0.25rem'
                }}>
                  {selectedIndicator.indicator_value}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1rem' }}>
                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    Threat Score
                  </label>
                  <div style={{ 
                    fontSize: '2rem', 
                    color: getThreatLevelColor(selectedIndicator.threat_score),
                    fontWeight: 700,
                    fontFamily: '"JetBrains Mono", monospace'
                  }}>
                    {selectedIndicator.threat_score}/100
                  </div>
                </div>

                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    Bahrain Relevance
                  </label>
                  <div style={{ 
                    fontSize: '2rem', 
                    color: getBahrainRelevanceColor(selectedIndicator.bahrain_score),
                    fontWeight: 700,
                    fontFamily: '"JetBrains Mono", monospace'
                  }}>
                    {selectedIndicator.bahrain_score}/100
                  </div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1rem' }}>
                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    Type
                  </label>
                  <div style={{ color: 'var(--text-primary)', marginTop: '0.25rem' }}>
                    {selectedIndicator.indicator_type}
                  </div>
                </div>

                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    Sector
                  </label>
                  <div style={{ color: 'var(--text-primary)', marginTop: '0.25rem' }}>
                    {getSectorIcon(selectedIndicator.targeted_sector)} {selectedIndicator.targeted_sector || 'General'}
                  </div>
                </div>

                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    Source
                  </label>
                  <div style={{ color: 'var(--text-primary)', marginTop: '0.25rem' }}>
                    {selectedIndicator.source}
                  </div>
                </div>

                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    Status
                  </label>
                  <div style={{ color: 'var(--text-primary)', marginTop: '0.25rem' }}>
                    {selectedIndicator.status}
                  </div>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                  First Seen
                </label>
                <div style={{ color: 'var(--text-primary)', marginTop: '0.25rem' }}>
                  {new Date(selectedIndicator.first_seen).toLocaleString()}
                </div>
              </div>

              {selectedIndicator.tags.length > 0 && (
                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    Tags
                  </label>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.5rem' }}>
                    {selectedIndicator.tags.map((tag, index) => (
                      <span
                        key={index}
                        style={{
                          fontSize: '0.75rem',
                          color: '#a78bfa',
                          backgroundColor: 'rgba(139, 92, 246, 0.1)',
                          border: '1px solid rgba(139, 92, 246, 0.3)',
                          padding: '0.25rem 0.75rem',
                          borderRadius: '9999px'
                        }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        </div>
      )}

      {/* Footer */}
      <footer style={{ 
        padding: '2rem 1rem',
        borderTop: '1px solid rgba(59, 130, 246, 0.2)',
        textAlign: 'center'
      }}>
        <div style={{ display: 'flex', justifyContent: 'center', gap: '2rem', fontSize: '0.875rem' }}>
          <Link href="/cti-dashboard" style={{ color: '#60a5fa', textDecoration: 'none' }}>
            ← Back to Dashboard
          </Link>
          <Link href="/analyze" style={{ color: '#60a5fa', textDecoration: 'none' }}>
            Analyze Domain
          </Link>
        </div>
      </footer>
    </div>
  );
}
