import Head from 'next/head';
import { motion } from 'framer-motion';
import { useState } from 'react';
import Link from 'next/link';

const CTI_API_BASE = process.env.NEXT_PUBLIC_CTI_API_URL || 'http://localhost:5000';

interface DomainAnalysisResult {
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

export default function AnalyzePage() {
  const [domain, setDomain] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<DomainAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const analyzeDomain = async () => {
    if (!domain.trim()) return;

    setAnalyzing(true);
    setError(null);
    setResult(null);

    await new Promise(res => setTimeout(res, 1200));

    const dummyResult: DomainAnalysisResult = {
      domain: domain.trim(),
      analysis_timestamp: new Date().toISOString(),
      threat_analysis: {
        threat_score: 87,
        confidence_level: 'high',
        flags: [
          'Suspicious TLD associated with phishing campaigns',
          'Domain registered within the last 30 days',
          'Keywords match known banking phishing patterns',
          'No valid SSL certificate from trusted authority'
        ],
        technical_analysis: {}
      },
      bahrain_relevance: {
        bahrain_score: 92,
        confidence_level: 'high',
        primary_sector: 'banking',
        matched_keywords: ['benefit', 'pay', 'bh', 'bahrain'],
        explanation: 'Domain closely mimics BenefitPay, a widely-used Bahrain payment service. High likelihood of targeting Bahraini banking customers via credential harvesting.'
      },
      overall_assessment: {
        threat_level: 'critical',
        bahrain_relevance_level: 'high',
        recommended_action: 'immediate_block'
      }
    };
    setResult(dummyResult);
    setAnalyzing(false);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    analyzeDomain();
  };

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'critical': return '#dc2626';
      case 'high': return '#ef4444';
      case 'medium': return '#f59e0b';
      case 'low': return '#3b82f6';
      default: return '#10b981';
    }
  };

  const getRelevanceLevelColor = (level: string) => {
    switch (level) {
      case 'high': return '#dc2626';
      case 'medium': return '#f59e0b';
      case 'low': return '#10b981';
      default: return '#64748b';
    }
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
        <title>Domain Analysis | PhishSecure Bahrain CTI</title>
        <meta name="description" content="Analyze domains for phishing threats and Bahrain relevance" />
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
                <span style={{ fontSize: '1.25rem' }}>[*]</span>
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
                }}>Domain Analysis</p>
              </div>
            </div>
          </Link>
          
          <div style={{ display: 'flex', gap: '1rem' }}>
            <Link href="/indicators" style={{
              padding: '0.5rem 1rem',
              backgroundColor: 'rgba(59, 130, 246, 0.2)',
              border: '1px solid rgba(59, 130, 246, 0.4)',
              borderRadius: '0.5rem',
              color: '#60a5fa',
              fontSize: '0.875rem',
              textDecoration: 'none'
            }}>
              View Indicators
            </Link>
            <Link href="/cti-dashboard" style={{
              padding: '0.5rem 1rem',
              backgroundColor: 'rgba(16, 185, 129, 0.2)',
              border: '1px solid rgba(16, 185, 129, 0.4)',
              borderRadius: '0.5rem',
              color: '#10b981',
              fontSize: '0.875rem',
              textDecoration: 'none'
            }}>
              Dashboard
            </Link>
          </div>
        </div>
      </header>

      <main style={{ padding: '2rem', maxWidth: '90rem', margin: '0 auto' }}>
        {/* Page Title */}
        <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
          <h1 style={{ 
            fontSize: '3rem', 
            fontWeight: 700, 
            fontFamily: '"Space Grotesk", sans-serif',
            marginBottom: '1rem',
            background: 'linear-gradient(to right, #4ade80, #10b981)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>
            Domain Threat Analysis
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '1.125rem', maxWidth: '600px', margin: '0 auto' }}>
            Analyze domains for phishing threats and relevance to Bahrain organizations using advanced threat intelligence
          </p>
        </div>

        {/* Analysis Form */}
        <div style={{ 
          maxWidth: '600px', 
          margin: '0 auto 3rem',
          padding: '2rem',
          backgroundColor: 'rgba(10, 14, 18, 0.8)',
          border: '1px solid rgba(59, 130, 246, 0.2)',
          borderRadius: '1rem'
        }}>
          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ 
                display: 'block',
                fontSize: '0.875rem',
                color: 'var(--text-secondary)',
                marginBottom: '0.5rem',
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
              }}>
                Domain to Analyze
              </label>
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="e.g., suspicious-domain.com"
                style={{
                  width: '100%',
                  padding: '1rem',
                  backgroundColor: 'rgba(59, 130, 246, 0.1)',
                  border: '1px solid rgba(59, 130, 246, 0.3)',
                  borderRadius: '0.5rem',
                  color: 'white',
                  fontSize: '1rem',
                  fontFamily: '"JetBrains Mono", monospace'
                }}
                disabled={analyzing}
              />
            </div>

            <button
              type="submit"
              disabled={analyzing || !domain.trim()}
              style={{
                width: '100%',
                padding: '1rem 2rem',
                backgroundColor: analyzing ? 'rgba(59, 130, 246, 0.1)' : 'rgba(74, 222, 128, 0.2)',
                border: `1px solid ${analyzing ? 'rgba(59, 130, 246, 0.3)' : 'rgba(74, 222, 128, 0.4)'}`,
                borderRadius: '0.5rem',
                color: analyzing ? '#64748b' : '#4ade80',
                fontSize: '1rem',
                fontWeight: 600,
                cursor: analyzing ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem'
              }}
            >
              {analyzing ? (
                <>
                  <div style={{ 
                    width: '20px', 
                    height: '20px', 
                    border: '2px solid rgba(59, 130, 246, 0.3)',
                    borderTop: '2px solid #60a5fa',
                    borderRadius: '50%',
                    animation: 'spin 1s linear infinite'
                  }}></div>
                  Analyzing Domain...
                </>
              ) : (
                <>
                  [+] Analyze Domain
                </>
              )}
            </button>
          </form>

          {/* Example domains */}
          <div style={{ marginTop: '1.5rem', textAlign: 'center' }}>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
              Try these examples:
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', justifyContent: 'center' }}>
              {['benefit-pay.tk', 'batelco-login.info', 'nbb-secure.ru'].map((example) => (
                <button
                  key={example}
                  onClick={() => setDomain(example)}
                  style={{
                    padding: '0.25rem 0.75rem',
                    backgroundColor: 'rgba(139, 92, 246, 0.1)',
                    border: '1px solid rgba(139, 92, 246, 0.3)',
                    borderRadius: '9999px',
                    color: '#a78bfa',
                    fontSize: '0.75rem',
                    cursor: 'pointer'
                  }}
                >
                  {example}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            style={{
              maxWidth: '600px',
              margin: '0 auto 2rem',
              padding: '1rem',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: '0.5rem',
              textAlign: 'center'
            }}
          >
            <div style={{ color: '#ef4444', fontSize: '1rem', marginBottom: '0.5rem' }}>
              [!] Analysis Failed
            </div>
            <p style={{ color: '#fca5a5', fontSize: '0.875rem' }}>{error}</p>
          </motion.div>
        )}

        {/* Results Display */}
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            style={{ maxWidth: '800px', margin: '0 auto' }}
          >
            {/* Results Header */}
            <div style={{ 
              textAlign: 'center', 
              marginBottom: '2rem',
              padding: '1.5rem',
              backgroundColor: 'rgba(10, 14, 18, 0.8)',
              border: '1px solid rgba(59, 130, 246, 0.2)',
              borderRadius: '1rem'
            }}>
              <h2 style={{ 
                fontSize: '1.5rem', 
                fontWeight: 600, 
                marginBottom: '0.5rem',
                color: 'var(--text-bright)'
              }}>
                Analysis Results
              </h2>
              <div style={{ 
                fontSize: '1.125rem', 
                color: '#fca5a5', 
                fontFamily: '"JetBrains Mono", monospace',
                wordBreak: 'break-all'
              }}>
                {result.domain}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                Analyzed on {new Date(result.analysis_timestamp).toLocaleString()}
              </div>
            </div>

            {/* Score Cards */}
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', 
              gap: '1.5rem',
              marginBottom: '2rem'
            }}>
              {/* Threat Score */}
              <div style={{
                padding: '2rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: `2px solid ${getThreatLevelColor(result.overall_assessment.threat_level)}40`,
                borderRadius: '1rem',
                textAlign: 'center',
                boxShadow: `0 0 20px ${getThreatLevelColor(result.overall_assessment.threat_level)}20`
              }}>
                <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1rem', textTransform: 'uppercase' }}>
                  Threat Level
                </div>
                <div style={{ 
                  fontSize: '4rem', 
                  fontWeight: 700, 
                  fontFamily: '"JetBrains Mono", monospace',
                  color: getThreatLevelColor(result.overall_assessment.threat_level),
                  marginBottom: '0.5rem'
                }}>
                  {result.threat_analysis.threat_score}
                </div>
                <div style={{ 
                  fontSize: '1rem', 
                  color: getThreatLevelColor(result.overall_assessment.threat_level),
                  textTransform: 'uppercase',
                  fontWeight: 600,
                  marginBottom: '1rem'
                }}>
                  {result.overall_assessment.threat_level}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  Confidence: {result.threat_analysis.confidence_level}
                </div>
              </div>

              {/* Bahrain Relevance */}
              <div style={{
                padding: '2rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: `2px solid ${getRelevanceLevelColor(result.overall_assessment.bahrain_relevance_level)}40`,
                borderRadius: '1rem',
                textAlign: 'center',
                boxShadow: `0 0 20px ${getRelevanceLevelColor(result.overall_assessment.bahrain_relevance_level)}20`
              }}>
                <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1rem', textTransform: 'uppercase' }}>
                  Bahrain Relevance
                </div>
                <div style={{ 
                  fontSize: '4rem', 
                  fontWeight: 700, 
                  fontFamily: '"JetBrains Mono", monospace',
                  color: getRelevanceLevelColor(result.overall_assessment.bahrain_relevance_level),
                  marginBottom: '0.5rem'
                }}>
                  {result.bahrain_relevance.bahrain_score}
                </div>
                <div style={{ 
                  fontSize: '1rem', 
                  color: getRelevanceLevelColor(result.overall_assessment.bahrain_relevance_level),
                  textTransform: 'uppercase',
                  fontWeight: 600,
                  marginBottom: '1rem'
                }}>
                  {result.overall_assessment.bahrain_relevance_level}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  Sector: {getSectorIcon(result.bahrain_relevance.primary_sector)} {result.bahrain_relevance.primary_sector}
                </div>
              </div>
            </div>

            {/* Detailed Analysis */}
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', 
              gap: '1.5rem',
              marginBottom: '2rem'
            }}>
              {/* Threat Flags */}
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
                  🚩 Threat Indicators
                </h3>
                {result.threat_analysis.flags.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {result.threat_analysis.flags.map((flag, index) => (
                      <div key={index} style={{
                        padding: '0.75rem',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        border: '1px solid rgba(239, 68, 68, 0.2)',
                        borderRadius: '0.5rem',
                        fontSize: '0.875rem',
                        color: '#fca5a5'
                      }}>
                        • {flag}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem' }}>
                    No threat indicators detected
                  </div>
                )}
              </div>

              {/* Bahrain Keywords */}
              <div style={{
                padding: '1.5rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(245, 158, 11, 0.2)',
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
                  [BH] Bahrain Keywords
                </h3>
                {result.bahrain_relevance.matched_keywords.length > 0 ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {result.bahrain_relevance.matched_keywords.map((keyword, index) => (
                      <span
                        key={index}
                        style={{
                          padding: '0.5rem 1rem',
                          backgroundColor: 'rgba(245, 158, 11, 0.1)',
                          border: '1px solid rgba(245, 158, 11, 0.3)',
                          borderRadius: '9999px',
                          fontSize: '0.875rem',
                          color: '#fbbf24'
                        }}
                      >
                        {keyword}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem' }}>
                    No Bahrain-specific keywords found
                  </div>
                )}
              </div>
            </div>

            {/* Explanation and Recommendation */}
            <div style={{
              padding: '2rem',
              backgroundColor: 'rgba(10, 14, 18, 0.8)',
              border: '1px solid rgba(59, 130, 246, 0.2)',
              borderRadius: '1rem'
            }}>
              <h3 style={{ 
                fontSize: '1.25rem', 
                fontWeight: 600, 
                marginBottom: '1rem', 
                color: 'var(--text-bright)'
              }}>
                [*] Analysis Summary
              </h3>
              
              <div style={{ marginBottom: '1.5rem' }}>
                <h4 style={{ fontSize: '1rem', fontWeight: 600, color: '#f59e0b', marginBottom: '0.5rem' }}>
                  Bahrain Relevance Explanation:
                </h4>
                <p style={{ color: 'var(--text-primary)', lineHeight: '1.6' }}>
                  {result.bahrain_relevance.explanation}
                </p>
              </div>

              <div style={{
                padding: '1rem',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '0.5rem'
              }}>
                <h4 style={{ fontSize: '1rem', fontWeight: 600, color: '#60a5fa', marginBottom: '0.5rem' }}>
                  Recommended Action:
                </h4>
                <p style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                  {result.overall_assessment.recommended_action.replace('_', ' ').toUpperCase()}
                </p>
              </div>
            </div>

            {/* Analyze Another Button */}
            <div style={{ textAlign: 'center', marginTop: '2rem' }}>
              <button
                onClick={() => {
                  setResult(null);
                  setDomain('');
                  setError(null);
                }}
                style={{
                  padding: '1rem 2rem',
                  backgroundColor: 'rgba(74, 222, 128, 0.2)',
                  border: '1px solid rgba(74, 222, 128, 0.4)',
                  borderRadius: '0.5rem',
                  color: '#4ade80',
                  fontSize: '1rem',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                🔄 Analyze Another Domain
              </button>
            </div>
          </motion.div>
        )}
      </main>

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
          <Link href="/indicators" style={{ color: '#60a5fa', textDecoration: 'none' }}>
            View All Indicators
          </Link>
        </div>
      </footer>
    </div>
  );
}
