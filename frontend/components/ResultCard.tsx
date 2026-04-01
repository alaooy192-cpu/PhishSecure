import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AnalysisResult, EmailAuthentication, ThreatAttribution } from '../utils/api';

interface ResultCardProps {
  result: AnalysisResult;
  onReset?: () => void;
}

const ResultCard: React.FC<ResultCardProps> = ({ result, onReset }: ResultCardProps) => {
  const [visible, setVisible] = useState(false);
  const [expandedSection, setExpandedSection] = useState<string | null>(null);
  
  useEffect(() => {
    setVisible(true);
  }, []);

  const { verdict, confidence, flags, threat_intel, business_context, email_authentication, threat_attribution } = result;
  // Use the verdict directly (confidence now correctly represents certainty)
  const isPhishing = verdict === 'phishing';
  
  // Get threat status color
  const getThreatStatusColor = (status?: string) => {
    switch(status) {
      case 'critical': return '#dc2626';
      case 'active_campaign': return '#ea580c';
      case 'suspicious': return '#f59e0b';
      case 'monitor': return '#3b82f6';
      case 'clear': return '#10b981';
      default: return '#6b7280';
    }
  };
  
  // Get risk level color
  const getRiskLevelColor = (level?: string) => {
    switch(level) {
      case 'critical': return '#dc2626';
      case 'high': return '#ef4444';
      case 'medium': return '#f59e0b';
      case 'low': return '#3b82f6';
      case 'minimal': return '#10b981';
      default: return '#6b7280';
    }
  };
  
  // Determine confidence level color
  const getConfidenceColor = () => {
    if (isPhishing) {
      if (confidence >= 80) return '#ef4444';
      if (confidence >= 50) return '#f87171';
      return '#fca5a5';
    } else {
      if (confidence >= 80) return 'var(--neon-green)';
      if (confidence >= 50) return 'var(--lime-green)';
      return 'var(--mint-green)';
    }
  };

  // Animation variants for terminal-style reveal
  const containerVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { 
      opacity: 1, 
      y: 0,
      transition: { 
        duration: 0.5,
        when: "beforeChildren",
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, x: -10 },
    visible: { opacity: 1, x: 0 }
  };

  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          initial="hidden"
          animate="visible"
          exit="hidden"
          variants={containerVariants}
          style={{
            position: 'relative',
            padding: '1.5rem',
            borderRadius: '0.75rem',
            backgroundColor: isPhishing ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
            backdropFilter: 'blur(8px)',
            border: `1px solid ${isPhishing ? 'rgba(239, 68, 68, 0.3)' : 'rgba(74, 222, 128, 0.3)'}`,
            boxShadow: `0 0 20px ${isPhishing ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)'}`,
            overflow: 'hidden'
          }}
        >
          {/* Terminal scanline effect */}
          <motion.div 
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              pointerEvents: 'none',
              backgroundImage: 'linear-gradient(to bottom, transparent 50%, rgba(16, 185, 129, 0.03) 50%)',
              backgroundSize: '100% 4px',
              zIndex: 2,
              opacity: 0.3
            }}
          ></motion.div>
          
          {/* Terminal flicker effect */}
          <motion.div 
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              pointerEvents: 'none',
              backgroundColor: 'transparent',
              opacity: 0.02,
              zIndex: 1
            }}
          ></motion.div>
          
          <motion.div 
            variants={itemVariants}
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              width: '100%',
              height: '4px',
              background: `linear-gradient(to right, ${isPhishing ? '#ef4444, #f87171' : 'var(--neon-green), var(--lime-green)'})`
            }}
          ></motion.div>
          
          <motion.div 
            variants={itemVariants}
            style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}
          >
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <div style={{
                padding: '0.5rem',
                borderRadius: '9999px',
                marginRight: '0.75rem',
                backgroundColor: isPhishing ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                color: isPhishing ? '#dc2626' : 'var(--neon-green)'
              }}>
                {isPhishing ? (
                  <span style={{ fontSize: '1.125rem', fontWeight: 'bold' }}>[!]</span>
                ) : (
                  <span style={{ fontSize: '1.125rem', fontWeight: 'bold' }}>[OK]</span>
                )}
              </div>
              <h2 style={{ fontFamily: '"Space Grotesk", sans-serif', fontSize: '1.5rem', fontWeight: 600, color: 'var(--text-bright)' }}>
                Analysis Result
              </h2>
            </div>
            <span style={{
              padding: '0.375rem 1rem',
              borderRadius: '9999px',
              color: 'white',
              fontSize: '0.875rem',
              fontWeight: 500,
              backgroundColor: isPhishing ? '#ef4444' : 'var(--neon-green)',
              boxShadow: isPhishing ? '0 0 10px rgba(239, 68, 68, 0.5)' : '0 0 10px rgba(74, 222, 128, 0.5)',
              border: isPhishing ? '1px solid rgba(239, 68, 68, 0.7)' : '1px solid rgba(74, 222, 128, 0.7)',
              textShadow: '0 0 5px rgba(0, 0, 0, 0.3)'
            }}>
              {confidence >= 60 ? (isPhishing ? 'Phishing Detected' : 'Legitimate Email') : 'Legitimate Email'}
            </span>
          </motion.div>
          
          <motion.div 
            variants={itemVariants}
            style={{ marginBottom: '2rem' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-secondary)' }}>Confidence Score</span>
              <span style={{ fontSize: '1.125rem', fontWeight: 'bold', color: getConfidenceColor() }}>{confidence}%</span>
            </div>
            <div style={{ height: '0.5rem', backgroundColor: 'rgba(16, 185, 129, 0.1)', borderRadius: '9999px', overflow: 'hidden' }}>
              <div 
                style={{
                  height: '100%',
                  width: `${confidence}%`,
                  backgroundColor: getConfidenceColor(),
                  borderRadius: '9999px',
                  transition: 'width 0.5s ease'
                }}
              ></div>
            </div>
          </motion.div>

          {flags.length > 0 && (
            <motion.div 
              variants={itemVariants}
              style={{ marginBottom: '1.5rem' }}
            >
              <h3 style={{ fontSize: '1.125rem', fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, marginBottom: '0.75rem', color: 'var(--text-bright)' }}>
                {isPhishing ? 'Phishing Indicators' : 'Suspicious Elements'}
              </h3>
              <ul style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {flags.map((flag: string, index: number) => (
                  <li key={index} style={{
                    backgroundColor: 'rgba(10, 14, 18, 0.7)',
                    padding: '0.75rem',
                    borderRadius: '0.5rem',
                    border: '1px solid rgba(16, 185, 129, 0.2)',
                    boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '0.75rem'
                  }}>
                    <span style={{ color: isPhishing ? '#ef4444' : '#f59e0b' }}>
                      <span style={{ fontSize: '0.875rem', fontWeight: 'bold' }}>[!]</span>
                    </span>
                    <span style={{ color: 'var(--text-primary)' }}>{flag}</span>
                  </li>
                ))}
              </ul>
            </motion.div>
          )}

          {isPhishing && (
            <motion.div 
              variants={itemVariants}
              style={{
                marginTop: '1.5rem',
                padding: '1rem',
                backgroundColor: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                borderRadius: '0.5rem',
                boxShadow: 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.05)',
                backdropFilter: 'blur(4px)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                <span style={{ fontSize: '1.125rem', fontWeight: 'bold', color: '#ef4444' }}>[!]</span>
                <div>
                  <h4 style={{ fontWeight: 500, color: '#b91c1c', marginBottom: '0.25rem' }}>Warning: Potential Phishing Attempt</h4>
                  <p style={{ color: '#b91c1c' }}>
                    This email contains characteristics commonly found in phishing attempts. 
                    Exercise caution and do not click on any links or provide personal information.
                  </p>
                </div>
              </div>
            </motion.div>
          )}

          {!isPhishing && flags.length > 0 && confidence < 90 && (
            <motion.div 
              variants={itemVariants}
              style={{
                marginTop: '1.5rem',
                padding: '1rem',
                backgroundColor: 'rgba(245, 158, 11, 0.15)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                borderRadius: '0.5rem',
                boxShadow: 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.05)',
                backdropFilter: 'blur(4px)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                <span style={{ fontSize: '1.125rem', fontWeight: 'bold', color: '#f59e0b' }}>[!]</span>
                <div>
                  <h4 style={{ fontWeight: 500, color: '#d97706', marginBottom: '0.25rem' }}>Use Caution</h4>
                  <p style={{ color: '#d97706' }}>
                    While this email appears legitimate, it contains some suspicious elements. 
                    Always verify the sender before taking any actions or clicking on links.
                  </p>
                </div>
              </div>
            </motion.div>
          )}

          {!isPhishing && flags.length === 0 && (
            <motion.div 
              variants={itemVariants}
              style={{
                marginTop: '1.5rem',
                padding: '1rem',
                backgroundColor: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid rgba(74, 222, 128, 0.3)',
                borderRadius: '0.5rem',
                boxShadow: 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.05)',
                backdropFilter: 'blur(4px)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                <span style={{ fontSize: '1.125rem', fontWeight: 'bold', color: '#10b981' }}>[OK]</span>
                <div>
                  <h4 style={{ fontWeight: 600, color: 'white', marginBottom: '0.25rem', textShadow: '0 0 5px rgba(4, 120, 87, 0.5)' }}>Email Appears Safe</h4>
                  <p style={{ color: 'white', textShadow: '0 0 3px rgba(4, 120, 87, 0.3)' }}>
                    This email appears to be legitimate with no suspicious elements detected.
                    Always practice good email security habits regardless.
                  </p>
                </div>
              </div>
            </motion.div>
          )}
          
          {/* Threat Intelligence Section */}
          {threat_intel && (
            <motion.div 
              variants={itemVariants}
              style={{
                marginTop: '1.5rem',
                padding: '1rem',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '0.5rem',
                boxShadow: 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.05)',
                backdropFilter: 'blur(4px)'
              }}
            >
              <h3 style={{ fontSize: '1.125rem', fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, marginBottom: '0.75rem', color: 'var(--text-bright)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                Threat Intelligence
              </h3>
              
              {/* Threat Status */}
              <div style={{ marginBottom: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-secondary)' }}>Threat Status</span>
                  <span style={{
                    padding: '0.25rem 0.75rem',
                    borderRadius: '9999px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    backgroundColor: getThreatStatusColor(threat_intel.threat_status) + '20',
                    color: getThreatStatusColor(threat_intel.threat_status),
                    textTransform: 'uppercase'
                  }}>
                    {threat_intel.threat_status?.replace('_', ' ')}
                  </span>
                </div>
                
                {/* Campaign Likelihood */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-secondary)' }}>Campaign Likelihood</span>
                  <span style={{
                    padding: '0.25rem 0.75rem',
                    borderRadius: '9999px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    backgroundColor: threat_intel.campaign_likelihood === 'very_high' ? '#dc262620' : 
                                    threat_intel.campaign_likelihood === 'high' ? '#ea580c20' :
                                    threat_intel.campaign_likelihood === 'medium' ? '#f59e0b20' : '#10b98120',
                    color: threat_intel.campaign_likelihood === 'very_high' ? '#dc2626' : 
                           threat_intel.campaign_likelihood === 'high' ? '#ea580c' :
                           threat_intel.campaign_likelihood === 'medium' ? '#f59e0b' : '#10b981',
                    textTransform: 'capitalize'
                  }}>
                    {threat_intel.campaign_likelihood?.replace('_', ' ')}
                  </span>
                </div>
                
                {/* Risk Level */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-secondary)' }}>Risk Level</span>
                  <span style={{
                    padding: '0.25rem 0.75rem',
                    borderRadius: '9999px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    backgroundColor: getRiskLevelColor(threat_intel.risk_level) + '20',
                    color: getRiskLevelColor(threat_intel.risk_level),
                    textTransform: 'capitalize'
                  }}>
                    {threat_intel.risk_level}
                  </span>
                </div>
              </div>
              
              {/* VirusTotal Results */}
              {threat_intel.virustotal?.success && (
                <div style={{ marginBottom: '1rem' }}>
                  <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--text-bright)' }}>🧠 VirusTotal Analysis</h4>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-primary)', lineHeight: '1.5' }}>
                    <div>Flagged by {threat_intel.virustotal.malicious_count || 0} security engines</div>
                    <div>Total engines checked: {threat_intel.virustotal.total_engines || 0}</div>
                    {threat_intel.virustotal.threat_percentage && (
                      <div>Threat percentage: {threat_intel.virustotal.threat_percentage}%</div>
                    )}
                  </div>
                </div>
              )}
              
              {/* WHOIS Information */}
              {threat_intel.whois?.success && (
                <div style={{ marginBottom: '1rem' }}>
                  <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--text-bright)' }}>📋 Domain Information</h4>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-primary)', lineHeight: '1.5' }}>
                    <div>Domain age: {threat_intel.whois.age_days} days</div>
                    {threat_intel.whois.creation_date && (
                      <div>Created: {threat_intel.whois.creation_date}</div>
                    )}
                    {threat_intel.whois.registrar && (
                      <div>Registrar: {threat_intel.whois.registrar}</div>
                    )}
                  </div>
                </div>
              )}
              
              {/* Threat Indicators */}
              {threat_intel.threat_indicators && threat_intel.threat_indicators.length > 0 && (
                <div style={{ marginBottom: '1rem' }}>
                  <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--text-bright)' }}>Threat Indicators</h4>
                  <ul style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                    {threat_intel.threat_indicators.map((indicator: string, index: number) => (
                      <li key={index} style={{
                        fontSize: '0.75rem',
                        color: 'var(--text-primary)',
                        paddingLeft: '1rem'
                      }}>
                        • {indicator}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              
              {/* Business Context */}
              {business_context && (
                <div>
                  <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--text-bright)' }}>Business Impact</h4>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-primary)', lineHeight: '1.5' }}>
                    <div>Organizational Impact: {business_context.organizational_impact}</div>
                    {business_context.recommended_actions && business_context.recommended_actions.length > 0 && (
                      <div style={{ marginTop: '0.5rem' }}>
                        <strong>Recommended Actions:</strong>
                        <ul style={{ marginTop: '0.25rem', paddingLeft: '1rem' }}>
                          {business_context.recommended_actions.map((action: string, index: number) => (
                            <li key={index} style={{ fontSize: '0.75rem' }}>{action}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </motion.div>
          )}

          {/* Email Authentication Section */}
          {email_authentication && !email_authentication.error && (
            <motion.div 
              variants={itemVariants}
              style={{
                marginTop: '1.5rem',
                padding: '1rem',
                backgroundColor: 'rgba(139, 92, 246, 0.1)',
                border: '1px solid rgba(139, 92, 246, 0.3)',
                borderRadius: '0.5rem',
                boxShadow: 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.05)',
                backdropFilter: 'blur(4px)'
              }}
            >
              <h3 style={{ fontSize: '1.125rem', fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, marginBottom: '0.75rem', color: 'var(--text-bright)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                Email Authentication
              </h3>
              
              {/* Overall Score */}
              <div style={{ marginBottom: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-secondary)' }}>Authentication Score</span>
                  <span style={{
                    padding: '0.25rem 0.75rem',
                    borderRadius: '9999px',
                    fontSize: '0.875rem',
                    fontWeight: 600,
                    backgroundColor: email_authentication.overall_status === 'strong' ? '#10b98120' :
                                    email_authentication.overall_status === 'moderate' ? '#f59e0b20' :
                                    email_authentication.overall_status === 'weak' ? '#ef444420' : '#dc262620',
                    color: email_authentication.overall_status === 'strong' ? '#10b981' :
                           email_authentication.overall_status === 'moderate' ? '#f59e0b' :
                           email_authentication.overall_status === 'weak' ? '#ef4444' : '#dc2626'
                  }}>
                    {email_authentication.overall_score}/100
                  </span>
                </div>
                <div style={{ height: '0.5rem', backgroundColor: 'rgba(139, 92, 246, 0.1)', borderRadius: '9999px', overflow: 'hidden' }}>
                  <div style={{
                    height: '100%',
                    width: `${email_authentication.overall_score}%`,
                    backgroundColor: email_authentication.overall_status === 'strong' ? '#10b981' :
                                    email_authentication.overall_status === 'moderate' ? '#f59e0b' :
                                    email_authentication.overall_status === 'weak' ? '#ef4444' : '#dc2626',
                    borderRadius: '9999px',
                    transition: 'width 0.5s ease'
                  }}></div>
                </div>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-primary)', marginTop: '0.5rem', lineHeight: '1.5' }}>
                  {email_authentication.summary}
                </p>
              </div>

              {/* SPF/DKIM/DMARC Status */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem', marginBottom: '1rem' }}>
                {/* SPF */}
                <div style={{
                  padding: '0.75rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.2)',
                  borderRadius: '0.5rem',
                  border: `1px solid ${email_authentication.spf?.status === 'pass' ? '#10b98140' : 
                                       email_authentication.spf?.status === 'partial' ? '#f59e0b40' : '#ef444440'}`
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontSize: '1rem' }}>
                      {email_authentication.spf?.status === 'pass' ? '[OK]' : 
                       email_authentication.spf?.status === 'partial' ? '[!]' : '[X]'}
                    </span>
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-bright)' }}>SPF</span>
                  </div>
                  <div style={{ fontSize: '0.625rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    {email_authentication.spf?.status || 'Unknown'}
                  </div>
                </div>

                {/* DKIM */}
                <div style={{
                  padding: '0.75rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.2)',
                  borderRadius: '0.5rem',
                  border: `1px solid ${email_authentication.dkim?.status === 'pass' ? '#10b98140' : 
                                       email_authentication.dkim?.status === 'partial' ? '#f59e0b40' : '#ef444440'}`
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontSize: '1rem' }}>
                      {email_authentication.dkim?.status === 'pass' ? '[OK]' : 
                       email_authentication.dkim?.status === 'partial' ? '[!]' : '[X]'}
                    </span>
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-bright)' }}>DKIM</span>
                  </div>
                  <div style={{ fontSize: '0.625rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    {email_authentication.dkim?.status || 'Unknown'}
                  </div>
                </div>

                {/* DMARC */}
                <div style={{
                  padding: '0.75rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.2)',
                  borderRadius: '0.5rem',
                  border: `1px solid ${email_authentication.dmarc?.status === 'pass' ? '#10b98140' : 
                                       email_authentication.dmarc?.status === 'partial' ? '#f59e0b40' : '#ef444440'}`
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontSize: '1rem' }}>
                      {email_authentication.dmarc?.status === 'pass' ? '[OK]' : 
                       email_authentication.dmarc?.status === 'partial' ? '[!]' : '[X]'}
                    </span>
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-bright)' }}>DMARC</span>
                  </div>
                  <div style={{ fontSize: '0.625rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    {email_authentication.dmarc?.status || 'Unknown'}
                  </div>
                </div>
              </div>

              {/* Expandable Details */}
              <button
                onClick={() => setExpandedSection(expandedSection === 'auth' ? null : 'auth')}
                style={{
                  width: '100%',
                  padding: '0.5rem',
                  backgroundColor: 'rgba(139, 92, 246, 0.1)',
                  border: '1px solid rgba(139, 92, 246, 0.3)',
                  borderRadius: '0.375rem',
                  color: '#a78bfa',
                  fontSize: '0.75rem',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '0.5rem'
                }}
              >
                {expandedSection === 'auth' ? '▲ Hide Details' : '▼ Show Details'}
              </button>

              {expandedSection === 'auth' && (
                <div style={{ marginTop: '1rem', fontSize: '0.75rem', color: 'var(--text-primary)' }}>
                  {email_authentication.spf && (
                    <div style={{ marginBottom: '0.75rem' }}>
                      <strong style={{ color: 'var(--text-bright)' }}>SPF:</strong>
                      <p style={{ marginTop: '0.25rem' }}>{email_authentication.spf.explanation}</p>
                      {email_authentication.spf.technical_details?.map((detail, i) => (
                        <div key={i} style={{ paddingLeft: '1rem', color: 'var(--text-secondary)', fontSize: '0.625rem' }}>• {detail}</div>
                      ))}
                    </div>
                  )}
                  {email_authentication.dmarc && (
                    <div style={{ marginBottom: '0.75rem' }}>
                      <strong style={{ color: 'var(--text-bright)' }}>DMARC:</strong>
                      <p style={{ marginTop: '0.25rem' }}>{email_authentication.dmarc.explanation}</p>
                      {email_authentication.dmarc.technical_details?.map((detail, i) => (
                        <div key={i} style={{ paddingLeft: '1rem', color: 'var(--text-secondary)', fontSize: '0.625rem' }}>• {detail}</div>
                      ))}
                    </div>
                  )}
                  {email_authentication.dkim && (
                    <div style={{ marginBottom: '0.75rem' }}>
                      <strong style={{ color: 'var(--text-bright)' }}>DKIM:</strong>
                      <p style={{ marginTop: '0.25rem' }}>{email_authentication.dkim.explanation}</p>
                      {email_authentication.dkim.technical_details?.map((detail, i) => (
                        <div key={i} style={{ paddingLeft: '1rem', color: 'var(--text-secondary)', fontSize: '0.625rem' }}>• {detail}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </motion.div>
          )}

          {/* Threat Attribution Section */}
          {threat_attribution && !threat_attribution.error && (
            <motion.div 
              variants={itemVariants}
              style={{
                marginTop: '1.5rem',
                padding: '1rem',
                backgroundColor: 'rgba(236, 72, 153, 0.1)',
                border: '1px solid rgba(236, 72, 153, 0.3)',
                borderRadius: '0.5rem',
                boxShadow: 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.05)',
                backdropFilter: 'blur(4px)'
              }}
            >
              <h3 style={{ fontSize: '1.125rem', fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, marginBottom: '0.75rem', color: 'var(--text-bright)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                Threat Attribution
              </h3>

              {/* Attribution Confidence */}
              <div style={{ marginBottom: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-secondary)' }}>Attribution Confidence</span>
                  <span style={{
                    padding: '0.25rem 0.75rem',
                    borderRadius: '9999px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    backgroundColor: threat_attribution.attribution_confidence === 'high' ? '#ef444420' :
                                    threat_attribution.attribution_confidence === 'medium' ? '#f59e0b20' :
                                    threat_attribution.attribution_confidence === 'low' ? '#3b82f620' : '#6b728020',
                    color: threat_attribution.attribution_confidence === 'high' ? '#ef4444' :
                           threat_attribution.attribution_confidence === 'medium' ? '#f59e0b' :
                           threat_attribution.attribution_confidence === 'low' ? '#3b82f6' : '#6b7280',
                    textTransform: 'uppercase'
                  }}>
                    {threat_attribution.attribution_confidence}
                  </span>
                </div>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-primary)', lineHeight: '1.5' }}>
                  {threat_attribution.summary}
                </p>
              </div>

              {/* Phishing Kit Match */}
              {threat_attribution.phishing_kit?.has_kit_match && threat_attribution.phishing_kit.highest_match && (
                <div style={{
                  marginBottom: '1rem',
                  padding: '0.75rem',
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: '0.5rem'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '1rem', color: '#ef4444' }}>[MALWARE]</span>
                    <span style={{ fontSize: '0.875rem', fontWeight: 600, color: '#ef4444' }}>
                      Phishing Kit Detected: {threat_attribution.phishing_kit.highest_match.kit_name}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                    {threat_attribution.phishing_kit.highest_match.description}
                  </p>
                  <div style={{ fontSize: '0.625rem', color: 'var(--text-secondary)' }}>
                    <span>Match Score: {threat_attribution.phishing_kit.highest_match.match_score}%</span>
                    <span style={{ margin: '0 0.5rem' }}>•</span>
                    <span>First Seen: {threat_attribution.phishing_kit.highest_match.first_seen}</span>
                    <span style={{ margin: '0 0.5rem' }}>•</span>
                    <span>Threat Level: {threat_attribution.phishing_kit.highest_match.threat_level}</span>
                  </div>
                  {threat_attribution.phishing_kit.highest_match.typical_targets && (
                    <div style={{ fontSize: '0.625rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                      Typical Targets: {threat_attribution.phishing_kit.highest_match.typical_targets.join(', ')}
                    </div>
                  )}
                </div>
              )}

              {/* Geographic Origin */}
              {threat_attribution.geographic_origin?.likely_regions && threat_attribution.geographic_origin.likely_regions.length > 0 && (
                <div style={{ marginBottom: '1rem' }}>
                  <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--text-bright)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    Geographic Origin
                  </h4>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {threat_attribution.geographic_origin.likely_regions.map((region, index) => (
                      <span key={index} style={{
                        padding: '0.25rem 0.75rem',
                        backgroundColor: 'rgba(236, 72, 153, 0.2)',
                        border: '1px solid rgba(236, 72, 153, 0.4)',
                        borderRadius: '9999px',
                        fontSize: '0.75rem',
                        color: '#f472b6'
                      }}>
                        {region}
                      </span>
                    ))}
                  </div>
                  {threat_attribution.geographic_origin.bulletproof_hosting_likely && (
                    <div style={{ fontSize: '0.625rem', color: '#ef4444', marginTop: '0.5rem' }}>
                      [WARNING] Bulletproof hosting suspected
                    </div>
                  )}
                </div>
              )}

              {/* Attack Patterns */}
              {threat_attribution.attack_patterns?.patterns && threat_attribution.attack_patterns.patterns.length > 0 && (
                <div style={{ marginBottom: '1rem' }}>
                  <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--text-bright)' }}>
                    Attack Patterns Detected
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {threat_attribution.attack_patterns.patterns.map((pattern, index) => (
                      <div key={index} style={{
                        padding: '0.5rem 0.75rem',
                        backgroundColor: 'rgba(0, 0, 0, 0.2)',
                        borderRadius: '0.375rem',
                        fontSize: '0.75rem'
                      }}>
                        <span style={{ color: '#f472b6', fontWeight: 500 }}>
                          {pattern.type.replace(/_/g, ' ').toUpperCase()}
                        </span>
                        <span style={{ color: 'var(--text-secondary)', marginLeft: '0.5rem' }}>
                          {pattern.description}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Expandable Details */}
              <button
                onClick={() => setExpandedSection(expandedSection === 'attribution' ? null : 'attribution')}
                style={{
                  width: '100%',
                  padding: '0.5rem',
                  backgroundColor: 'rgba(236, 72, 153, 0.1)',
                  border: '1px solid rgba(236, 72, 153, 0.3)',
                  borderRadius: '0.375rem',
                  color: '#f472b6',
                  fontSize: '0.75rem',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '0.5rem'
                }}
              >
                {expandedSection === 'attribution' ? '▲ Hide Technical Details' : '▼ Show Technical Details'}
              </button>

              {expandedSection === 'attribution' && (
                <div style={{ marginTop: '1rem', fontSize: '0.75rem', color: 'var(--text-primary)' }}>
                  {/* TLD Analysis */}
                  {threat_attribution.tld_analysis && (
                    <div style={{ marginBottom: '0.75rem' }}>
                      <strong style={{ color: 'var(--text-bright)' }}>TLD Analysis (.{threat_attribution.tld_analysis.tld}):</strong>
                      <p style={{ marginTop: '0.25rem' }}>{threat_attribution.tld_analysis.explanation}</p>
                      <div style={{ color: 'var(--text-secondary)', fontSize: '0.625rem' }}>
                        Risk Level: {threat_attribution.tld_analysis.risk_level}
                      </div>
                    </div>
                  )}
                  
                  {/* Registrar Analysis */}
                  {threat_attribution.registrar_analysis && (
                    <div style={{ marginBottom: '0.75rem' }}>
                      <strong style={{ color: 'var(--text-bright)' }}>Registrar Analysis:</strong>
                      <p style={{ marginTop: '0.25rem' }}>{threat_attribution.registrar_analysis.explanation}</p>
                      <div style={{ color: 'var(--text-secondary)', fontSize: '0.625rem' }}>
                        Risk Level: {threat_attribution.registrar_analysis.risk_level}
                      </div>
                    </div>
                  )}

                  {/* Attribution Indicators */}
                  {threat_attribution.indicators && threat_attribution.indicators.length > 0 && (
                    <div>
                      <strong style={{ color: 'var(--text-bright)' }}>Attribution Indicators:</strong>
                      <ul style={{ marginTop: '0.25rem', paddingLeft: '1rem' }}>
                        {threat_attribution.indicators.map((indicator, index) => (
                          <li key={index} style={{ color: 'var(--text-secondary)', fontSize: '0.625rem' }}>
                            {indicator}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </motion.div>
          )}
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default ResultCard;
