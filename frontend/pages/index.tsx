// index.tsx
import Head from 'next/head';
import { EmailInput } from '../components/EmailInput';
import { motion, AnimatePresence } from 'framer-motion';
import { useState, useEffect } from 'react';
import { analyzeEmail, AnalysisResult } from '../utils/api';
import ResultCard from '../components/ResultCard';
import DebugPanel from '../components/DebugPanel';

// Import dynamic from next/dynamic
import dynamic from 'next/dynamic';
import { useCallback } from 'react';

// Animated particles component
const ParticlesBackgroundComponent = () => {
  useEffect(() => {
    // Create particles
    const particlesContainer = document.querySelector('.particles-bg');
    const particleCount = 50;
    
    if (particlesContainer) {
      // Clear any existing particles
      particlesContainer.innerHTML = '';
      
      for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.classList.add('particle');
        
        // Random position
        const x = Math.random() * 100;
        const y = Math.random() * 100;
        particle.style.left = `${x}%`;
        particle.style.top = `${y}%`;
        
        // Random size
        const size = Math.random() * 3 + 1;
        particle.style.width = `${size}px`;
        particle.style.height = `${size}px`;
        
        // Random opacity
        particle.style.opacity = (Math.random() * 0.5 + 0.3).toString();
        
        // Animation
        particle.style.animation = `float ${Math.random() * 10 + 5}s ease-in-out infinite`;
        particle.style.animationDelay = `${Math.random() * 5}s`;
        
        particlesContainer.appendChild(particle);
      }
    }
    
    return () => {
      if (particlesContainer) {
        particlesContainer.innerHTML = '';
      }
    };
  }, []);
  
  return <div className="particles-bg" />;
};

// Use dynamic import with ssr: false to prevent server-side rendering
const ParticlesBackground = dynamic(
  () => Promise.resolve(ParticlesBackgroundComponent),
  { ssr: false }
);

// Radar scanning animation component
const ScannerAnimationComponent = () => {
  return (
    <div className="scanner" style={{
      width: '120px',
      height: '120px',
      borderRadius: '50%',
      border: '2px solid rgba(74, 222, 128, 0.5)',
      margin: '0 auto 2.5rem auto',
      position: 'relative',
      boxShadow: '0 0 15px rgba(74, 222, 128, 0.3), inset 0 0 10px rgba(16, 185, 129, 0.2)'
    }}>
      <div style={{
        position: 'absolute',
        top: '50%',
        left: '50%',
        width: '50%',
        height: '2px',
        background: 'linear-gradient(to right, rgba(74, 222, 128, 1), rgba(16, 185, 129, 0.7))',
        transformOrigin: 'left center',
        animation: 'spin 2s linear infinite',
        boxShadow: '0 0 8px rgba(74, 222, 128, 0.8)'
      }} />
      <div style={{
        position: 'absolute',
        top: '50%',
        left: '50%',
        transform: 'translate(-50%, -50%)',
        width: '12px',
        height: '12px',
        borderRadius: '50%',
        backgroundColor: '#4ade80',
        boxShadow: '0 0 10px rgba(74, 222, 128, 0.8)',
        animation: 'pulse 2s ease-in-out infinite'
      }} />
      <div className="scanner-grid" style={{
        position: 'absolute',
        inset: '0',
        borderRadius: '50%',
        background: 'radial-gradient(circle, transparent 0%, transparent 70%, rgba(74, 222, 128, 0.1) 100%)',
        backgroundSize: '10px 10px',
        opacity: 0.5
      }}></div>
    </div>
  );
};

// Use dynamic import with ssr: false to prevent server-side rendering
const ScannerAnimation = dynamic(
  () => Promise.resolve(ScannerAnimationComponent),
  { ssr: false }
);

// Matrix code rain component
const MatrixCodeRainComponent = () => {
  useEffect(() => {
    const container = document.getElementById('matrix-code-container');
    if (!container) return;
    
    // Clear any existing content
    container.innerHTML = '';
    
    // Create matrix code lines
    for (let i = 0; i < 15; i++) {
      const codeLine = document.createElement('div');
      codeLine.className = 'code-line';
      
      // Apply random styles
      codeLine.style.left = `${Math.random() * 100}%`;
      codeLine.style.top = `-${Math.random() * 50}px`;
      codeLine.style.opacity = `${Math.random() * 0.5 + 0.25}`;
      codeLine.style.animationDuration = `${Math.random() * 10 + 5}s`;
      codeLine.style.animationDelay = `${Math.random() * 5}s`;
      
      // Generate random characters
      const charCount = Math.floor(Math.random() * 20) + 10;
      let text = '';
      for (let j = 0; j < charCount; j++) {
        text += String.fromCharCode(Math.floor(Math.random() * 93) + 33);
      }
      
      codeLine.textContent = text;
      container.appendChild(codeLine);
    }
    
    return () => {
      if (container) {
        container.innerHTML = '';
      }
    };
  }, []);
  
  return null;
};

// Use dynamic import with ssr: false to prevent server-side rendering
const MatrixCodeRain = dynamic(
  () => Promise.resolve(MatrixCodeRainComponent),
  { ssr: false }
);

export default function Home() {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  const handleEmailSubmit = async (email: string) => {
    // Reset previous results and errors
    console.log('Starting analysis, resetting state...');
    setAnalysisResult(null);
    setError(null);
    setIsAnalyzing(true);
    console.log('isAnalyzing set to true');
    
    try {
      console.log('Calling analyzeEmail with:', email);
      console.log('Current URL:', window.location.href);
      const result = await analyzeEmail(email);
      console.log('Analysis result received:', result);
      console.log('Setting analysis result in state...');
      setAnalysisResult(result);
      console.log('Analysis result set in state');
    } catch (err) {
      console.error('Error analyzing email:', err);
      console.error('Full error details:', err);
      setError(`Failed to analyze email: ${err.message || err}`);
      console.log('Error state set');
    } finally {
      console.log('Setting isAnalyzing to false...');
      setIsAnalyzing(false);
      console.log('isAnalyzing set to false');
    }
  };
  
  const handleReset = () => {
    // Reset the analysis state
    setAnalysisResult(null);
    setError(null);
  };

  return (
    <div className="min-h-screen text-white">
      <Head>
        <title>PhishSecure | Email Security</title>
        <meta name="description" content="AI-Powered Phishing Email Detection" />
        <link rel="icon" href="/favicon.ico" />
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet" />
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet" />
      </Head>

      {/* Animated particles background */}
      <ParticlesBackground />
      
      {/* Cyberpunk grid overlay */}
      <div className="cyber-grid"></div>
      
      {/* Animated glow elements */}
      <div style={{ position: 'absolute', inset: 0, overflow: 'hidden', pointerEvents: 'none' }}>
        {/* Primary glow */}
        <div style={{ 
          position: 'absolute', 
          top: '10%', 
          left: '5%', 
          width: '30rem', 
          height: '30rem', 
          background: 'radial-gradient(circle, rgba(74, 222, 128, 0.8), rgba(16, 185, 129, 0.5))',
          filter: 'blur(90px)', 
          opacity: 0.15,
          borderRadius: '50%',
          zIndex: -1,
          animation: 'pulse-slow 8s ease-in-out infinite alternate'
        }}></div>
        
        {/* Secondary glow */}
        <div style={{ 
          position: 'absolute', 
          bottom: '10%', 
          right: '5%', 
          width: '25rem', 
          height: '25rem', 
          background: 'radial-gradient(circle, rgba(52, 211, 153, 0.8), rgba(16, 185, 129, 0.5))',
          filter: 'blur(70px)', 
          opacity: 0.15,
          borderRadius: '50%',
          zIndex: -1,
          animation: 'pulse-slow 10s ease-in-out infinite alternate-reverse'
        }}></div>
        
        {/* Matrix code rain effect - Empty div as placeholder for client-side rendering */}
        <div className="matrix-code" id="matrix-code-container"></div>
        <MatrixCodeRain />
        
        {/* Decorative elements */}
        {[...Array(6)].map((_, i) => (
          <div 
            key={`dot-${i}`} 
            className="decorative-dot" 
            style={{
              top: `${Math.random() * 100}%`,
              left: `${Math.random() * 100}%`,
              opacity: Math.random() * 0.5 + 0.3
            }}
          />
        ))}
        
        {[...Array(4)].map((_, i) => (
          <div 
            key={`trace-${i}`} 
            className="circuit-trace" 
            style={{
              top: `${Math.random() * 100}%`,
              left: `${Math.random() * 100}%`,
              transform: `rotate(${Math.random() * 360}deg)`,
              width: `${Math.random() * 100 + 50}px`
            }}
          />
        ))}
      </div>

      {/* Header - Cyberpunk Style */}
      <header style={{ 
        position: 'relative', 
        zIndex: 10, 
        padding: '1.5rem',
        borderBottom: '1px solid rgba(59, 130, 246, 0.2)'
      }}>
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          maxWidth: '90rem', 
          marginLeft: 'auto', 
          marginRight: 'auto'
        }}>
          <motion.div 
            className="neon-border"
            style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '0.5rem',
              padding: '0.5rem 1rem',
              borderRadius: '0.5rem'
            }}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5 }}
          >
            <div className="header-icon-container" style={{ 
              background: 'linear-gradient(to right, #4ade80, #10b981)', 
              padding: '0.5rem', 
              borderRadius: '0.5rem',
              boxShadow: '0 0 10px rgba(74, 222, 128, 0.5)'
            }}>
              <span style={{ fontSize: '1.25rem' }}>🔒</span>
            </div>
            <h2 style={{ 
              fontSize: '1.5rem', 
              fontWeight: 'bold', 
              letterSpacing: '-0.025em',
              background: 'linear-gradient(to right, #4ade80, #10b981, #059669)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent'
            }}>PhishSecure</h2>
          </motion.div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              <div className="header-badge" style={{
                padding: '0.25rem 0.75rem',
                borderRadius: '9999px',
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                width: '100%',
                justifyContent: 'center'
              }}>
                <a 
                  href="https://github.com/wxmohd/PhishSecure" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    gap: '0.5rem',
                    color: '#bfdbfe',
                    textDecoration: 'none'
                  }}
                >
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16" style={{
                    color: '#22d3ee',
                    width: '16px',
                    height: '16px'
                  }} className="header-icon">
                    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"/>
                  </svg>
                  <span style={{ fontSize: '0.75rem' }}>GitHub</span>
                </a>
              </div>
            </motion.div>
            
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              <div className="header-badge" style={{
                padding: '0.25rem 0.75rem',
                borderRadius: '9999px',
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                width: '100%',
                justifyContent: 'center'
              }}>
                <span style={{
                  width: '0.5rem',
                  height: '0.5rem',
                  borderRadius: '50%',
                  backgroundColor: '#22d3ee',
                  boxShadow: '0 0 8px #22d3ee',
                  animation: 'pulse 2s infinite'
                }}></span>
                <span style={{ fontSize: '0.75rem', color: '#bfdbfe' }}>AI Powered</span>
              </div>
            </motion.div>
          </div>
        </div>
      </header>

      <motion.main
        style={{
          position: 'relative',
          zIndex: 10,
          padding: '4rem 1.5rem',
          maxWidth: '80rem',
          marginLeft: 'auto',
          marginRight: 'auto'
        }}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.8, delay: 0.3 }}
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '3rem', alignItems: 'center' }}>
          {/* Left column - Hero content */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.5 }}
          >
            <div style={{
              display: 'inline-block',
              padding: '0.5rem 0.75rem',
              marginBottom: '1.5rem',
              borderRadius: '9999px',
              background: 'linear-gradient(to right, rgba(74, 222, 128, 0.2), rgba(16, 185, 129, 0.15))',
              backdropFilter: 'blur(4px)',
              border: '1px solid rgba(74, 222, 128, 0.4)',
              boxShadow: '0 0 10px rgba(74, 222, 128, 0.2)'
            }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#4ade80', letterSpacing: '0.05em', textTransform: 'uppercase' }}>Neural Shield Active</span>
            </div>
            
            <h1 style={{ 
              fontSize: 'clamp(2rem, 5vw, 3.75rem)', 
              fontWeight: '800', 
              marginBottom: '1.5rem', 
              fontFamily: '"Space Grotesk", sans-serif',
              lineHeight: '1.1',
              letterSpacing: '-0.02em'
            }}>
              <span style={{ 
                backgroundClip: 'text', 
                WebkitBackgroundClip: 'text',
                color: 'transparent', 
                backgroundImage: 'linear-gradient(to right, #4ade80, #10b981, #059669)',
                textShadow: '0 0 25px rgba(16, 185, 129, 0.5)'
              }}>AI That Hunts Threats</span>
              <br /><span style={{ color: 'var(--text-bright)' }}>Before You Click</span>
            </h1>
            
            <p style={{ 
              fontSize: '1.125rem', 
              color: 'var(--text-primary)', 
              marginBottom: '2rem', 
              maxWidth: '32rem',
              lineHeight: '1.6',
              fontWeight: '300',
              letterSpacing: '0.01em'
            }}>
              <span style={{ color: '#4ade80', fontWeight: '500' }}>Ruthless precision.</span> Our quantum-enhanced AI scans emails in milliseconds, neutralizing phishing threats before they breach your digital perimeter.
            </p>
            
            <motion.div 
              className="terminal-text" 
              style={{ 
                fontSize: 'clamp(1rem, 4vw, 1.5rem)', 
                fontFamily: '"JetBrains Mono", monospace', 
                marginBottom: '2rem',
                color: '#4ade80',
                borderRight: '0.15em solid #4ade80',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textShadow: '0 0 8px rgba(9, 104, 68, 0.7)',
                paddingRight: '0.5rem', // Add padding after the text
                width: 'max-content', // Only take up as much space as needed
                display: 'inline-block' // Better control over width
              }}
              initial={{ width: '0%' }}
              animate={{ width: 'max-content' }} // Use max-content instead of 100% or auto
              transition={{ 
                duration: 2.5, 
                delay: 1,
                ease: "easeInOut"
              }}
            >
              <span style={{ letterSpacing: '0.1em' }}>Detect</span><span>.</span><span style={{ letterSpacing: '0.1em' }}>Analyze</span><span>.</span><span style={{ letterSpacing: '0.1em' }}>Protect</span><span>.</span>
            </motion.div>
            
            <ScannerAnimation />
            
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', marginBottom: '2rem' }}>              
              <div className="glass-card" style={{ 
                padding: '1.25rem', 
                width: '100%', 
                maxWidth: '18rem',
                borderLeft: '3px solid #10b981',
                background: 'var(--terminal-gradient)',
                boxShadow: '0 0 15px rgba(16, 185, 129, 0.15)'
              }}>
                <div style={{ 
                  fontSize: '0.875rem', 
                  color: '#4ade80', 
                  marginBottom: '0.5rem',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  fontWeight: '500'
                }}>Threat Detection</div>
                <div style={{ 
                  fontSize: '1.75rem', 
                  fontWeight: 'bold', 
                  color: '#10b981',
                  fontFamily: '"JetBrains Mono", monospace'
                }}>99.7<span style={{ fontSize: '1.25rem', opacity: 0.8 }}>%</span></div>
              </div>
            </div>
          </motion.div>
          
          {/* Right column - Email analyzer */}
          <motion.div
            id="analyzer"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.7 }}
          >
            <div className="glass-card neon-border" style={{ 
              padding: '2rem',
              position: 'relative',
              overflow: 'hidden'
            }}>
              <div className="corner-accent top-left"></div>
              <div className="corner-accent top-right"></div>
              <div className="corner-accent bottom-left"></div>
              <div className="corner-accent bottom-right"></div>
              
              <EmailInput 
                onSubmit={handleEmailSubmit} 
                isLoading={isAnalyzing} 
                hasResult={!!analysisResult}
                onReset={handleReset}
              />
            </div>

            <AnimatePresence>
              {analysisResult && (
                <motion.div
                  key="result-card"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5 }}
                  className="mt-6"
                >
                  <ResultCard 
                    result={analysisResult} 
                    onReset={handleReset}
                  />
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        </div>
      </motion.main>

      <footer style={{ 
        position: 'relative',
        zIndex: 10,
        padding: '2rem 1rem',
        marginTop: '4rem',
        borderTop: '1px solid rgba(59, 130, 246, 0.2)'
      }}>
        <div style={{ 
          display: 'flex',
          flexDirection: 'row',
          flexWrap: 'wrap',
          justifyContent: 'center',
          alignItems: 'center',
          maxWidth: '90rem',
          marginLeft: 'auto',
          marginRight: 'auto',
          fontSize: 'clamp(0.75rem, 3vw, 0.875rem)',
          color: '#94a3b8',
          textAlign: 'center',
          gap: '0.25rem'
        }}>
          <span> 2023 PhishSecure. Developed with by</span>
          <a 
            href="https://linkedin.com/in/wxmohd" 
            target="_blank" 
            rel="noopener noreferrer"
            className="neon-text"
            style={{ marginLeft: '0.25rem' }}
          >
            Walaa Mohammed
          </a>
        </div>
      </footer>
    </div>
  );
}
