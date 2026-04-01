// PhishSecure Bahrain CTI Platform - Homepage
import Head from 'next/head';
import { motion } from 'framer-motion';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import dynamic from 'next/dynamic';

// Animated particles component
const ParticlesBackgroundComponent = () => {
  useEffect(() => {
    const particlesContainer = document.querySelector('.particles-bg');
    const particleCount = 50;
    
    if (particlesContainer) {
      particlesContainer.innerHTML = '';
      
      for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.classList.add('particle');
        
        const x = Math.random() * 100;
        const y = Math.random() * 100;
        particle.style.left = `${x}%`;
        particle.style.top = `${y}%`;
        
        const size = Math.random() * 3 + 1;
        particle.style.width = `${size}px`;
        particle.style.height = `${size}px`;
        
        particle.style.opacity = (Math.random() * 0.5 + 0.3).toString();
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

const ParticlesBackground = dynamic(
  () => Promise.resolve(ParticlesBackgroundComponent),
  { ssr: false }
);

export default function Home() {
  return (
    <div className="min-h-screen text-white" style={{ 
      background: 'linear-gradient(135deg, #0a0e12 0%, #1a1f2e 50%, #0a0e12 100%)' 
    }}>
      <Head>
        <title>PhishSecure Bahrain | Cyber Threat Intelligence</title>
        <meta name="description" content="Bahrain-focused Cyber Threat Intelligence Platform" />
        <link rel="icon" href="/favicon.ico" />
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet" />
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet" />
      </Head>

      {/* Animated particles background */}
      <ParticlesBackground />
      
      {/* Background effects */}
      <div style={{ position: 'absolute', inset: 0, overflow: 'hidden', pointerEvents: 'none' }}>
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
      </div>

      {/* Header */}
      <header style={{ 
        position: 'relative', 
        zIndex: 10, 
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
          <motion.div 
            style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '0.5rem'
            }}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5 }}
          >
            <div style={{ 
              background: 'linear-gradient(to right, #4ade80, #10b981)', 
              padding: '0.5rem', 
              borderRadius: '0.5rem',
              boxShadow: '0 0 10px rgba(74, 222, 128, 0.5)'
            }}>
              <span style={{ fontSize: '1.25rem', color: '#0a0e12', fontWeight: 700 }}>✦</span>
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
          </motion.div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              <div style={{
                padding: '0.25rem 0.75rem',
                borderRadius: '9999px',
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem'
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
            
            <Link href="/live-monitoring" style={{
              padding: '0.5rem 1rem',
              borderRadius: '0.5rem',
              backgroundColor: 'rgba(239, 68, 68, 0.2)',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              color: '#ef4444',
              fontSize: '0.875rem',
              textDecoration: 'none'
            }}>
              🔴 Live Monitoring
            </Link>

            <Link href="/cti-dashboard" style={{
              padding: '0.5rem 1rem',
              borderRadius: '0.5rem',
              backgroundColor: 'rgba(139, 92, 246, 0.2)',
              border: '1px solid rgba(139, 92, 246, 0.4)',
              color: '#a78bfa',
              fontSize: '0.875rem',
              textDecoration: 'none'
            }}>
              CTI Dashboard
            </Link>
            
            <Link href="/analyze" style={{
              padding: '0.5rem 1rem',
              borderRadius: '0.5rem',
              backgroundColor: 'rgba(16, 185, 129, 0.2)',
              border: '1px solid rgba(16, 185, 129, 0.4)',
              color: '#10b981',
              fontSize: '0.875rem',
              textDecoration: 'none'
            }}>
              Analyze Domain
            </Link>
          </div>
        </div>
      </header>

      <main style={{
        position: 'relative',
        zIndex: 10,
        padding: '4rem 2rem',
        maxWidth: '90rem',
        margin: '0 auto',
        textAlign: 'center'
      }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
        >
          {/* Hero Section */}
          <div style={{ marginBottom: '4rem' }}>
            <div style={{
              display: 'inline-block',
              padding: '0.5rem 1rem',
              marginBottom: '2rem',
              borderRadius: '9999px',
              background: 'linear-gradient(to right, rgba(74, 222, 128, 0.2), rgba(16, 185, 129, 0.15))',
              border: '1px solid rgba(74, 222, 128, 0.4)',
              boxShadow: '0 0 10px rgba(74, 222, 128, 0.2)'
            }}>
              <span style={{ fontSize: '0.875rem', fontWeight: 600, color: '#4ade80', letterSpacing: '0.05em', textTransform: 'uppercase' }}>◈ Bahrain CTI Platform</span>
            </div>
            
            <h1 style={{ 
              fontSize: 'clamp(2.5rem, 6vw, 4rem)', 
              fontWeight: '800', 
              marginBottom: '2rem', 
              fontFamily: '"Space Grotesk", sans-serif',
              lineHeight: '1.1'
            }}>
              <span style={{ 
                background: 'linear-gradient(to right, #4ade80, #10b981, #059669)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent'
              }}>Cyber Threat Intelligence</span>
              <br />
              <span style={{ color: '#e2e8f0' }}>for Bahrain Organizations</span>
            </h1>
            
            <p style={{ 
              fontSize: '1.25rem', 
              color: '#94a3b8', 
              marginBottom: '3rem', 
              maxWidth: '600px',
              margin: '0 auto 3rem',
              lineHeight: '1.6'
            }}>
              Advanced threat intelligence platform monitoring phishing campaigns targeting 
              <span style={{ color: '#4ade80', fontWeight: '600' }}> banking, telecom, and government </span>
              sectors in Bahrain.
            </p>
          </div>

          {/* Feature Cards */}
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', 
            gap: '2rem',
            marginBottom: '4rem'
          }}>
            <motion.div
              whileHover={{ scale: 1.05 }}
              style={{
                padding: '2rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(139, 92, 246, 0.3)',
                borderRadius: '1rem',
                textAlign: 'left'
              }}
            >
              <div style={{ fontSize: '2rem', marginBottom: '1rem', color: '#a78bfa' }}>◫</div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 600, marginBottom: '1rem', color: '#a78bfa' }}>
                Threat Intelligence Dashboard
              </h3>
              <p style={{ color: '#94a3b8', lineHeight: '1.6' }}>
                Real-time monitoring of phishing threats with Bahrain-specific relevance scoring and sector analysis.
              </p>
              <Link href="/cti-dashboard" style={{
                display: 'inline-block',
                marginTop: '1rem',
                padding: '0.5rem 1rem',
                backgroundColor: 'rgba(139, 92, 246, 0.2)',
                border: '1px solid rgba(139, 92, 246, 0.4)',
                borderRadius: '0.5rem',
                color: '#a78bfa',
                textDecoration: 'none',
                fontSize: '0.875rem'
              }}>
                View Dashboard →
              </Link>
            </motion.div>

            <motion.div
              whileHover={{ scale: 1.05 }}
              style={{
                padding: '2rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                borderRadius: '1rem',
                textAlign: 'left'
              }}
            >
              <div style={{ fontSize: '2rem', marginBottom: '1rem', color: '#10b981' }}>◎</div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 600, marginBottom: '1rem', color: '#10b981' }}>
                Domain Analysis
              </h3>
              <p style={{ color: '#94a3b8', lineHeight: '1.6' }}>
                Analyze suspicious domains for threat level and relevance to Bahrain organizations with detailed explanations.
              </p>
              <Link href="/analyze" style={{
                display: 'inline-block',
                marginTop: '1rem',
                padding: '0.5rem 1rem',
                backgroundColor: 'rgba(16, 185, 129, 0.2)',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                borderRadius: '0.5rem',
                color: '#10b981',
                textDecoration: 'none',
                fontSize: '0.875rem'
              }}>
                Analyze Domain →
              </Link>
            </motion.div>

            <motion.div
              whileHover={{ scale: 1.05 }}
              style={{
                padding: '2rem',
                backgroundColor: 'rgba(10, 14, 18, 0.8)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '1rem',
                textAlign: 'left'
              }}
            >
              <div style={{ fontSize: '2rem', marginBottom: '1rem', color: '#60a5fa' }}>☰</div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 600, marginBottom: '1rem', color: '#60a5fa' }}>
                Threat Indicators
              </h3>
              <p style={{ color: '#94a3b8', lineHeight: '1.6' }}>
                Browse comprehensive database of threat indicators with filtering by sector, threat level, and Bahrain relevance.
              </p>
              <Link href="/indicators" style={{
                display: 'inline-block',
                marginTop: '1rem',
                padding: '0.5rem 1rem',
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                border: '1px solid rgba(59, 130, 246, 0.4)',
                borderRadius: '0.5rem',
                color: '#60a5fa',
                textDecoration: 'none',
                fontSize: '0.875rem'
              }}>
                Browse Indicators →
              </Link>
            </motion.div>
          </div>

          {/* Stats Section */}
          <div style={{
            padding: '2rem',
            backgroundColor: 'rgba(10, 14, 18, 0.8)',
            border: '1px solid rgba(74, 222, 128, 0.3)',
            borderRadius: '1rem',
            marginBottom: '2rem'
          }}>
            <h3 style={{ fontSize: '1.5rem', fontWeight: 600, marginBottom: '2rem', color: '#4ade80' }}>
              Protecting Bahrain's Digital Infrastructure
            </h3>
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', 
              gap: '2rem'
            }}>
              <div>
                <div style={{ fontSize: '2rem', color: '#4ade80' }}>$</div>
                <div style={{ fontSize: '0.875rem', color: '#94a3b8', marginTop: '0.5rem' }}>Banking Sector</div>
              </div>
              <div>
                <div style={{ fontSize: '2rem', color: '#4ade80' }}>☎</div>
                <div style={{ fontSize: '0.875rem', color: '#94a3b8', marginTop: '0.5rem' }}>Telecom Sector</div>
              </div>
              <div>
                <div style={{ fontSize: '2rem', color: '#4ade80' }}>⌂</div>
                <div style={{ fontSize: '0.875rem', color: '#94a3b8', marginTop: '0.5rem' }}>Government Sector</div>
              </div>
              <div>
                <div style={{ fontSize: '2rem', color: '#4ade80' }}>⊞</div>
                <div style={{ fontSize: '0.875rem', color: '#94a3b8', marginTop: '0.5rem' }}>Business Sector</div>
              </div>
            </div>
          </div>
        </motion.div>
      </main>

      <footer style={{ 
        position: 'relative',
        zIndex: 10,
        padding: '2rem 1rem',
        borderTop: '1px solid rgba(59, 130, 246, 0.2)',
        textAlign: 'center'
      }}>
        <div style={{ 
          maxWidth: '90rem',
          margin: '0 auto',
          fontSize: '0.875rem',
          color: '#94a3b8'
        }}>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '2rem', marginBottom: '1rem' }}>
            <Link href="/live-monitoring" style={{ color: '#ef4444', textDecoration: 'none' }}>
              🔴 Live Monitoring
            </Link>
            <Link href="/cti-dashboard" style={{ color: '#60a5fa', textDecoration: 'none' }}>
              CTI Dashboard
            </Link>
            <Link href="/analyze" style={{ color: '#60a5fa', textDecoration: 'none' }}>
              Domain Analysis
            </Link>
            <Link href="/indicators" style={{ color: '#60a5fa', textDecoration: 'none' }}>
              Threat Indicators
            </Link>
          </div>
          <p>© 2024 PhishSecure Bahrain CTI Platform. Protecting Bahrain's digital infrastructure.</p>
        </div>
      </footer>
    </div>
  );
}
