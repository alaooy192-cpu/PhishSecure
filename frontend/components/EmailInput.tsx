// EmailInput.tsx
import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

export const EmailInput = ({ onSubmit, isLoading, hasResult, onReset }: { onSubmit: (email: string) => void, isLoading: boolean, hasResult: boolean, onReset: () => void }) => {
  const [email, setEmail] = useState('');
  const [validationMessage, setValidationMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [typingTimer, setTypingTimer] = useState<NodeJS.Timeout | null>(null);

  // Check if the text contains email-like format
  const checkEmailFormat = (text: string) => {
    if (!text.trim()) {
      setValidationMessage('');
      return;
    }
    
    // Simple check for @ symbol
    if (!text.includes('@')) {
      setValidationMessage('Email should contain @ symbol');
      return;
    }
    
    // Check for domain-like structure
    if (!text.match(/@[^@]+\.[^@]+$/)) {
      setValidationMessage('Email should have a domain (e.g., @gmail.com)');
      return;
    }
    
    // All checks passed - any email with @ and a domain is accepted
    setValidationMessage('');
  };

  const handleEmailChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newValue = e.target.value;
    setEmail(newValue);
    setIsTyping(true);
    
    // Clear previous timer
    if (typingTimer) {
      clearTimeout(typingTimer);
    }
    
    // Set new timer
    const timer = setTimeout(() => {
      checkEmailFormat(newValue);
      setIsTyping(false);
    }, 500);
    
    setTypingTimer(timer);
  };

  // Clean up timer on unmount
  useEffect(() => {
    return () => {
      if (typingTimer) {
        clearTimeout(typingTimer);
      }
    };
  }, [typingTimer]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    // Submit on Enter (without Shift)
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (email.trim() && !isLoading && !validationMessage) {
        onSubmit(email);
      }
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    // If we already have results and button is in "Analyze again" state
    if (hasResult && !isLoading) {
      // Reset the form and state
      setEmail('');
      onReset();
      return;
    }
    
    // Normal submission flow
    if (email.trim()) {
      onSubmit(email);
    }
  };

  return (
    <motion.div style={{ width: '100%' }} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.5 }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <div style={{ 
            width: '0.25rem', 
            height: '1.5rem', 
            background: 'linear-gradient(to bottom, #4ade80, #10b981)',
            borderRadius: '9999px',
            boxShadow: '0 0 8px rgba(16, 185, 129, 0.4)'
          }}></div>
          <label htmlFor="email-input" style={{ 
            fontSize: '0.875rem', 
            fontWeight: 500, 
            color: '#4ade80',
            letterSpacing: '0.02em'
          }}>Enter suspicious email address</label>
        </div>
        
        <form onSubmit={handleSubmit}>
          <div style={{ position: 'relative' }}>
            <div style={{
              position: 'relative',
              width: '100%',
              borderRadius: '0.75rem',
              padding: '2px',
              background: 'linear-gradient(135deg, rgba(74, 222, 128, 0.5), rgba(16, 185, 129, 0.2), rgba(52, 211, 153, 0.5))',
              boxShadow: '0 0 15px rgba(16, 185, 129, 0.2)',
              overflow: 'hidden'
            }}>
              {/* Animated border effect */}
              <div style={{
                position: 'absolute',
                inset: 0,
                borderRadius: '0.75rem',
                padding: '2px',
                background: 'linear-gradient(135deg, rgba(74, 222, 128, 0.8), rgba(16, 185, 129, 0.3), rgba(52, 211, 153, 0.8))',
                opacity: 0.5,
                animation: 'borderGlow 3s ease infinite alternate',
                zIndex: 0
              }}></div>
              
              <textarea
                id="email-input"
                value={email}
                onChange={handleEmailChange}
                onKeyDown={handleKeyDown}
                placeholder="Enter the email address (e.g., example@domain.com)..."
                disabled={hasResult && !isLoading}
                style={{
                  width: '100%',
                  height: '10rem',
                  padding: '1rem',
                  borderRadius: '0.65rem',
                  backgroundColor: hasResult && !isLoading ? 'rgba(10, 14, 18, 0.9)' : 'rgba(10, 14, 18, 0.7)',
                  border: 'none',
                  color: 'var(--text-primary)',
                  resize: 'none',
                  backdropFilter: 'blur(4px)',
                  position: 'relative',
                  zIndex: 1,
                  outline: 'none',
                  fontFamily: '"Space Grotesk", sans-serif',
                  letterSpacing: '0.01em',
                  transition: 'all 0.3s ease',
                  opacity: hasResult && !isLoading ? 0.7 : 1,
                  cursor: hasResult && !isLoading ? 'not-allowed' : 'text'
                }}
                className="white-placeholder"
                onFocus={(e) => {
                  if (hasResult && !isLoading) return;
                  const parentDiv = e.target.parentElement;
                  if (parentDiv) {
                    parentDiv.style.boxShadow = '0 0 20px rgba(16, 185, 129, 0.4)';
                    parentDiv.style.transform = 'scale(1.005)';
                  }
                }}
                onBlur={(e) => {
                  if (hasResult && !isLoading) return;
                  const parentDiv = e.target.parentElement;
                  if (parentDiv) {
                    parentDiv.style.boxShadow = '0 0 15px rgba(16, 185, 129, 0.2)';
                    parentDiv.style.transform = 'scale(1)';
                  }
                }}

              />
              
              {/* Corner accents */}
              <div style={{
                position: 'absolute',
                top: 0,
                left: 0,
                width: '10px',
                height: '10px',
                borderTop: '2px solid rgba(74, 222, 128, 0.8)',
                borderLeft: '2px solid rgba(74, 222, 128, 0.8)',
                borderTopLeftRadius: '0.65rem',
                zIndex: 2
              }}></div>
              <div style={{
                position: 'absolute',
                top: 0,
                right: 0,
                width: '10px',
                height: '10px',
                borderTop: '2px solid rgba(74, 222, 128, 0.8)',
                borderRight: '2px solid rgba(74, 222, 128, 0.8)',
                borderTopRightRadius: '0.65rem',
                zIndex: 2
              }}></div>
              <div style={{
                position: 'absolute',
                bottom: 0,
                left: 0,
                width: '10px',
                height: '10px',
                borderBottom: '2px solid rgba(74, 222, 128, 0.8)',
                borderLeft: '2px solid rgba(74, 222, 128, 0.8)',
                borderBottomLeftRadius: '0.65rem',
                zIndex: 2
              }}></div>
              <div style={{
                position: 'absolute',
                bottom: 0,
                right: 0,
                width: '10px',
                height: '10px',
                borderBottom: '2px solid rgba(74, 222, 128, 0.8)',
                borderRight: '2px solid rgba(74, 222, 128, 0.8)',
                borderBottomRightRadius: '0.65rem',
                zIndex: 2
              }}></div>
            </div>
            
            {/* Email validation message */}
            {isTyping && email.trim() && (
              <div style={{ 
                marginTop: '0.5rem', 
                fontSize: '0.875rem', 
                color: '#4ade80',
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem'
              }}>
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"></circle>
                  <line x1="12" y1="16" x2="12" y2="12"></line>
                  <line x1="12" y1="8" x2="12.01" y2="8"></line>
                </svg>
                <span>Typing...</span>
              </div>
            )}
            
            {!isTyping && validationMessage && (
              <div style={{ 
                marginTop: '0.5rem', 
                fontSize: '0.875rem', 
                color: '#fca5a5',
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem'
              }}>
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"></circle>
                  <line x1="12" y1="8" x2="12" y2="12"></line>
                  <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                <span>{validationMessage}</span>
              </div>
            )}
          </div>
          
          <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'flex-end' }}>
            <button 
              type="submit"
              disabled={(isLoading && !hasResult) || (!!validationMessage && !isTyping && !hasResult)}
              style={{
                padding: '0.75rem 1.5rem',
                borderRadius: '0.5rem',
                background: 'linear-gradient(to right, #4ade80, #10b981)',
                color: 'white',
                fontWeight: 500,
                boxShadow: '0 10px 15px -3px rgba(16, 185, 129, 0.3)',
                transition: 'all 0.2s ease',
                cursor: (isLoading || (!!validationMessage && !isTyping)) ? 'not-allowed' : 'pointer',
                opacity: (isLoading || (!!validationMessage && !isTyping)) ? 0.7 : 1,
                border: 'none',
                fontSize: '1rem',
                WebkitTapHighlightColor: 'transparent',
                touchAction: 'manipulation'
              }}
              onMouseOver={(e) => {
                if (!isLoading && !validationMessage) {
                  e.currentTarget.style.background = 'linear-gradient(to right, #10b981, #059669)';
                  e.currentTarget.style.boxShadow = '0 15px 20px -3px rgba(16, 185, 129, 0.4)';
                }
              }}
              onMouseOut={(e) => {
                if (!isLoading && !validationMessage) {
                  e.currentTarget.style.background = 'linear-gradient(to right, #4ade80, #10b981)';
                  e.currentTarget.style.boxShadow = '0 10px 15px -3px rgba(16, 185, 129, 0.3)';
                }
              }}
              onTouchStart={(e) => {
                if (!isLoading && !validationMessage) {
                  e.currentTarget.style.background = 'linear-gradient(to right, #10b981, #059669)';
                  e.currentTarget.style.boxShadow = '0 15px 20px -3px rgba(16, 185, 129, 0.4)';
                  e.currentTarget.style.transform = 'scale(0.98)';
                }
              }}
              onTouchEnd={(e) => {
                if (!isLoading && !validationMessage) {
                  e.currentTarget.style.background = 'linear-gradient(to right, #4ade80, #10b981)';
                  e.currentTarget.style.boxShadow = '0 10px 15px -3px rgba(16, 185, 129, 0.3)';
                  e.currentTarget.style.transform = 'scale(1)';
                }
              }}
            >
              {isLoading && !hasResult ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <div style={{ 
                    width: '1rem', 
                    height: '1rem', 
                    border: '2px solid rgba(255, 255, 255, 0.3)', 
                    borderTop: '2px solid white', 
                    borderRadius: '50%',
                    animation: 'spin 1s linear infinite'
                  }} />
                  <span>Analyzing...</span>
                </div>
              ) : hasResult ? 'Analyze again' : 'Analyze Email'}
            </button>
          </div>
        </form>
      </div>
    </motion.div>
  );
};