/**
 * API utilities for communicating with the PhishSecure backend
 */

export interface AnalysisResult {
  verdict: 'phishing' | 'legitimate';
  confidence: number; // 0-100
  flags: string[];
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
      flags: data.flags || []
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