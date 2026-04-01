import { useEffect } from 'react';
import { useRouter } from 'next/router';

export default function Dashboard() {
  const router = useRouter();
  
  useEffect(() => {
    // Redirect to CTI dashboard
    router.replace('/cti-dashboard');
  }, [router]);



  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      backgroundColor: '#0a0e12',
      color: 'white'
    }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>🔄</div>
        <p>Redirecting to CTI Dashboard...</p>
      </div>
    </div>
  );
}
