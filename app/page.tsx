'use client';

import { useEffect } from 'react';
import { supabase } from '../lib/supabaseClient';

export default function HomePage() {
  useEffect(() => {
    const redirectUser = async () => {
      const { data: { session } } = await supabase.auth.getSession();
      if (session) {
        window.location.href = '/dashboard';
      } else {
        window.location.href = '/login';
      }
    };
    redirectUser();
  }, []);

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      backgroundColor: '#0b0f19',
      color: '#f3f4f6',
      fontFamily: 'system-ui, sans-serif'
    }}>
      <p>Redirecting to Multi-Tenant Workspace...</p>
    </div>
  );
}
