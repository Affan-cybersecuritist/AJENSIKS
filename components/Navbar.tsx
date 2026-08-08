'use client';

import React from 'react';
import { supabase } from '../lib/supabaseClient';
import { User } from '@supabase/supabase-js';

interface NavbarProps {
  user: User | null;
  onSignOut?: () => void;
}

export default function Navbar({ user, onSignOut }: NavbarProps) {
  const handleLogout = async () => {
    await supabase.auth.signOut();
    if (onSignOut) {
      onSignOut();
    } else {
      window.location.href = '/login';
    }
  };

  return (
    <header className="navbar-container">
      <div className="navbar-logo">
        <span className="logo-badge">⚡</span>
        <span className="logo-title">CloudWorkspace</span>
        <span className="tenant-badge">Multi-Tenant RLS</span>
      </div>

      <div className="navbar-user">
        {user ? (
          <>
            <div className="user-profile-info">
              <span className="user-avatar">{user.email ? user.email[0].toUpperCase() : 'U'}</span>
              <div className="user-text">
                <span className="user-email">{user.email}</span>
                <span className="user-id">ID: {user.id.substring(0, 8)}...</span>
              </div>
            </div>
            <button onClick={handleLogout} className="btn-logout">
              Sign Out
            </button>
          </>
        ) : (
          <a href="/login" className="btn-login-link">
            Sign In
          </a>
        )}
      </div>
    </header>
  );
}
