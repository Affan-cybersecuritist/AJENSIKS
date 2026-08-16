'use client';

import React, { useState, useEffect } from 'react';
import { supabase, WorkspaceItem } from '../../lib/supabaseClient';
import Navbar from '../../components/Navbar';
import BootLoader from '../../components/BootLoader';
import { User } from '@supabase/supabase-js';

export default function DashboardPage() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [workspaces, setWorkspaces] = useState<WorkspaceItem[]>([]);
  const [newItemName, setNewItemName] = useState('');
  const [newItemContent, setNewItemContent] = useState('');
  const [isCreating, setIsCreating] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'items' | 'security'>('items');

  // Route Protection & Workspace Data Fetching
  useEffect(() => {
    const initAuthAndData = async () => {
      setLoading(true);
      const { data: { session } } = await supabase.auth.getSession();

      if (!session) {
        window.location.href = '/login';
        return;
      }

      setUser(session.user);
      await fetchUserWorkspaces(session.user.id);
      setLoading(false);
    };

    initAuthAndData();

    // Session Listener
    const { data: { subscription } } = supabase.auth.onAuthStateChange(async (event, session) => {
      if (!session || event === 'SIGNED_OUT') {
        window.location.href = '/login';
      } else if (session) {
        setUser(session.user);
      }
    });

    return () => {
      subscription.unsubscribe();
    };
  }, []);

  const fetchUserWorkspaces = async (userId: string) => {
    try {
      setErrorMsg(null);
      // RLS Policy ensures ONLY items where auth.uid() = user_id are returned
      const { data, error } = await supabase
        .from('workspaces')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false });

      if (error) throw error;
      setWorkspaces(data || []);
    } catch (err) {
      const error = err as Error;
      console.error('Error fetching workspaces:', error);
      setErrorMsg(error.message || 'Failed to load workspace items');
    }
  };

  const handleCreateItem = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user || !newItemName.trim()) return;

    try {
      setIsCreating(true);
      setErrorMsg(null);

      // Automatically attach logged in user.id to user_id column
      const { data, error } = await supabase
        .from('workspaces')
        .insert([
          {
            user_id: user.id,
            name: newItemName.trim(),
            content: newItemContent.trim() || null,
          },
        ])
        .select();

      if (error) throw error;

      if (data && data[0]) {
        setWorkspaces([data[0], ...workspaces]);
      }

      setNewItemName('');
      setNewItemContent('');
    } catch (err) {
      const error = err as Error;
      setErrorMsg(error.message || 'Failed to create workspace item');
    } finally {
      setIsCreating(false);
    }
  };

  const handleDeleteItem = async (itemId: string) => {
    if (!user || !confirm('Are you sure you want to delete this workspace item?')) return;

    try {
      setErrorMsg(null);
      const { error } = await supabase
        .from('workspaces')
        .delete()
        .eq('id', itemId)
        .eq('user_id', user.id);

      if (error) throw error;

      setWorkspaces(workspaces.filter((item) => item.id !== itemId));
    } catch (err) {
      const error = err as Error;
      setErrorMsg(error.message || 'Failed to delete workspace item');
    }
  };

  if (loading) {
    // `ready={false}` holds the loader up for as long as the auth/RLS check actually takes
    // (its own failsafe still dismisses it if that never resolves), replacing the bare spinner
    // that used to sit here so both entry points into this app share one polished boot screen.
    return <BootLoader ready={false} />;
  }

  return (
    <div className="dashboard-layout">
      <Navbar user={user} />

      <main className="dashboard-main">
        {/* User Identity Header Banner */}
        <section className="tenant-banner">
          <div className="banner-content">
            <span className="banner-badge">🔐 Isolated Tenant Environment</span>
            <h1>Personal Workspace Environment</h1>
            <p>
              Logged in as <strong className="user-highlight">{user?.email}</strong>. 
              Your data is protected by Supabase Row Level Security (RLS).
            </p>
          </div>
          <div className="banner-stats">
            <div className="stat-card">
              <span className="stat-number">{workspaces.length}</span>
              <span className="stat-label">Isolated Items</span>
            </div>
            <div className="stat-card">
              <span className="stat-status">ACTIVE</span>
              <span className="stat-label">RLS Security Policy</span>
            </div>
          </div>
        </section>

        {errorMsg && (
          <div className="alert-box alert-error">
            <span>⚠️ {errorMsg}</span>
          </div>
        )}

        {/* Dashboard Grid */}
        <div className="workspace-grid">
          {/* Create Workspace Item Form */}
          <section className="card create-card">
            <div className="card-header">
              <h2>➕ Create New Workspace Item</h2>
              <span className="badge-tenant">Tenant ID: {user?.id.substring(0, 6)}</span>
            </div>
            <form onSubmit={handleCreateItem} className="create-form">
              <div className="form-group">
                <label htmlFor="itemName">Item Name / Title</label>
                <input
                  id="itemName"
                  type="text"
                  placeholder="e.g. Confidential Project Roadmap"
                  value={newItemName}
                  onChange={(e) => setNewItemName(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="itemContent">Item Details / Notes</label>
                <textarea
                  id="itemContent"
                  rows={4}
                  placeholder="Enter private tenant content here..."
                  value={newItemContent}
                  onChange={(e) => setNewItemContent(e.target.value)}
                />
              </div>

              <button type="submit" className="btn-create-submit" disabled={isCreating}>
                {isCreating ? 'Saving to Supabase...' : 'Save Isolated Workspace Item'}
              </button>
            </form>
          </section>

          {/* Workspace Items List */}
          <section className="card items-card">
            <div className="card-header">
              <h2>📁 Your Isolated Data Environment ({workspaces.length})</h2>
              <button className="btn-refresh" onClick={() => user && fetchUserWorkspaces(user.id)}>
                🔄 Refresh
              </button>
            </div>

            {workspaces.length === 0 ? (
              <div className="empty-workspace">
                <div className="empty-icon">📂</div>
                <h3>No Workspace Items Yet</h3>
                <p>Create your first isolated data record using the form on the left.</p>
              </div>
            ) : (
              <div className="items-list">
                {workspaces.map((item) => (
                  <div key={item.id} className="workspace-item-card">
                    <div className="item-main">
                      <div className="item-header">
                        <h3>{item.name}</h3>
                        <span className="item-date">
                          {new Date(item.created_at).toLocaleDateString()}
                        </span>
                      </div>
                      {item.content && <p className="item-content">{item.content}</p>}
                      <div className="item-footer">
                        <span className="item-user-id">Owner user_id: {item.user_id}</span>
                      </div>
                    </div>

                    <div className="item-actions">
                      <button
                        onClick={() => handleDeleteItem(item.id)}
                        className="btn-delete"
                        title="Delete Workspace Item"
                      >
                        🗑️ Delete
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      </main>
    </div>
  );
}
