import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://qeqyjpuhkrhxwkvfnvch.supabase.co';
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFlcXlqcHVoa3JoeHdrdmZudmNoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODYwODY5MjgsImV4cCI6MjEwMTY2MjkyOH0.OnAHkwYzDsKj0HG2Gk7QI-2jKRtaY2HbjZwZ62DdFVw';

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true
  }
});

export interface Profile {
  id: string;
  email: string;
  full_name: string | null;
  created_at: string;
}

export interface WorkspaceItem {
  id: string;
  user_id: string;
  name: string;
  content: string | null;
  created_at: string;
}
