import React from 'react';
import './globals.css';

export const metadata = {
  title: 'Supabase Multi-Tenant Workspace',
  description: 'Isolated multi-tenant user environment with Supabase Auth and Row Level Security (RLS)',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
