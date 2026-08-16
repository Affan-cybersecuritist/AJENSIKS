'use client';

import React, { useEffect, useState } from 'react';

const PHASES = [
  'Establishing secure connection',
  'Verifying your session',
  'Applying row-level security',
  'Preparing your workspace',
];

/**
 * Full-screen boot loader for the Next.js pages.
 *
 * Rendered on the server as well as the client so it paints with the very first frame —
 * that first frame is exactly the window this covers, while the Supabase SDK loads and the
 * session check runs. On the login page that check can end in a redirect to /dashboard, so
 * without this the user briefly sees the login form flash before being navigated away.
 *
 * Pass `ready` once the page's own async startup work is finished; the loader then fades
 * after a short minimum so it never flash-and-vanishes on a warm cache. A hard failsafe
 * dismisses it regardless, so a hung network request can never trap the user behind it.
 */
export default function BootLoader({ ready = true }: { ready?: boolean }) {
  const [gone, setGone] = useState(false);
  const [fading, setFading] = useState(false);
  const [phase, setPhase] = useState(0);

  useEffect(() => {
    const cycle = setInterval(() => setPhase((p) => (p + 1) % PHASES.length), 850);
    return () => clearInterval(cycle);
  }, []);

  useEffect(() => {
    const MIN_VISIBLE_MS = 1400;
    const started = Date.now();
    let fadeTimer: ReturnType<typeof setTimeout>;
    let removeTimer: ReturnType<typeof setTimeout>;

    const dismiss = () => {
      setFading(true);
      removeTimer = setTimeout(() => setGone(true), 600);
    };

    if (ready) {
      fadeTimer = setTimeout(dismiss, Math.max(0, MIN_VISIBLE_MS - (Date.now() - started)));
    }
    // Failsafe: never leave the overlay up if `ready` never arrives.
    const failsafe = setTimeout(dismiss, 6000);

    return () => {
      clearTimeout(fadeTimer);
      clearTimeout(removeTimer);
      clearTimeout(failsafe);
    };
  }, [ready]);

  useEffect(() => {
    // Lock scrolling only while the overlay is actually up.
    document.body.classList.toggle('nx-booting', !gone);
    return () => document.body.classList.remove('nx-booting');
  }, [gone]);

  if (gone) return null;

  return (
    <div
      className={`nx-loader${fading ? ' is-hidden' : ''}`}
      role="status"
      aria-live="polite"
      aria-label="Loading your workspace"
    >
      <div className="nx-grid" aria-hidden="true" />
      <div className="nx-glow nx-glow-a" aria-hidden="true" />
      <div className="nx-glow nx-glow-b" aria-hidden="true" />

      <div className="nx-core">
        <div className="nx-shield-wrap">
          <div className="nx-ring" aria-hidden="true" />
          <div className="nx-ring nx-ring-2" aria-hidden="true" />
          <div className="nx-shield">
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.9"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path className="nx-check" d="M8.6 12.1l2.4 2.4 4.5-4.7" />
            </svg>
            <span className="nx-scan" aria-hidden="true" />
          </div>
        </div>

        <h1 className="nx-title">
          Multi-Tenant <span>Workspace</span>
        </h1>
        <p className="nx-sub">{PHASES[phase]}</p>

        <div className="nx-steps" aria-hidden="true">
          <span className="nx-step" style={{ ['--i' as string]: 0 }}>
            <i />
            Auth
          </span>
          <span className="nx-step" style={{ ['--i' as string]: 1 }}>
            <i />
            Session
          </span>
          <span className="nx-step" style={{ ['--i' as string]: 2 }}>
            <i />
            RLS
          </span>
          <span className="nx-step" style={{ ['--i' as string]: 3 }}>
            <i />
            Workspace
          </span>
        </div>

        <div className="nx-bar" aria-hidden="true">
          <span />
        </div>
      </div>
    </div>
  );
}
