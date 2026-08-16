const SUPABASE_URL = 'https://qeqyjpuhkrhxwkvfnvch.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFlcXlqcHVoa3JoeHdrdmZudmNoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODYwODY5MjgsImV4cCI6MjEwMTY2MjkyOH0.OnAHkwYzDsKj0HG2Gk7QI-2jKRtaY2HbjZwZ62DdFVw';

let supabaseClient;
let currentUser = null;
let ws;
let isRunning = false;
let isSignUpMode = false;
let isEditMode = false;
let currentSessionId = null;
let sessionsList = [];
let currentProcessId = null;
let swarmWatchdogTimer = null;
let currentLanguage = "python";
const SAFETY_MAX_LOOPS = 30;
// Set the moment the user submits the sign-in form. Supabase's onAuthStateChange fires on its
// own as soon as the session lands and calls onUserAuthenticated() first — without this flag
// that call would hide the modal instantly and the explicit interactive call arriving a beat
// later would find nothing left to animate, so the transition silently never played.
let pendingInteractiveSignIn = false;

// ── Boot loader ────────────────────────────────────────────────────────────
// Covers the gap between first paint and the app being usable (Google Fonts,
// highlight.js, the Supabase SDK and the session check all resolve in that window).
function initAppLoader() {
  const loader = document.getElementById("app-loader");
  if (!loader) return;

  const statusEl = document.getElementById("ldr-status");
  const phases = [
    "Initializing autonomous security pipeline",
    "Waking the agent swarm",
    "Loading static analysis engines",
    "Securing your workspace"
  ];
  let phase = 0;
  const cycle = setInterval(() => {
    phase = (phase + 1) % phases.length;
    if (statusEl) statusEl.textContent = phases[phase];
  }, 850);

  let dismissed = false;
  const dismiss = () => {
    if (dismissed) return;
    dismissed = true;
    clearInterval(cycle);
    loader.classList.add("is-hidden");
    document.body.classList.remove("is-booting");
    // Drop it from the DOM after the fade so its fixed overlay can never intercept clicks.
    setTimeout(() => loader.remove(), 700);
  };

  // Show for a beat so the animation doesn't flash-and-vanish on a warm cache, but never
  // hold the UI hostage: whichever of "page loaded" or the hard failsafe lands first wins.
  const MIN_VISIBLE_MS = 1400;
  const started = Date.now();
  const dismissWhenReady = () => setTimeout(dismiss, Math.max(0, MIN_VISIBLE_MS - (Date.now() - started)));

  if (document.readyState === "complete") dismissWhenReady();
  else window.addEventListener("load", dismissWhenReady, { once: true });

  // Failsafe — a hung CDN asset must never leave the user stuck behind the overlay.
  setTimeout(dismiss, 6000);
}

function initSupabase() {
  if (window.supabase) {
    supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    installAuthenticatedFetch();
    checkSession();
  }
}

/** Current Supabase access token, refreshed by the SDK when it's close to expiry. */
async function getAccessToken() {
  if (!supabaseClient) return null;
  try {
    const { data: { session } } = await supabaseClient.auth.getSession();
    return session ? session.access_token : null;
  } catch {
    return null;
  }
}

/**
 * Attaches the Supabase bearer token to every same-origin /api/ request.
 *
 * Done by wrapping fetch once rather than editing ~17 call sites: any future call is covered
 * automatically, so an endpoint can't silently end up unauthenticated. The backend now derives
 * the tenant id from this token and ignores whatever user_id the body/URL claims.
 */
function installAuthenticatedFetch() {
  if (window.__authFetchInstalled) return;
  window.__authFetchInstalled = true;

  const rawFetch = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : (input && input.url) || "";
    const isOwnApi = url.startsWith("/api/") || url.startsWith(`${location.origin}/api/`);
    if (!isOwnApi) return rawFetch(input, init);

    const token = await getAccessToken();
    if (token) {
      const headers = new Headers(init.headers || (typeof input !== "string" && input.headers) || {});
      headers.set("Authorization", `Bearer ${token}`);
      init = { ...init, headers };
    }

    const res = await rawFetch(input, init);
    // The token expired or was revoked server-side — drop back to the sign-in screen rather
    // than leaving a workspace on screen that can no longer talk to the backend.
    if (res.status === 401) {
      onUserSignedOut();
      showAuthError("Your session expired. Please sign in again.");
    } else if (res.status === 403) {
      showAuthError("You do not have access to that workspace.");
    }
    return res;
  };
}

async function checkSession() {
  // Sign-in is required to reach the workspace. Previously every "not signed in" path here
  // fell through to continueAsGuest(), which dismissed the auth modal and dropped the visitor
  // straight into the main page under a shared "guest_devsecops_user" account — so the login
  // screen was effectively decorative and every guest shared one workspace.
  if (!supabaseClient) {
    // Auth SDK unavailable (offline, CDN blocked) — we cannot verify anyone, so deny entry
    // rather than granting it. Failing open here would defeat the gate entirely.
    onUserSignedOut();
    showAuthError("Authentication service unavailable — check your connection and reload.");
    return;
  }

  const { data: { session } } = await supabaseClient.auth.getSession();

  if (session && session.user) {
    onUserAuthenticated(session.user);
  } else {
    onUserSignedOut();
  }

  supabaseClient.auth.onAuthStateChange((event, session) => {
    if (session && session.user) {
      onUserAuthenticated(session.user);
    } else {
      onUserSignedOut();
    }
  });
}

/** True only for a real, signed-in Supabase user. */
function isAuthenticated() {
  return !!(currentUser && currentUser.id && currentUser.id !== "guest_devsecops_user");
}

/** Blocks an action and re-opens the sign-in screen. Returns true when the caller must stop. */
function requireAuth() {
  if (isAuthenticated()) return false;
  onUserSignedOut();
  showAuthError("Please sign in to use the workspace.");
  return true;
}

function showAuthError(message) {
  const box = document.getElementById("auth-error");
  const text = document.getElementById("auth-error-text");
  if (text) text.innerText = message;
  if (box) box.style.display = "block";
}

// continueAsGuest() intentionally removed — the workspace now requires a real signed-in
// account. It used to log everyone in as a single shared "guest_devsecops_user", which both
// bypassed the login screen and pooled every unauthenticated visitor's sessions, generated
// code and security reports into one common workspace on disk.

/**
 * 3D hand-off from the sign-in card into the workspace.
 *
 * Timeline: the auth card flips back in perspective and recedes, a success seal stamps in
 * with expanding rings, the overlay dissolves, and the workspace rises into place with its
 * stat cards and agent nodes staggering in. Cleans every class up afterwards so a later
 * sign-out → sign-in replays it correctly.
 */
function playSignInTransition() {
  const modal = document.getElementById("auth-modal");
  const card = modal ? modal.querySelector(".auth-card") : null;
  const app = document.getElementById("app-content");
  if (!modal) return;
  // onUserAuthenticated() legitimately runs twice for one sign-in (the SDK's onAuthStateChange
  // and the form's own call). The modal stays visible for the first ~1.25s of the sequence, so
  // the second call would otherwise start a whole second overlapping run — two seals, and two
  // competing cleanup timers that left `is-entering` stuck on the workspace.
  if (window.__signInTransitionPlaying) return;
  window.__signInTransitionPlaying = true;

  const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduced) {
    modal.style.display = "none";
    window.__signInTransitionPlaying = false;
    return;
  }

  if (card) card.classList.add("is-signing-in");
  modal.classList.add("is-dissolving");

  // Success seal, injected for the duration of the animation only.
  const seal = document.createElement("div");
  seal.className = "signin-seal";
  seal.innerHTML = `
    <div class="signin-seal-badge">
      <span class="signin-seal-ring"></span>
      <span class="signin-seal-ring"></span>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path class="seal-check" d="M8.5 12.1l2.5 2.5 4.6-4.9"/>
      </svg>
    </div>`;
  document.body.appendChild(seal);

  // Workspace rises in just after the card starts clearing out of the way.
  if (app) {
    setTimeout(() => {
      app.classList.add("is-entering");
      const clearEntering = () => {
        app.classList.remove("is-entering");
        app.removeEventListener("animationend", onEnd);
      };
      function onEnd(e) {
        if (e.target !== app) return;           // ignore the staggered child animations
        clearEntering();
      }
      app.addEventListener("animationend", onEnd);
      // animationend never fires if the element gets hidden mid-flight (e.g. the session is
      // rejected and we bounce back to the sign-in screen), which would leave the animation
      // class stuck on and break the next replay. Always clear it on a timer as well.
      setTimeout(clearEntering, 1600);
    }, 380);
  }

  setTimeout(() => {
    modal.style.display = "none";
    modal.classList.remove("is-dissolving");
    if (card) card.classList.remove("is-signing-in");
    seal.remove();
    window.__signInTransitionPlaying = false;
  }, 1250);
}

function onUserAuthenticated(user, interactive = false) {
  currentUser = user;
  // The socket usually opens before sign-in completes, so it authenticated as nobody and is
  // currently receiving no events. Re-send the handshake now that a token exists.
  authenticateWebSocket();

  const modal = document.getElementById("auth-modal");
  // Only animate a sign-in the user just performed. Restoring an existing session on page
  // load must not replay the sequence — the modal was never on screen in that case.
  const animate = (interactive || pendingInteractiveSignIn) && modal && getComputedStyle(modal).display !== "none";
  pendingInteractiveSignIn = false;

  // Unlocks #app-content — the only place this class is ever added.
  document.body.classList.add("is-authenticated");
  if (animate) {
    playSignInTransition();
  } else if (modal) {
    modal.style.display = "none";
  }
  const authError = document.getElementById("auth-error");
  if (authError) authError.style.display = "none";
  const badgeContainer = document.getElementById("user-badge-container");
  if (badgeContainer) badgeContainer.style.display = "flex";
  const signinBtn = document.getElementById("signin-btn");
  if (signinBtn) signinBtn.style.display = "none";
  const signoutBtn = document.getElementById("signout-btn");
  if (signoutBtn) signoutBtn.style.display = "inline-flex";

  const emailEl = document.getElementById("user-email-display");
  const avatarEl = document.getElementById("user-avatar-initial");
  if (emailEl) emailEl.innerText = user.email;
  if (avatarEl) avatarEl.innerText = user.email ? user.email[0].toUpperCase() : 'U';

  appendTerminal(`[Auth] Authenticated user tenant: ${user.email} (ID: ${user.id})`, "system");
  loadUserSessions();
}

function onUserSignedOut() {
  currentUser = null;
  currentSessionId = null;
  // Re-locks the workspace and clears the previous tenant's data out of the DOM so nothing
  // from their session is left on screen behind the sign-in overlay.
  document.body.classList.remove("is-authenticated");
  sessionsList = [];
  renderSidebarSessions();
  document.getElementById("auth-modal").style.display = "flex";
  const badgeContainer = document.getElementById("user-badge-container");
  if (badgeContainer) badgeContainer.style.display = "none";
  const signinBtn = document.getElementById("signin-btn");
  if (signinBtn) signinBtn.style.display = "none";
  const signoutBtn = document.getElementById("signout-btn");
  if (signoutBtn) signoutBtn.style.display = "none";
}

function signOutUser() {
  handleSignOut();
}

function openAuthModal() {
  document.getElementById("auth-modal").style.display = "flex";
}

function toggleAuthMode() {
  isSignUpMode = !isSignUpMode;
  const title = document.getElementById("auth-title");
  const subtitle = document.getElementById("auth-subtitle");
  const submitBtn = document.getElementById("auth-submit-btn");
  const toggleText = document.getElementById("auth-toggle-text");
  const toggleBtn = document.querySelector(".btn-toggle");
  const groupFullName = document.getElementById("group-fullname");

  if (isSignUpMode) {
    title.innerText = "Create Your Workspace Account";
    subtitle.innerText = "Sign up to launch your isolated DevSecOps data environment";
    submitBtn.innerText = "Create Workspace Account";
    toggleText.innerText = "Already have an account?";
    toggleBtn.innerText = "Sign In";
    groupFullName.style.display = "flex";
  } else {
    title.innerText = "Sign In to Your Workspace";
    subtitle.innerText = "Access your isolated multi-tenant application security environment";
    submitBtn.innerText = "Sign In to Workspace";
    toggleText.innerText = "Don't have a workspace account?";
    toggleBtn.innerText = "Sign Up";
    groupFullName.style.display = "none";
  }

  document.getElementById("auth-error").style.display = "none";
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  const email = document.getElementById("auth-email").value.trim();
  const password = document.getElementById("auth-password").value;
  const fullName = document.getElementById("auth-fullname").value.trim();
  const errorBox = document.getElementById("auth-error");
  const errorText = document.getElementById("auth-error-text");

  errorBox.style.display = "none";
  // Claimed by whichever onUserAuthenticated() call lands first (this one or the SDK's
  // onAuthStateChange), so the transition plays exactly once regardless of ordering.
  pendingInteractiveSignIn = true;

  try {
    if (isSignUpMode) {
      const { data, error } = await supabaseClient.auth.signUp({
        email,
        password,
        options: { data: { full_name: fullName || email.split('@')[0] } }
      });
      if (error) throw error;

      if (data.session) {
        onUserAuthenticated(data.session.user, true);
      } else {
        alert("Account created successfully! Check your email to confirm registration or sign in.");
      }
    } else {
      const { data, error } = await supabaseClient.auth.signInWithPassword({ email, password });
      if (error) throw error;

      if (data.session) {
        onUserAuthenticated(data.session.user, true);
      }
    }
  } catch (err) {
    // Sign-in failed, so nothing will consume the flag — clear it, otherwise a later session
    // restore (e.g. another tab signing in) would replay the transition out of nowhere.
    pendingInteractiveSignIn = false;
    errorText.innerText = err.message || 'Authentication failed';
    errorBox.style.display = "block";
  }
}

async function handleSignOut() {
  if (supabaseClient) {
    await supabaseClient.auth.signOut();
    onUserSignedOut();
  }
}

/**
 * Identifies this socket to the server. A browser can't set an Authorization header on a
 * WebSocket handshake, so the token goes in a first message instead; until the server verifies
 * it, the socket is sent no tenant-scoped events at all.
 */
async function authenticateWebSocket() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const token = await getAccessToken();
  if (token && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: "AUTH", token }));
  }
}

function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/swarm`;
  
  ws = new WebSocket(wsUrl);

  ws.onopen = async () => {
    console.log("WebSocket connected to DevSecOps Swarm.");
    await authenticateWebSocket();
    const st = document.getElementById("status-text");
    if (st) st.innerText = "System Ready";
    if (window.__wasDisconnected) {
      appendTerminal(`\n[System] Reconnected to server.`, "system");
      window.__wasDisconnected = false;
    }
  };

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === "AUTH_RESULT") return;  // handshake ack, not a pipeline event
    if (!data.user_id || (currentUser && data.user_id === currentUser.id)) {
      if (!data.session_id || data.session_id === currentSessionId) {
        handleSwarmEvent(data);
      }
    }
  };

  ws.onclose = () => {
    const st = document.getElementById("status-text");
    if (st) st.innerText = "⚠ Disconnected — reconnecting...";
    if (!window.__wasDisconnected) {
      appendTerminal(`\n[System] Lost connection to server. Retrying every 3s — if this persists, the backend may have stopped; restart it and refresh this page.`, "system");
      window.__wasDisconnected = true;
    }
    setTimeout(initWebSocket, 3000);
  };
}

function loadAvailableModels() {
  fetch("/api/models")
    .then(res => res.json())
    .then(data => {
      const select = document.getElementById("model-select");
      select.innerHTML = "";
      if (data.models && data.models.length > 0) {
        data.models.forEach(m => {
          const opt = document.createElement("option");
          opt.value = m;
          opt.innerText = m;
          select.appendChild(opt);
        });
      }
    })
    .catch(err => console.error("Failed to load models:", err));
}

function loadUserSessions() {
  if (!currentUser) return;

  fetch(`/api/sessions/${currentUser.id}`)
    .then(res => (res.ok ? res.json() : null))
    .then(sessions => {
      // A rejected request returns an error object, not a list. Assigning that straight to
      // sessionsList made every later sessionsList.forEach(...) throw, so one expired token
      // turned into a broken sidebar and a console full of TypeErrors.
      if (!Array.isArray(sessions)) return;   // 401/403 already handled by the fetch wrapper
      sessionsList = sessions;
      renderSidebarSessions();
      if (sessionsList.length > 0 && !currentSessionId) {
        loadSession(sessionsList[0].id);
      } else if (sessionsList.length === 0) {
        createNewChatSession();
      }
    })
    .catch(err => console.error("Error loading sessions:", err));
}

function renderSidebarSessions() {
  const listContainer = document.getElementById("chat-history-list");
  if (!listContainer) return;

  if (sessionsList.length === 0) {
    listContainer.innerHTML = '<div class="empty-history-text">No project sessions yet. Click "+ New Chat" above.</div>';
    return;
  }

  let html = "";
  sessionsList.forEach(session => {
    const isActive = session.id === currentSessionId ? "active" : "";
    html += `
      <div class="chat-item ${isActive}" onclick="loadSession('${session.id}')">
        <div class="chat-item-title-box">
          <svg class="chat-item-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
          <span class="chat-item-text">${escapeHtml(session.title)}</span>
        </div>
        <div class="chat-item-actions">
          <button class="chat-item-action chat-item-rename" onclick="event.stopPropagation(); renameSession('${session.id}', '${escapeHtml(session.title)}')" title="Rename Workspace">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          </button>
          <button class="chat-item-action chat-item-delete" onclick="event.stopPropagation(); deleteSession('${session.id}')" title="Delete Workspace">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          </button>
        </div>
      </div>
    `;
  });
  listContainer.innerHTML = html;
}

function renameSession(sessionId, currentTitle) {
  if (!currentUser) return;
  const newTitle = prompt("Enter new title for this program workspace:", currentTitle);
  if (!newTitle || !newTitle.trim()) return;

  fetch("/api/sessions/rename", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      user_id: currentUser.id,
      session_id: sessionId,
      new_title: newTitle.trim()
    })
  })
  .then(res => res.json())
  .then(data => {
    const session = sessionsList.find(s => s.id === sessionId);
    if (session) session.title = newTitle.trim();
    renderSidebarSessions();
  })
  .catch(err => console.error("Error renaming session:", err));
}

function createNewChatSession() {
  if (!currentUser) return;

  fetch("/api/sessions/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: currentUser.id, title: "New Program Workspace" })
  })
  .then(res => res.json())
  .then(newSession => {
    currentSessionId = newSession.id;
    sessionsList.unshift(newSession);
    renderSidebarSessions();
    resetUI(10);
    document.getElementById("prompt-input").value = "";
    document.getElementById("prompt-input").focus();
    closeSidebar();
  })
  .catch(err => console.error("Error creating chat session:", err));
}

function loadSession(sessionId) {
  if (!currentUser) return;
  currentSessionId = sessionId;
  renderSidebarSessions();
  closeSidebar();

  fetch(`/api/sessions/${currentUser.id}/${sessionId}`)
    .then(res => res.json())
    .then(data => {
      currentLanguage = data.language || "python";
      const langSelect = document.getElementById("language-select");
      if (langSelect) langSelect.value = currentLanguage;

      if (data.app_code) {
        updateCodeView(data.app_code);
      } else {
        updateCodeView("# New program workspace created.\nEnter a prompt above to generate software...");
      }

      if (data.test_code) {
        const testEl = document.getElementById("test-display");
        if (testEl) {
          testEl.textContent = data.test_code;
          if (window.hljs) {
            delete testEl.dataset.highlighted;
            hljs.highlightElement(testEl);
          }
        }
      }

      if (data.vulnerability_report) {
        renderAuditReport(data.vulnerability_report);
      } else {
        document.getElementById("audit-display").innerHTML = '<p class="empty-state">No security vulnerability report generated yet for this session.</p>';
      }

      const beforeEl = document.getElementById("diff-before");
      const afterEl = document.getElementById("diff-after");
      if (data.diff_before && data.diff_after) {
        if (beforeEl) {
          beforeEl.textContent = data.diff_before;
          if (window.hljs) { delete beforeEl.dataset.highlighted; hljs.highlightElement(beforeEl); }
        }
        if (afterEl) {
          afterEl.textContent = data.diff_after;
          if (window.hljs) { delete afterEl.dataset.highlighted; hljs.highlightElement(afterEl); }
        }
      } else {
        if (beforeEl) {
          beforeEl.textContent = "# Vulnerable code version pre-patch will appear here...";
          if (window.hljs) { delete beforeEl.dataset.highlighted; hljs.highlightElement(beforeEl); }
        }
        if (afterEl) {
          afterEl.textContent = "# Securitized code version post-patch will appear here...";
          if (window.hljs) { delete afterEl.dataset.highlighted; hljs.highlightElement(afterEl); }
        }
      }

      const runOut = document.getElementById("run-output");
      if (runOut) runOut.innerHTML = '<div class="terminal-line system" style="color: #64748b; font-style: italic;">[Interactive run ready. Click "▶ Interactive Run" to execute code.]</div>';

      appendTerminal(`[Session] Switched active workspace to session: ${sessionId}`, "system");
      loadWorkspaceFiles();
    })
    .catch(err => console.error("Error loading session details:", err));
}

function deleteSession(sessionId) {
  if (!currentUser) return;
  if (!confirm("Are you sure you want to delete this project workspace?")) return;

  fetch(`/api/sessions/${currentUser.id}/${sessionId}`, { method: "DELETE" })
    .then(res => res.json())
    .then(() => {
      sessionsList = sessionsList.filter(s => s.id !== sessionId);
      if (currentSessionId === sessionId) {
        currentSessionId = sessionsList.length > 0 ? sessionsList[0].id : null;
        if (currentSessionId) {
          loadSession(currentSessionId);
        } else {
          createNewChatSession();
        }
      } else {
        renderSidebarSessions();
      }
    })
    .catch(err => console.error("Error deleting session:", err));
}

function openSidebar() {
  const sidebar = document.getElementById("sidebar");
  const backdrop = document.getElementById("sidebar-backdrop");
  if (sidebar) sidebar.classList.add("open");
  if (backdrop) backdrop.classList.add("active");
}

function closeSidebar() {
  const sidebar = document.getElementById("sidebar");
  const backdrop = document.getElementById("sidebar-backdrop");
  if (sidebar) sidebar.classList.remove("open");
  if (backdrop) backdrop.classList.remove("active");
}

function toggleSidebar() {
  const sidebar = document.getElementById("sidebar");
  if (sidebar && sidebar.classList.contains("open")) {
    closeSidebar();
  } else {
    openSidebar();
  }
}

function setPrompt(text) {
  document.getElementById("prompt-input").value = text;
}

function switchTab(tabName) {
  document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll(".tab-content").forEach(content => content.classList.remove("active"));

  if (event && event.target) {
    event.target.classList.add("active");
  }
  const targetTab = document.getElementById(`tab-${tabName}`);
  if (targetTab) {
    targetTab.classList.add("active");
  }

  highlightAllCodeBlocks();
}

function executeSwarmLoop() {
  startSwarm();
}

function downloadSecurePackage() {
  exportZipPackage();
}

function startSwarm() {
  if (isRunning) return;
  if (requireAuth()) return;

  if (!currentSessionId) {
    fetch("/api/sessions/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: currentUser.id, title: "New Program Workspace" })
    })
    .then(res => res.json())
    .then(newSession => {
      currentSessionId = newSession.id;
      sessionsList.unshift(newSession);
      renderSidebarSessions();
      startSwarm();
    })
    .catch(err => console.error("Error creating session:", err));
    return;
  }

  const promptInput = document.getElementById("prompt-input");
  const prompt = promptInput ? promptInput.value.trim() : "";
  // User-chosen iteration limit, clamped to SAFETY_MAX_LOOPS as a hard ceiling against a
  // runaway loop. The backend's own "no progress" and time-budget guards can still stop a
  // run earlier than this — this is the upper bound, not a target to reach.
  const loopSelect = document.getElementById("max-loops-select");
  const chosenLoops = loopSelect ? parseInt(loopSelect.value, 10) : 5;
  const maxLoops = Math.min(Number.isNaN(chosenLoops) ? 5 : chosenLoops, SAFETY_MAX_LOOPS);
  const selectedModel = document.getElementById("model-select").value;
  const langSelect = document.getElementById("language-select");
  const selectedLanguage = langSelect ? langSelect.value : "python";
  if (!prompt) {
    alert("Please enter a software prompt to execute!");
    return;
  }

  currentLanguage = selectedLanguage;

  isRunning = true;
  const runBtn = document.getElementById("run-btn");
  if (runBtn) {
    runBtn.disabled = true;
    runBtn.innerText = "Executing...";
  }

  resetUI(maxLoops);

  fetch("/api/swarm/execute", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      prompt: prompt,
      max_loops: maxLoops,
      selected_model: selectedModel,
      language: selectedLanguage,
      user_id: currentUser.id,
      session_id: currentSessionId
    })
  }).then(res => res.json())
  .then(data => {
    if (data.status === "already_running") {
      // The backend already has a run active for this session (e.g. this button's own
      // watchdog reset it client-side while the server was still genuinely working) —
      // don't claim we started a new one, and don't leave the button falsely re-enabled.
      appendTerminal(`\n[System] ${data.message || "A run is already active for this session."}`, "cmd");
      return;
    }
    appendTerminal(`[System] Swarm workflow triggered for prompt: "${prompt}" (Session: ${currentSessionId})`, "system");
    setTimeout(loadUserSessions, 1000);
  }).catch(err => {
    console.error("Failed to start swarm:", err);
    isRunning = false;
    if (runBtn) {
      runBtn.disabled = false;
      runBtn.innerText = "Execute Swarm Loop";
    }
  });

  clearTimeout(swarmWatchdogTimer);
  swarmWatchdogTimer = setTimeout(() => {
    if (!isRunning) return;
    // Margin above the backend's own per-call model timeout (240s for local Ollama models)
    // so a single legitimately-slow generation call doesn't itself trip this watchdog —
    // it should only fire on a genuine hang (dropped connection, crashed server, etc).
    appendTerminal(`\n[Watchdog] No response from server after 320s (connection lost or server error). Resetting — please try again.`, "cmd");
    isRunning = false;
    const btn = document.getElementById("run-btn");
    if (btn) {
      btn.disabled = false;
      btn.innerText = "Execute Swarm Loop";
    }
    ["coder", "tester", "hacker", "patcher"].forEach(a => setAgentState(a, "", "IDLE"));
  }, 320000);
}

function toggleEditMode() {
  isEditMode = !isEditMode;
  const displayPre = document.querySelector("#tab-code .vscode-code-pre");
  const editorArea = document.getElementById("code-editor");
  const toggleBtn = document.getElementById("edit-toggle-btn");

  if (isEditMode) {
    displayPre.style.display = "none";
    editorArea.style.display = "block";
    toggleBtn.innerText = "👁️ View Highlighted Code";
  } else {
    displayPre.style.display = "block";
    editorArea.style.display = "none";
    toggleBtn.innerText = "✏️ Edit Custom Code";
    updateCodeView(editorArea.value);
  }
}

function auditCustomCode() {
  if (!currentUser) {
    alert("Please sign in to audit custom code!");
    return;
  }

  const customCode = document.getElementById("code-editor").value;
  if (!customCode.trim()) return;

  if (isEditMode) {
    toggleEditMode();
  } else {
    updateCodeView(customCode);
  }

  isRunning = true;
  document.getElementById("run-btn").disabled = true;
  document.getElementById("run-btn").innerText = "Auditing Code...";

  fetch("/api/swarm/audit-custom-code", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ 
      code: customCode, 
      user_id: currentUser.id, 
      session_id: currentSessionId,
      filename: (typeof activeFilename !== 'undefined') ? activeFilename : "generated_app.py"
    })
  }).then(res => res.json())
  .then(data => {
    appendTerminal(`[System] User custom code edits submitted. Hacker & Patcher Agents activated!`, "system");
  }).catch(err => {
    console.error("Error submitting custom code:", err);
    isRunning = false;
    document.getElementById("run-btn").disabled = false;
    document.getElementById("run-btn").innerText = "Execute Swarm Loop";
  });
}

function extendIterations() {
  fetch("/api/swarm/extend", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      user_id: currentUser ? currentUser.id : "default_user",
      session_id: currentSessionId
    })
  })
    .then(res => res.json())
    .then(data => {
      document.getElementById("max-loop-display").innerText = data.new_max_loops;
      appendTerminal(`[System] Extended max iterations by +5 loops. New limit: ${data.new_max_loops}`, "system");
    })
    .catch(err => console.error("Error extending iterations:", err));
}

function exportZipPackage() {
  if (!currentUser) {
    alert("Please sign in to export your workspace package!");
    return;
  }
  window.location.href = `/api/swarm/export/${currentUser.id}`;
}

function downloadPdfReport() {
  if (!currentUser) {
    alert("Please sign in to download your Compliance PDF Certificate!");
    return;
  }
  const sid = currentSessionId || "main";
  window.location.href = `/api/swarm/export-pdf/${currentUser.id}/${sid}`;
}



function selectPayload(type) {
  const input = document.getElementById("exploit-input");
  if (type === 'eval') input.value = "__import__('os').system('whoami')";
  else if (type === 'sqli') input.value = "' OR '1'='1' --";
  else if (type === 'traversal') input.value = "../../../../etc/passwd";
}

function runExploitSimulation() {
  const payload = document.getElementById("exploit-input").value;
  const resultBox = document.getElementById("exploit-result");
  const preOut = document.getElementById("exploit-out-pre");
  const postOut = document.getElementById("exploit-out-post");
  const runBtn = document.getElementById("btn-run-exploit");

  runBtn.innerText = "Simulating Cyber Attack Payload...";
  runBtn.disabled = true;

  setTimeout(() => {
    resultBox.style.display = "grid";
    runBtn.innerText = "Launch Live Exploit Simulation";
    runBtn.disabled = false;

    if (payload.includes("system") || payload.includes("eval")) {
      preOut.innerText = `$ python generated_app.py --expr "${payload}"\n[VULNERABLE] Output: root / SYSTEM\n[CRITICAL ALERT] Remote Code Execution via eval() (CWE-95) succeeded!\nProcess memory compromised. Arbitrary shell access granted.`;
      postOut.innerText = `$ python generated_app.py --expr "${payload}"\n[SAFE] ValueError: Dangerous syntax '__import__' is blocked by AST Safe Evaluator.\n[REMEDIATED] 0 vulnerabilities exposed. Application protected by secure AST parser.`;
    } else if (payload.includes("OR")) {
      preOut.innerText = `$ python generated_app.py --user "admin' OR '1'='1"\n[VULNERABLE] Query executed: SELECT * FROM users WHERE username = 'admin' OR '1'='1'\n[CRITICAL ALERT] SQL Injection (CWE-89) succeeded!\nAuthentication bypassed cleanly. Logged in as administrator.`;
      postOut.innerText = `$ python generated_app.py --user "admin' OR '1'='1"\n[SAFE] Query executed: SELECT * FROM users WHERE username = ? [Params: ("admin' OR '1'='1",)]\n[REMEDIATED] Parameterized prepared query blocked injection. Invalid login rejected.`;
    } else {
      preOut.innerText = `$ python generated_app.py --file "${payload}"\n[VULNERABLE] File content exposed: root:x:0:0:root:/root:/bin/bash\n[CRITICAL ALERT] Path Traversal (CWE-22) succeeded!\nSystem credentials read from filesystem.`;
      postOut.innerText = `$ python generated_app.py --file "${payload}"\n[SAFE] PermissionError: Access outside sandbox directory blocked by os.path.resolve().\n[REMEDIATED] Path traversal blocked cleanly. File request denied.`;
    }

    appendTerminal(`[Red-Team Exploit Sandbox] Live payload simulation completed for: ${payload}`, "cmd");
  }, 600);
}



function resetUI(maxLoops = 10) {
  syncCodeLangClasses();
  document.querySelectorAll(".agent-node").forEach(node => {
    node.className = "agent-node card-static-pop";
  });
  document.querySelectorAll(".agent-status").forEach(st => {
    st.innerHTML = '<span class="status-dot dot-idle"></span> IDLE';
  });

  // Clear Code Editor tab
  updateCodeView("# New program workspace created.\nEnter a prompt above to generate software...");

  // Clear Pytest suite tab
  const testEl = document.getElementById("test-display");
  if (testEl) {
    testEl.textContent = "# Pytest test suite will generate here when you run the swarm...";
    if (window.hljs) {
      delete testEl.dataset.highlighted;
      hljs.highlightElement(testEl);
    }
  }

  // Clear Audit Report tab
  document.getElementById("audit-display").innerHTML = '<p class="empty-state">No security vulnerability report generated yet. Run the swarm to analyze app.py with Bandit.</p>';

  // Clear Diff view tabs
  const beforeEl = document.getElementById("diff-before");
  const afterEl = document.getElementById("diff-after");
  if (beforeEl) {
    beforeEl.textContent = "# Vulnerable code version pre-patch will appear here...";
    if (window.hljs) { delete beforeEl.dataset.highlighted; hljs.highlightElement(beforeEl); }
  }
  if (afterEl) {
    afterEl.textContent = "# Securitized code version post-patch will appear here...";
    if (window.hljs) { delete afterEl.dataset.highlighted; hljs.highlightElement(afterEl); }
  }

  // Clear Exploit Sandbox outputs
  const exploitResult = document.getElementById("exploit-result");
  if (exploitResult) exploitResult.style.display = "none";

  // Clear Terminal Output
  document.getElementById("terminal-output").innerHTML = '<div class="terminal-line system">[System initialized. New workspace ready...]</div>';
  
  // Clear Interactive Run Output
  const runOut = document.getElementById("run-output");
  if (runOut) runOut.innerHTML = '<div class="terminal-line system" style="color: #64748b; font-style: italic;">[Interactive run ready. Click "▶ Interactive Run" to execute code.]</div>';

  document.getElementById("loop-counter").innerText = "0";
  document.getElementById("max-loop-display").innerText = maxLoops;

  // Switch tab to main app.py code view
  switchTabByName("code");
}

function updateCodeView(codeText) {
  syncCodeLangClasses();
  const editor = document.getElementById("code-editor");
  const codeDisplay = document.getElementById("code-display");

  if (editor) editor.value = codeText;
  if (codeDisplay) {
    codeDisplay.textContent = codeText;
    if (window.hljs) {
      delete codeDisplay.dataset.highlighted;
      hljs.highlightElement(codeDisplay);
    }
  }
}

function highlightAllCodeBlocks() {
  if (window.hljs) {
    document.querySelectorAll('pre code').forEach((el) => {
      delete el.dataset.highlighted;
      hljs.highlightElement(el);
    });
  }
}

function handleSwarmEvent(data) {
  syncCodeLangClasses();
  if (isRunning && data.type !== "PIPELINE_COMPLETE") {
    clearTimeout(swarmWatchdogTimer);
    swarmWatchdogTimer = setTimeout(() => {
      if (!isRunning) return;
      appendTerminal(`\n[Watchdog] No response from server after 320s (connection lost or server error). Resetting — please try again.`, "cmd");
      isRunning = false;
      const btn = document.getElementById("run-btn");
      if (btn) {
        btn.disabled = false;
        btn.innerText = "Execute Swarm Loop";
      }
      ["coder", "tester", "hacker", "patcher"].forEach(a => setAgentState(a, "", "IDLE"));
    }, 320000);
  }

  switch (data.type) {
    case "STATUS":
      const statusEl = document.getElementById("status-text");
      if (statusEl) statusEl.innerText = cleanText(data.message);
      break;

    case "LOOP_START":
      document.getElementById("loop-counter").innerText = data.loop;
      document.getElementById("max-loop-display").innerText = data.max_loops;
      ["tester", "hacker", "patcher"].forEach(a => setAgentState(a, "", "IDLE"));
      break;

    case "AGENT_START":
      setAgentState(data.agent, "running", "EXECUTING");
      appendTerminal(`\n=== ${data.title} ===`, "cmd");
      if (data.agent === "coder") {
        switchTabByName("code");
      } else if (data.agent === "patcher") {
        switchTabByName("diff");
      }
      break;

    case "AGENT_END":
      if (data.agent === "coder" && (data.status === "SUCCESS" || data.status === "FAILED")) {
        loadWorkspaceFiles();
      }
      if (data.status === "SUCCESS") {
        setAgentState(data.agent, "success", "PASSED");
      } else if (data.status === "VULNERABLE") {
        setAgentState(data.agent, "vulnerable", "VULNERABLE");
      } else if (data.status === "PATCHED") {
        setAgentState(data.agent, "success", "PATCHED");
      } else if (data.status === "VERIFIED_SECURE") {
        setAgentState(data.agent, "success", "SECURE");
      } else {
        setAgentState(data.agent, "", "FAILED");
      }
      break;

    case "LOG":
      appendTerminal(cleanText(data.text));
      break;

    case "TERMINAL_OUTPUT":
      if (data.cmd) appendTerminal(`$ ${data.cmd}`, "cmd");
      appendTerminal(cleanText(data.output));
      break;

    case "FILE_STREAM":
      if (data.file.startsWith("generated_app.")) {
        updateCodeView(data.content);
      }
      break;

    case "FILE_UPDATE":
      if (data.file.startsWith("generated_app.")) {
        updateCodeView(data.content);
      } else if (data.file.startsWith("test_generated_app.")) {
        const testEl = document.getElementById("test-display");
        if (testEl) {
          testEl.textContent = data.content;
          if (window.hljs) {
            delete testEl.dataset.highlighted;
            hljs.highlightElement(testEl);
          }
        }
      } else if (data.file === "vulnerability_report.md") {
        renderAuditReport(data.content);
      }
      break;

    case "DIFF_UPDATE":
      const beforeEl = document.getElementById("diff-before");
      const afterEl = document.getElementById("diff-after");
      if (beforeEl) {
        beforeEl.textContent = data.before;
        if (window.hljs) {
          delete beforeEl.dataset.highlighted;
          hljs.highlightElement(beforeEl);
        }
      }
      if (afterEl) {
        afterEl.textContent = data.after;
        if (window.hljs) {
          delete afterEl.dataset.highlighted;
          hljs.highlightElement(afterEl);
        }
      }
      break;

    case "INTERACTIVE_OUTPUT":
      appendRunOutput(data.text, "run-line-out");
      break;

    case "PROCESS_DONE":
      currentProcessId = null;
      setRunStatus("idle");
      const exitCode = data.exit_code;
      if (exitCode === 0) {
        appendRunOutput(`\n[Process exited cleanly (code 0)]`, "run-line-done");
      } else {
        appendRunOutput(`\n[Process exited with error (code ${exitCode})]`, "run-line-fail");
      }
      const runBtnDone = document.getElementById("run-code-btn");
      if (runBtnDone) { runBtnDone.disabled = false; runBtnDone.innerText = "▶ Run Interactive"; }
      break;

    case "RUN_COMPLETE":
      const recheckBtnEl = document.getElementById("recheck-btn");
      if (recheckBtnEl) {
        recheckBtnEl.disabled = false;
        recheckBtnEl.innerText = "🔁 Recheck with AI";
      }
      appendTerminal(`\n[Run Complete] Status: ${data.status} after ${data.attempts} attempt(s).`, "cmd");
      break;

    case "PIPELINE_COMPLETE":
      clearTimeout(swarmWatchdogTimer);
      isRunning = false;
      document.getElementById("run-btn").disabled = false;
      document.getElementById("run-btn").innerText = "Execute Swarm Loop";
      const statusComp = document.getElementById("status-text");
      if (statusComp) {
        const statusLabels = {
          SUCCESS: "Verified Secure",
          // Security audit passed but QA only ran a placeholder test — must not read as a
          // clean bill of health, because the app's behaviour was never actually checked.
          SUCCESS_UNVERIFIED: "Secure — Tests Not Verified",
          STUCK: "Stopped — No Fix Found",
          MAX_LOOPS_REACHED: "Stopped — Loop Limit Reached",
          TIME_LIMIT: "Stopped — Time Limit Reached",
          ERROR: "Error",
        };
        statusComp.innerText = statusLabels[data.status] || "Stopped";
      }
      appendTerminal(`\n[Pipeline Complete] ${cleanText(data.message)}`, "cmd");
      loadUserSessions();
      loadWorkspaceFiles();
      break;
  }
}

function renderAuditReport(content) {
  const container = document.getElementById("audit-display");
  if (!content) return;

  let html = `<div class="audit-report-card">`;
  const lines = content.split("\n");
  for (let line of lines) {
    if (line.startsWith("# ")) {
      html += `<h2>${escapeHtml(line.replace("# ", ""))}</h2>`;
    } else if (line.startsWith("### ")) {
      html += `<h3>${escapeHtml(line.replace("### ", ""))}</h3>`;
    } else if (line.startsWith("- ")) {
      html += `<div class="audit-finding-item">${escapeHtml(line.replace("- ", ""))}</div>`;
    } else if (line.trim()) {
      html += `<p>${escapeHtml(line)}</p>`;
    }
  }
  html += `</div>`;
  container.innerHTML = html;
}

function switchTabByName(tabName) {
  const btn = Array.from(document.querySelectorAll(".tab-btn")).find(b => b.innerText.toLowerCase().includes(tabName));
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

  if (btn) btn.classList.add("active");
  const target = document.getElementById(`tab-${tabName}`);
  if (target) target.classList.add("active");

  highlightAllCodeBlocks();
}

// ── Interactive Run Terminal ──────────────────────────────────────────────

function appendRunOutput(text, cls = "run-line-out") {
  const out = document.getElementById("run-output");
  if (!out) return;
  const div = document.createElement("div");
  div.className = `terminal-line ${cls}`;
  div.innerText = text;
  out.appendChild(div);
  out.scrollTop = out.scrollHeight;
}

function setRunStatus(state) {
  const lbl = document.getElementById("run-status-label");
  const killBtn = document.getElementById("run-kill-btn");
  const inputField = document.getElementById("run-input-field");
  const sendBtn = document.getElementById("run-send-btn");
  if (state === "running") {
    if (lbl) { lbl.className = "run-status-running"; lbl.innerText = "● Process running — type input below"; }
    if (killBtn) killBtn.style.display = "inline-block";
    if (inputField) inputField.disabled = false;
    if (sendBtn) sendBtn.disabled = false;
    if (inputField) inputField.focus();
  } else {
    if (lbl) { lbl.className = "run-status-idle"; lbl.innerText = "● No process running"; }
    if (killBtn) killBtn.style.display = "none";
    if (inputField) inputField.disabled = true;
    if (sendBtn) sendBtn.disabled = true;
  }
}

function getActiveLanguage() {
  return (typeof currentLanguage !== 'undefined' && currentLanguage) ? currentLanguage : "python";
}

// The code/test/diff panels' <code> elements were hardcoded with class="language-python" in
// the HTML, so hljs kept applying Python syntax rules to C++/Java sessions. Re-tag them with
// the actual active language before every highlight pass.
function syncCodeLangClasses() {
  const lang = getActiveLanguage();
  ["code-display", "test-display", "diff-before", "diff-after"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.className = `language-${lang}`;
  });
}

function runInteractive() {
  if (requireAuth()) return;
  const code = getActiveCode();
  if (!code.trim()) { alert("No code to run. Generate code first or paste it in the editor."); return; }

  const btn = document.getElementById("run-code-btn");
  if (btn) { btn.disabled = true; btn.innerText = "Running..."; }

  // Clear previous output
  const out = document.getElementById("run-output");
  if (out) out.innerHTML = "";

  currentProcessId = "proc_" + Date.now();
  switchTabByName("run");
  setRunStatus("running");
  appendRunOutput("[Interactive Run] Starting process...", "terminal-line system");

  fetch("/api/run/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code: code,
      process_id: currentProcessId,
      user_id: currentUser.id,
      session_id: currentSessionId,
      language: getActiveLanguage()
    })
  }).catch(err => {
    appendRunOutput("[Error] Failed to start process: " + err, "run-line-fail");
    setRunStatus("idle");
    if (btn) { btn.disabled = false; btn.innerText = "▶ Run Interactive"; }
  });
}

function sendRunInput() {
  if (!currentProcessId) return;
  const field = document.getElementById("run-input-field");
  if (!field) return;
  const text = field.value;
  field.value = "";
  appendRunOutput("❯ " + text, "run-line-in");
  fetch("/api/run/input", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ process_id: currentProcessId, text: text, user_id: currentUser ? currentUser.id : "guest" })
  })
  .then(res => {
    if (!res.ok) appendRunOutput("[Warning] Server couldn't deliver that input — the process may have already ended.", "run-line-fail");
    return res.json();
  })
  .then(data => {
    if (data && data.status === "error") {
      appendRunOutput(`[Warning] ${data.message || "No active process to send input to."}`, "run-line-fail");
    }
  })
  .catch(() => {
    appendRunOutput("[Error] Could not reach the server — the backend may be down. Restart it and refresh this page.", "run-line-fail");
  });
}

async function killRunProcess() {
  if (!currentProcessId) return;
  const killedId = currentProcessId;
  try {
    const res = await fetch("/api/run/kill", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ process_id: killedId, text: "", user_id: currentUser ? currentUser.id : "guest" })
    });
    if (res.ok) {
      appendRunOutput("[Process killed by user]", "run-line-fail");
    } else {
      appendRunOutput(`[Warning] Server responded with an error (status ${res.status}) — the process may still be running. Try again or restart the backend.`, "run-line-fail");
    }
  } catch (err) {
    appendRunOutput("[Error] Could not reach the server to kill this process — the backend may be down. Restart it and refresh this page.", "run-line-fail");
  }
  setRunStatus("idle");
  currentProcessId = null;
  const btn = document.getElementById("run-code-btn");
  if (btn) { btn.disabled = false; btn.innerText = "▶ Run Interactive"; }
}

function getActiveCode() {
  const editorEl = document.getElementById("code-editor");
  const displayEl = document.getElementById("code-display");
  if (isEditMode && editorEl) return editorEl.value;
  return displayEl ? displayEl.innerText : (editorEl ? editorEl.value : "");
}

function runActiveCode() {
  if (requireAuth()) return;

  const code = getActiveCode();
  if (!code.trim()) return;

  const recheckBtn = document.getElementById("recheck-btn");
  if (recheckBtn) {
    recheckBtn.disabled = true;
    recheckBtn.innerText = "Rechecking...";
  }

  switchTabByName("terminal");
  appendTerminal(`\n[System] Asking AI to run and auto-fix the current code...`, "cmd");

  const modelSelect = document.getElementById("model-select");

  fetch("/api/swarm/run-code", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code: code,
      user_id: currentUser.id,
      session_id: currentSessionId,
      selected_model: modelSelect ? modelSelect.value : null,
      language: getActiveLanguage()
    })
  }).catch(err => {
    console.error("Error running code:", err);
    if (recheckBtn) {
      recheckBtn.disabled = false;
      recheckBtn.innerText = "🔁 Recheck with AI";
    }
  });
}

function copyActiveCode() {
  const codeEl = document.getElementById("code-display");
  const editorEl = document.getElementById("code-editor");
  const copyBtn = document.getElementById("copy-code-btn");
  
  const textToCopy = (isEditMode && editorEl) ? editorEl.value : (codeEl ? codeEl.innerText : "");
  if (!textToCopy) return;

  navigator.clipboard.writeText(textToCopy).then(() => {
    if (copyBtn) {
      const origText = copyBtn.innerText;
      copyBtn.innerText = "✅ Copied to Clipboard!";
      copyBtn.style.background = "#2a9d8f";
      copyBtn.style.color = "#ffffff";
      setTimeout(() => {
        copyBtn.innerText = origText;
        copyBtn.style.background = "";
        copyBtn.style.color = "";
      }, 2000);
    }
  }).catch(err => console.error("Copy failed:", err));
}

function setAgentState(agentId, className, statusText) {
  const node = document.getElementById(`agent-${agentId}`);
  const statusEl = document.getElementById(`status-${agentId}`);
  if (node) {
    node.className = `agent-node card-static-pop ${className}`;
  }
  
  let dotClass = "dot-idle";
  if (className === "running" || className === "executing") {
    dotClass = "dot-executing";
  } else if (className === "success" || className === "passed" || className === "patched") {
    dotClass = "dot-passed";
  } else if (className === "vulnerable" || className === "failed") {
    dotClass = "dot-vulnerable";
  } else if (className === "remediated") {
    dotClass = "dot-remediated";
  }

  if (statusEl) {
    statusEl.innerHTML = `<span class="status-dot ${dotClass}"></span> ${statusText}`;
  }
}

function appendTerminal(text, type = "") {
  const term = document.getElementById("terminal-output");
  const line = document.createElement("div");
  line.className = `terminal-line ${type}`;
  line.innerText = text;
  term.appendChild(line);
  term.scrollTop = term.scrollHeight;
}

function cleanText(str) {
  if (!str) return '';
  return str.replace(/[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu, '');
}

function escapeHtml(text) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

document.addEventListener("DOMContentLoaded", () => {
  initAppLoader();
  initSupabase();
  initWebSocket();
  loadAvailableModels();

  const savedApiKey = localStorage.getItem("gemini_api_key");
  const apiKeyEl = document.getElementById("gemini-api-key-input");
  if (savedApiKey && apiKeyEl) {
    apiKeyEl.value = savedApiKey;
  }

  const runField = document.getElementById("run-input-field");
  if (runField) {
    runField.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); sendRunInput(); }
    });
  }
});


// --- ADVANCED FEATURES ---

// 1. Save Code Locally
async function saveCodeLocally() {
  const code = getActiveCode();
  const btn = document.getElementById("save-code-btn");
  if (!code || !btn) return;
  
  const originalText = btn.innerHTML;
  btn.innerText = "Saving...";
  btn.disabled = true;

  try {
    const res = await fetch("/api/save-code", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: code,
        user_id: currentUser ? currentUser.id : "default",
        session_id: currentSessionId || "default",
        filename: (typeof activeFilename !== 'undefined') ? activeFilename : "generated_app.py"
      })
    });
    if (!res.ok) throw new Error("Failed to save");
    
    btn.innerHTML = "? Saved!";
    setTimeout(() => { btn.innerHTML = originalText; btn.disabled = false; }, 2000);
  } catch (err) {
    btn.innerHTML = "? Error";
    setTimeout(() => { btn.innerHTML = originalText; btn.disabled = false; }, 2000);
  }
}

// Enable Save Code Button in Edit Mode
const originalToggleEditMode = toggleEditMode;
toggleEditMode = function() {
  originalToggleEditMode();
  const saveBtn = document.getElementById("save-code-btn");
  if (saveBtn) {
    saveBtn.style.display = isEditMode ? "inline-flex" : "none";
  }
};

// Ctrl+S Listener for Code Editor
document.addEventListener("keydown", (e) => {
  if (isEditMode && (e.ctrlKey || e.metaKey) && e.key === "s") {
    e.preventDefault();
    saveCodeLocally();
  }
});

// 2. Download Audit Report
function downloadAuditReport() {
  const auditContainer = document.getElementById("audit-display");
  if (!auditContainer || auditContainer.innerText.includes("No security vulnerability report generated yet")) {
    alert("No report to download yet.");
    return;
  }
  
  // Extract text and clean it up for Markdown
  let reportText = auditContainer.innerText;
  const blob = new Blob([reportText], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `security_audit_report_${currentSessionId || "default"}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// --- MULTI-FILE EXPLORER LOGIC ---
let activeFilename = "generated_app.py";

async function loadWorkspaceFiles() {
  if (!currentUser || !currentSessionId) return;
  try {
    const res = await fetch(`/api/workspace-files?user_id=${currentUser.id}&session_id=${currentSessionId}`);
    if (!res.ok) return;
    const data = await res.json();
    const files = data.files || [];
    renderFileTree(files);
    // Keep currentLanguage in sync with whichever generated_app.* file actually exists,
    // rather than trusting UI state that may be stale from a previous session/run.
    if (files.includes("generated_app.cpp")) currentLanguage = "cpp";
    else if (files.includes("generated_app.java")) currentLanguage = "java";
    else if (files.includes("generated_app.py")) currentLanguage = "python";
  } catch (err) {
    console.error("Failed to load workspace files:", err);
  }
}

function renderFileTree(files) {
  const tree = document.getElementById("file-tree");
  if (!tree) return;
  tree.innerHTML = "";
  
  if (files.length === 0) {
    tree.innerHTML = `<div style="color: #64748b; font-style: italic; padding: 10px;">No files yet. Generate some code first!</div>`;
    return;
  }
  
  files.forEach(file => {
    const isPython = file.endsWith(".py");
    const isCpp = file.endsWith(".cpp") || file.endsWith(".hpp") || file.endsWith(".h");
    const isJava = file.endsWith(".java");
    const isJson = file.endsWith(".json");
    const icon = isPython ? "&#128013;" : isCpp ? "&#9881;&#65039;" : isJava ? "&#9749;" : (isJson ? "&#128203;" : "&#128196;");
    
    const div = document.createElement("div");
    div.className = `file-node ${file === activeFilename ? "active-file" : ""}`;
    div.innerHTML = `<span class="file-icon">${icon}</span> ${escapeHtml(file)}`;
    div.onclick = () => loadFile(file);
    tree.appendChild(div);
  });
}

async function loadFile(filename) {
  activeFilename = filename;
  if (filename.startsWith("generated_app.")) {
    if (filename.endsWith(".cpp")) currentLanguage = "cpp";
    else if (filename.endsWith(".java")) currentLanguage = "java";
    else if (filename.endsWith(".py")) currentLanguage = "python";
  }

  // Re-render tree to update active highlight
  loadWorkspaceFiles();
  
  // Update Tab Label
  const tabCodeBtn = document.getElementById("tab-btn-code");
  if (tabCodeBtn) tabCodeBtn.innerText = `${filename} (Code Editor)`;
  
  try {
    const res = await fetch(`/api/file-content?user_id=${currentUser.id}&session_id=${currentSessionId}&filename=${encodeURIComponent(filename)}`);
    if (!res.ok) throw new Error("File not found");
    const data = await res.json();
    
    // Set Editor Content
    const pre = document.getElementById("code-display");
    if (pre) {
      const hljsLang = filename.endsWith(".cpp") ? "cpp" : filename.endsWith(".java") ? "java" : "python";
      pre.innerHTML = `<code class="language-${hljsLang}">${escapeHtml(data.content)}</code>`;
      hljs.highlightElement(pre.querySelector("code"));
    }
    
    // Set Textarea Content
    const ta = document.getElementById("code-editor-textarea");
    if (ta) ta.value = data.content;
    
    switchTab("code");
  } catch (err) {
    console.error("Failed to load file:", err);
  }
}

// Hook into loadSession to trigger file tree load
const originalLoadSession2 = loadSession;
loadSession = function(sessionId) {
  originalLoadSession2(sessionId);
  activeFilename = "generated_app.py";
  setTimeout(loadWorkspaceFiles, 800);
};


function toggleFileExplorer() {
  const sidebar = document.getElementById("file-explorer");
  if (sidebar) {
    if (sidebar.style.display === "none") {
      sidebar.style.display = "flex";
    } else {
      sidebar.style.display = "none";
    }
  }
}

