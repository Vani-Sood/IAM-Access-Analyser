"use strict";

// ── constants ──────────────────────────────────────────────────────────────────
const AUTH_KEY     = "iam_access_token";
const REFRESH_KEY  = "iam_refresh_token";

// ── token storage ─────────────────────────────────────────────────────────────
function getToken()         { return localStorage.getItem(AUTH_KEY); }
function setToken(t)        { localStorage.setItem(AUTH_KEY, t); }
function clearToken()       { localStorage.removeItem(AUTH_KEY); }
function isLoggedIn()       { return Boolean(getToken()); }

function getRefreshToken()  { return localStorage.getItem(REFRESH_KEY); }
function setRefreshToken(t) { localStorage.setItem(REFRESH_KEY, t); }
function clearRefreshToken(){ localStorage.removeItem(REFRESH_KEY); }

// ── auth headers ──────────────────────────────────────────────────────────────
function authHeaders() {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

// ── jwt helpers ───────────────────────────────────────────────────────────────
function getUserPayload() {
  const t = getToken();
  if (!t) return null;
  try {
    const parts = t.split(".");
    if (parts.length !== 3) return null;
    return JSON.parse(atob(parts[1]));
  } catch {
    return null;
  }
}

function isAdmin() {
  const p = getUserPayload();
  return p?.role === "admin";
}

// ── single-flight refresh state ───────────────────────────────────────────────
let _refreshPromise = null;
let _doNavigate = (url) => { window.location.href = url; };

function _resetRefreshState() {
  _refreshPromise = null;
  _doNavigate = (url) => { window.location.href = url; };
}

function _setNavigate(fn) { _doNavigate = fn; }

async function _doRefresh() {
  const rt = getRefreshToken();
  if (!rt) return false;
  try {
    const resp = await fetch("/api/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: rt }),
    });
    if (!resp.ok) return false;
    const data = await resp.json();
    setToken(data.access_token);
    return true;
  } catch {
    return false;
  }
}

function _clearSession() {
  clearToken();
  clearRefreshToken();
  _doNavigate("/index.html");
}

// ── api fetch wrapper ─────────────────────────────────────────────────────────
async function apiFetch(url, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...authHeaders(),
    ...(options.headers || {}),
  };
  const resp = await fetch(url, { ...options, headers });
  if (resp.status !== 401) return resp;

  // Token expired — attempt single-flight refresh
  if (!_refreshPromise) {
    _refreshPromise = _doRefresh().finally(() => { _refreshPromise = null; });
  }
  const refreshed = await _refreshPromise;
  if (!refreshed) {
    _clearSession();
    return null;
  }

  // Retry once with new token
  const retryHeaders = {
    ...headers,
    ...authHeaders(),  // picks up new token set by _doRefresh
  };
  const retryResp = await fetch(url, { ...options, headers: retryHeaders });
  if (retryResp.status === 401) {
    _clearSession();
    return null;
  }
  return retryResp;
}

// ── route guard ───────────────────────────────────────────────────────────────
function requireAuth() {
  if (!isLoggedIn()) {
    window.location.href = "/index.html";
  }
}

// ── nav component ─────────────────────────────────────────────────────────────
function renderNav(activePage) {
  const payload = getUserPayload();
  const email   = payload?.email || "";
  const admin   = isAdmin();

  const links = [
    { href: "analyze.html",   label: "Analyze",   key: "analyze"   },
    { href: "history.html",   label: "History",   key: "history"   },
    { href: "dashboard.html", label: "Dashboard", key: "dashboard" },
    { href: "orgs.html",      label: "Orgs",      key: "orgs"      },
    { href: "settings.html",  label: "Settings",  key: "settings"  },
  ];
  if (admin) links.push({ href: "admin.html", label: "Admin", key: "admin" });

  const navLinks = links.map(({ href, label, key }) => {
    const active = key === activePage ? ' class="nav-active"' : "";
    return `<a href="${href}"${active}>${label}</a>`;
  }).join("");

  const navHtml = `
    <nav class="top-nav">
      <a href="analyze.html" class="nav-brand">IAM Analyzer</a>
      <div class="nav-links">${navLinks}</div>
      <div class="nav-user">
        <span class="nav-email">${email}</span>
        <button class="nav-logout" id="nav-logout-btn">Logout</button>
      </div>
    </nav>`;

  const container = document.getElementById("nav-root");
  if (container) {
    container.innerHTML = navHtml;
    document.getElementById("nav-logout-btn").addEventListener("click", () => {
      clearToken();
      window.location.href = "/index.html";
    });
  }
}

// ── conditional export (jest / node) ─────────────────────────────────────────
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    getToken, setToken, clearToken, isLoggedIn,
    authHeaders, getUserPayload, isAdmin,
    getRefreshToken, setRefreshToken, clearRefreshToken,
    apiFetch, _resetRefreshState, _setNavigate,
  };
}
