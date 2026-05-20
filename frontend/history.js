"use strict";

// ── pure functions (exported for tests) ───────────────────────────────────────

function buildHistoryUrl(limit, offset) {
  return `/api/v1/analyses?limit=${limit}&offset=${offset}`;
}

function totalPages(total, limit) {
  if (total === 0) return 0;
  return Math.ceil(total / limit);
}

function calcOffset(page, limit) {
  return (page - 1) * limit;
}

function getPageFromSearch(search) {
  if (!search) return 1;
  const params = new URLSearchParams(search);
  const raw = params.get("page");
  if (!raw) return 1;
  const num = parseInt(raw, 10);
  return Number.isFinite(num) && num > 0 ? num : 1;
}

function matchesSeverityFilter(item, filter) {
  if (!filter) return true;
  return item.severity === filter;
}

function truncateHash(hash, max = 12) {
  if (!hash) return "";
  if (hash.length <= max) return hash;
  return hash.slice(0, max) + "…";
}

// ── conditional export ────────────────────────────────────────────────────────
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    buildHistoryUrl, totalPages, calcOffset,
    getPageFromSearch, matchesSeverityFilter, truncateHash,
  };
}

// ── browser-only DOM logic (skipped in Node/Jest) ─────────────────────────────
if (typeof module === "undefined") {

const PAGE_LIMIT = 20;

const errorBanner  = document.getElementById("error-banner");
const errorMsg     = document.getElementById("error-message");
const loadingEl    = document.getElementById("page-loading");
const tableBody    = document.getElementById("history-body");
const emptyState   = document.getElementById("history-empty");
const paginationEl = document.getElementById("pagination");
const filterEl     = document.getElementById("severity-filter");
const totalCountEl = document.getElementById("total-count");

let currentPage    = 1;
let currentFilter  = "";
let allItems       = [];
let serverTotal    = 0;

function showError(msg) {
  if (errorMsg)    errorMsg.textContent = msg;
  if (errorBanner) {
    errorBanner.classList.add("active");
    setTimeout(() => errorBanner.classList.remove("active"), 30000);
  }
}

function setLoading(active) {
  if (loadingEl) loadingEl.classList.toggle("active", active);
}

// ── Render helpers ────────────────────────────────────────────────────────────
const BADGE_CLASS = {
  CRITICAL: "badge-critical", HIGH: "badge-high",
  MEDIUM: "badge-medium",     LOW:  "badge-low",
};

function getRiskColor(score) {
  if (score >= 8.0) return "#ef4444";
  if (score >= 6.0) return "#f59e0b";
  if (score >= 4.0) return "#e8b94a";
  return "#22c55e";
}

function formatDate(isoStr) {
  const d = new Date(isoStr);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) +
         " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

// ── Render table ──────────────────────────────────────────────────────────────
function renderTable(items) {
  if (!items.length) {
    if (tableBody)  tableBody.innerHTML = "";
    if (emptyState) emptyState.style.display = "";
    return;
  }
  if (emptyState) emptyState.style.display = "none";
  tableBody.innerHTML = items.map(item => `
    <tr class="history-row" data-id="${item.id}" role="button" tabindex="0"
        title="View analysis #${item.id}">
      <td>${formatDate(item.created_at)}</td>
      <td><span class="finding-badge ${BADGE_CLASS[item.severity] || ""}">${item.severity}</span></td>
      <td style="color:${getRiskColor(item.risk_score)};font-weight:600">
        ${item.risk_score.toFixed(1)}
      </td>
      <td style="font-family:monospace;font-size:13px;color:var(--color-muted)">
        ${truncateHash(item.policy_hash)}
      </td>
      <td>
        <a href="analysis.html?id=${item.id}" class="btn-secondary"
           style="padding:4px 12px;font-size:13px;text-decoration:none">
          View
        </a>
      </td>
    </tr>`).join("");

  tableBody.querySelectorAll(".history-row").forEach(row => {
    const id = row.dataset.id;
    const nav = () => { window.location.href = `analysis.html?id=${id}`; };
    row.addEventListener("click", e => {
      if (e.target.tagName === "A") return;
      nav();
    });
    row.addEventListener("keydown", e => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); nav(); }
    });
  });
}

// ── Render pagination ─────────────────────────────────────────────────────────
function renderPagination(numPages, current) {
  if (!paginationEl) return;
  if (numPages <= 1) { paginationEl.innerHTML = ""; return; }

  const pages = [];
  for (let i = 1; i <= numPages; i++) {
    if (i === 1 || i === numPages || (i >= current - 2 && i <= current + 2)) {
      pages.push(i);
    } else if (pages[pages.length - 1] !== "…") {
      pages.push("…");
    }
  }

  paginationEl.innerHTML = pages.map(p => {
    if (p === "…") return `<span class="page-ellipsis">…</span>`;
    const active = p === current ? " page-active" : "";
    return `<button class="page-btn${active}" data-page="${p}" type="button">${p}</button>`;
  }).join("");

  paginationEl.querySelectorAll(".page-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const p = parseInt(btn.dataset.page, 10);
      if (p !== currentPage) loadPage(p);
    });
  });
}

// ── Data loading ──────────────────────────────────────────────────────────────
async function loadPage(page) {
  currentPage = page;
  setLoading(true);
  try {
    const offset = calcOffset(page, PAGE_LIMIT);
    const resp = await fetch(buildHistoryUrl(PAGE_LIMIT, offset), {
      headers: authHeaders(),
    });
    if (resp.status === 401) { clearToken(); window.location.href = "/index.html"; return; }
    if (!resp.ok) { showError(`Failed to load history (${resp.status})`); return; }
    const data = await resp.json();
    serverTotal = data.total;
    allItems    = data.items;

    const filtered = allItems.filter(i => matchesSeverityFilter(i, currentFilter));
    renderTable(filtered);

    const numPages = totalPages(data.total, PAGE_LIMIT);
    renderPagination(numPages, page);

    if (totalCountEl) totalCountEl.textContent = `${data.total} total`;
  } catch (err) {
    showError(`Network error: ${err.message}`);
  } finally {
    setLoading(false);
  }
}

// ── Filter change ─────────────────────────────────────────────────────────────
if (filterEl) {
  filterEl.addEventListener("change", () => {
    currentFilter = filterEl.value;
    const filtered = allItems.filter(i => matchesSeverityFilter(i, currentFilter));
    renderTable(filtered);
  });
}

// ── Init ──────────────────────────────────────────────────────────────────────
const startPage = getPageFromSearch(window.location.search);
loadPage(startPage);

} // end browser-only block
