"use strict";

// ── pure functions (exported for tests) ───────────────────────────────────────

function buildAuditUrl(limit, offset, eventType) {
  let url = `/api/v1/admin/audit-log?limit=${limit}&offset=${offset}`;
  if (eventType) url += `&event_type=${encodeURIComponent(eventType)}`;
  return url;
}

function formatPayload(payload) {
  return JSON.stringify(payload);
}

function truncateAuditHash(hash) {
  if (!hash) return "";
  if (hash.length <= 12) return hash;
  return hash.slice(0, 12) + "…";
}

function auditTotalPages(total, limit) {
  if (total === 0) return 0;
  return Math.ceil(total / limit);
}

function auditCalcOffset(page, limit) {
  return (page - 1) * limit;
}

function auditGetPage(search) {
  if (!search) return 1;
  const params = new URLSearchParams(search);
  const raw = params.get("page");
  if (!raw) return 1;
  const num = parseInt(raw, 10);
  return Number.isFinite(num) && num > 0 ? num : 1;
}

// ── conditional export ────────────────────────────────────────────────────────
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    buildAuditUrl, formatPayload, truncateAuditHash,
    auditTotalPages, auditCalcOffset, auditGetPage,
  };
}

// ── browser-only DOM logic (skipped in Node/Jest) ─────────────────────────────
if (typeof module === "undefined") {

const PAGE_LIMIT = 50;

const errorBanner   = document.getElementById("error-banner");
const errorMsg      = document.getElementById("error-message");
const loadingEl     = document.getElementById("page-loading");
const tableBody     = document.getElementById("audit-body");
const emptyState    = document.getElementById("audit-empty");
const paginationEl  = document.getElementById("pagination");
const totalCountEl  = document.getElementById("total-count");
const filterEl      = document.getElementById("event-type-filter");
const exportBtn     = document.getElementById("export-btn");

let currentPage   = 1;
let currentFilter = "";

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

function escapeHtml(str) {
  if (typeof str !== "string") return String(str);
  return str
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function formatDate(isoStr) {
  const d = new Date(isoStr);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) +
         " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// ── Render audit table ────────────────────────────────────────────────────────
function renderAuditLog(entries) {
  if (!entries.length) {
    if (tableBody)  tableBody.innerHTML = "";
    if (emptyState) emptyState.style.display = "";
    return;
  }
  if (emptyState) emptyState.style.display = "none";

  tableBody.innerHTML = entries.map(e => `
    <tr>
      <td style="font-size:13px;color:var(--color-muted);white-space:nowrap">
        ${formatDate(e.timestamp)}
      </td>
      <td>
        <code style="font-size:12px;background:var(--color-surface-soft);
                     padding:2px 6px;border-radius:4px">
          ${escapeHtml(e.event_type)}
        </code>
      </td>
      <td style="font-size:13px">
        ${escapeHtml(e.actor_email || `#${e.actor_id}` || "system")}
      </td>
      <td style="font-size:12px;font-family:monospace;max-width:300px;
                 overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${escapeHtml(formatPayload(e.payload))}">
        ${escapeHtml(formatPayload(e.payload))}
      </td>
      <td style="font-family:monospace;font-size:11px;color:var(--color-muted)"
          title="${escapeHtml(e.entry_hash)}">
        ${truncateAuditHash(e.entry_hash)}
      </td>
    </tr>`).join("");
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

// ── Load page ─────────────────────────────────────────────────────────────────
async function loadPage(page) {
  currentPage = page;
  setLoading(true);
  try {
    const offset = auditCalcOffset(page, PAGE_LIMIT);
    const resp = await fetch(
      buildAuditUrl(PAGE_LIMIT, offset, currentFilter || null),
      { headers: authHeaders() }
    );
    if (resp.status === 401) { clearToken(); window.location.href = "/index.html"; return; }
    if (resp.status === 403) {
      showError("Admin access required.");
      setLoading(false);
      return;
    }
    if (!resp.ok) { showError(`Failed to load audit log (${resp.status})`); return; }

    const data = await resp.json();
    renderAuditLog(data.items);
    renderPagination(auditTotalPages(data.total, PAGE_LIMIT), page);
    if (totalCountEl) totalCountEl.textContent = `${data.total} entries`;
  } catch (err) {
    showError(`Network error: ${err.message}`);
  } finally {
    setLoading(false);
  }
}

// ── Event type filter ─────────────────────────────────────────────────────────
if (filterEl) {
  filterEl.addEventListener("change", () => {
    currentFilter = filterEl.value;
    loadPage(1);
  });
}

// ── Export button ─────────────────────────────────────────────────────────────
if (exportBtn) {
  exportBtn.addEventListener("click", async () => {
    exportBtn.disabled = true;
    exportBtn.textContent = "Exporting…";
    try {
      const resp = await fetch("/api/v1/admin/audit-log/export", { headers: authHeaders() });
      if (!resp.ok) { showError(`Export failed (${resp.status})`); return; }
      const blob = await resp.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      const cd   = resp.headers.get("Content-Disposition") || "";
      const match = cd.match(/filename="([^"]+)"/);
      a.href     = url;
      a.download = match ? match[1] : "audit_log.json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      showError(`Export error: ${err.message}`);
    } finally {
      exportBtn.disabled = false;
      exportBtn.textContent = "Export JSON";
    }
  });
}

// ── Init ──────────────────────────────────────────────────────────────────────
const startPage = auditGetPage(window.location.search);
loadPage(startPage);

} // end browser-only block
