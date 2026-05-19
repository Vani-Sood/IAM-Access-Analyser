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
  if (errorBanner) errorBanner.classList.add("active");
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
loadUsers();

} // end browser-only block

// ── User management (runs in browser only) ────────────────────────────────────
if (typeof window !== "undefined") {

const createUserForm    = document.getElementById("create-user-form");
const createUserErrBanner = document.getElementById("create-user-error");
const createUserErrMsg  = document.getElementById("create-user-error-msg");
const createUserSuccess = document.getElementById("create-user-success");
const createUserBtn     = document.getElementById("create-user-btn");

if (createUserForm) {
  createUserForm.addEventListener("submit", async e => {
    e.preventDefault();
    if (createUserErrBanner) createUserErrBanner.classList.remove("active");
    if (createUserSuccess)   createUserSuccess.style.display = "none";
    const email    = document.getElementById("new-user-email").value.trim();
    const password = document.getElementById("new-user-password").value;
    const isAdmin  = document.getElementById("new-user-is-admin").checked;
    if (createUserBtn) createUserBtn.disabled = true;
    try {
      const resp = await fetch("/api/v1/admin/users", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ email, password, is_admin: isAdmin }),
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        if (createUserErrMsg) createUserErrMsg.textContent = data.detail || `Failed (${resp.status})`;
        if (createUserErrBanner) createUserErrBanner.classList.add("active");
        return;
      }
      document.getElementById("new-user-email").value = "";
      document.getElementById("new-user-password").value = "";
      document.getElementById("new-user-is-admin").checked = false;
      if (createUserSuccess) {
        createUserSuccess.textContent = `User ${data.email} created. They must change password on first login.`;
        createUserSuccess.style.display = "";
      }
      await loadUsers();
    } catch (err) {
      if (createUserErrMsg) createUserErrMsg.textContent = `Network error: ${err.message}`;
      if (createUserErrBanner) createUserErrBanner.classList.add("active");
    } finally {
      if (createUserBtn) createUserBtn.disabled = false;
    }
  });
}

async function loadUsers() {
  try {
    const resp = await fetch("/api/v1/admin/users", { headers: authHeaders() });
    if (!resp.ok) return;
    const data = await resp.json();
    renderPendingUsers(data.items.filter(u => !u.is_active));
    renderAllUsers(data.items);
  } catch (_) {}
}

function renderPendingUsers(users) {
  const tbody   = document.getElementById("pending-body");
  const empty   = document.getElementById("pending-empty");
  const table   = document.getElementById("pending-table");
  if (!tbody) return;
  if (!users.length) {
    if (empty) empty.style.display = "";
    if (table) table.style.display = "none";
    return;
  }
  if (empty) empty.style.display = "none";
  if (table) table.style.display = "";
  tbody.innerHTML = users.map(u => `
    <tr>
      <td style="font-weight:600">${escapeHtml(u.email)}</td>
      <td style="font-size:13px;color:var(--color-muted)">${new Date(u.created_at).toLocaleString()}</td>
      <td>
        <button class="btn-primary approve-btn" data-user-id="${u.id}"
                style="font-size:13px;padding:4px 12px">
          Approve
        </button>
      </td>
    </tr>`).join("");
  tbody.querySelectorAll(".approve-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.textContent = "Approving…";
      try {
        const resp = await fetch(`/api/v1/admin/users/${btn.dataset.userId}/activate`, {
          method: "POST", headers: authHeaders(),
        });
        if (!resp.ok) { btn.disabled = false; btn.textContent = "Approve"; return; }
        await loadUsers();
      } catch (_) { btn.disabled = false; btn.textContent = "Approve"; }
    });
  });
}

function renderAllUsers(users) {
  const tbody = document.getElementById("users-body");
  if (!tbody) return;
  tbody.innerHTML = users.map(u => `
    <tr>
      <td>${escapeHtml(u.email)}</td>
      <td><span class="finding-badge" style="background:${u.is_active ? "var(--color-ok,#22c55e)" : "var(--color-error,#ef4444)"}20;
               color:${u.is_active ? "var(--color-ok,#16a34a)" : "var(--color-error,#dc2626)"}">
        ${u.is_active ? "Active" : "Pending"}
      </span></td>
      <td><span class="finding-badge">${u.is_admin ? "Admin" : "User"}</span></td>
      <td style="font-size:13px;color:var(--color-muted)">${new Date(u.created_at).toLocaleString()}</td>
      <td>
        ${u.is_active
          ? `<button class="btn-secondary deactivate-btn" data-user-id="${u.id}"
                     style="font-size:13px;padding:4px 10px;color:var(--color-error)">
               Deactivate
             </button>`
          : `<button class="btn-primary approve-btn2" data-user-id="${u.id}"
                     style="font-size:13px;padding:4px 12px">
               Approve
             </button>`
        }
      </td>
    </tr>`).join("");

  tbody.querySelectorAll(".approve-btn2").forEach(btn => {
    btn.addEventListener("click", async () => {
      await fetch(`/api/v1/admin/users/${btn.dataset.userId}/activate`,
        { method: "POST", headers: authHeaders() });
      await loadUsers();
    });
  });
  tbody.querySelectorAll(".deactivate-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      if (!confirm("Deactivate this user? They won't be able to log in.")) return;
      await fetch(`/api/v1/admin/users/${btn.dataset.userId}`,
        { method: "DELETE", headers: authHeaders() });
      await loadUsers();
    });
  });
}

}
