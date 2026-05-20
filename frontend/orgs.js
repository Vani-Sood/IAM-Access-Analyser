"use strict";

// ── pure functions (exported for tests) ───────────────────────────────────────

const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const VALID_ROLES = new Set(["creator", "manager", "member"]);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const ROLE_RANK = { creator: 3, manager: 2, member: 1 };

function validateOrgName(name) {
  const trimmed = (name || "").trim();
  if (!trimmed) throw new Error("name must not be blank");
  return trimmed;
}

function validateSlug(slug) {
  if (!slug || !SLUG_RE.test(slug)) {
    throw new Error(
      "slug must be lowercase alphanumeric with optional hyphens (e.g. 'my-org')"
    );
  }
  return slug;
}

function validateRole(role) {
  if (!VALID_ROLES.has(role)) {
    throw new Error(`role must be one of: creator, manager, member`);
  }
  return role;
}

function validateEmail(email) {
  const trimmed = (email || "").trim();
  if (!EMAIL_RE.test(trimmed)) throw new Error("valid email required");
  return trimmed;
}

function buildMemberAddPayload(email, role) {
  return { email, role };
}

function getRoleRank(role) {
  return ROLE_RANK[role] || 0;
}

function canManageMembers(currentRole) {
  return getRoleRank(currentRole) >= 2;
}

function canRemoveMember(currentRole, targetRole, ownerCount) {
  if (getRoleRank(currentRole) < 3) return false;
  if (targetRole === "owner" && ownerCount <= 1) return false;
  return true;
}

// ── conditional export ────────────────────────────────────────────────────────
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    validateOrgName, validateSlug, validateRole, validateEmail,
    buildMemberAddPayload, getRoleRank, canManageMembers, canRemoveMember,
  };
}

// ── browser-only DOM logic (skipped in Node/Jest) ─────────────────────────────
if (typeof module === "undefined") {

const errorBanner    = document.getElementById("error-banner");
const errorMsg       = document.getElementById("error-message");
const orgListEl      = document.getElementById("org-list");
const orgEmptyEl     = document.getElementById("org-empty");
const orgDetailEl    = document.getElementById("org-detail");
const orgNameEl      = document.getElementById("detail-org-name");
const membersBodyEl  = document.getElementById("members-body");
const membersEmptyEl = document.getElementById("members-empty");
const addMemberForm  = document.getElementById("add-member-form");
const addEmailEl     = document.getElementById("add-email");
const addRoleEl      = document.getElementById("add-role");
const addBtnEl       = document.getElementById("add-member-btn");
const newOrgForm     = document.getElementById("new-org-form");
const newNameEl      = document.getElementById("new-org-name");
const newSlugEl      = document.getElementById("new-org-slug");
const newOrgBtnEl    = document.getElementById("create-org-btn");

let activeSlug = null;
let currentRole = "";

function showError(msg) {
  if (errorMsg)    errorMsg.textContent = msg;
  if (errorBanner) {
    errorBanner.classList.add("active");
    setTimeout(() => errorBanner.classList.remove("active"), 30000);
  }
}

function clearError() {
  if (errorBanner) errorBanner.classList.remove("active");
}

function escapeHtml(str) {
  if (typeof str !== "string") return String(str);
  return str
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ── Render org list ───────────────────────────────────────────────────────────
function renderOrgList(orgs) {
  if (!orgs.length) {
    if (orgListEl)  orgListEl.innerHTML = "";
    if (orgEmptyEl) orgEmptyEl.style.display = "";
    return;
  }
  if (orgEmptyEl) orgEmptyEl.style.display = "none";
  orgListEl.innerHTML = orgs.map(o => `
    <div class="org-item${o.slug === activeSlug ? " org-item-active" : ""}"
         data-slug="${o.slug}" role="button" tabindex="0">
      <div class="org-item-name">${escapeHtml(o.name)}</div>
      <div class="org-item-slug">${escapeHtml(o.slug)}</div>
    </div>`).join("");

  orgListEl.querySelectorAll(".org-item").forEach(el => {
    const handler = () => selectOrg(el.dataset.slug);
    el.addEventListener("click", handler);
    el.addEventListener("keydown", e => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); handler(); }
    });
  });
}

// ── Render members table ──────────────────────────────────────────────────────
function renderMembers(members) {
  if (!members.length) {
    if (membersBodyEl)  membersBodyEl.innerHTML = "";
    if (membersEmptyEl) membersEmptyEl.style.display = "";
    return;
  }
  if (membersEmptyEl) membersEmptyEl.style.display = "none";
  const ownerCount = members.filter(m => m.role === "owner").length;
  const canAdmin = canManageMembers(currentRole);

  membersBodyEl.innerHTML = members.map(m => {
    const removeAllowed = canRemoveMember(currentRole, m.role, ownerCount);
    return `
    <tr>
      <td>${escapeHtml(m.email)}</td>
      <td>
        ${canAdmin && m.role !== "owner" ? `
          <select class="role-select history-filter-select" data-user-id="${m.id}"
                  style="font-size:13px;height:30px">
            ${(currentRole === "creator" ? ["manager","member"] : ["member"]).map(r =>
              `<option value="${r}"${r === m.role ? " selected" : ""}>${r}</option>`
            ).join("")}
          </select>` : `<span class="finding-badge">${escapeHtml(m.role)}</span>`
        }
      </td>
      <td>
        ${removeAllowed ? `
          <button class="btn-secondary remove-member-btn" data-user-id="${m.id}"
                  style="font-size:13px;padding:4px 10px;color:var(--color-error)">
            Remove
          </button>` : ""}
      </td>
    </tr>`;
  }).join("");

  membersBodyEl.querySelectorAll(".role-select").forEach(sel => {
    sel.addEventListener("change", async () => {
      const userId = sel.dataset.userId;
      const newRole = sel.value;
      await changeMemberRole(activeSlug, userId, newRole);
    });
  });

  membersBodyEl.querySelectorAll(".remove-member-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const userId = btn.dataset.userId;
      if (!confirm("Remove this member?")) return;
      await removeMember(activeSlug, userId);
    });
  });
}

// ── API actions ───────────────────────────────────────────────────────────────
async function selectOrg(slug) {
  activeSlug = slug;
  if (orgNameEl) orgNameEl.textContent = slug;
  if (orgDetailEl) orgDetailEl.style.display = "";

  try {
    const resp = await fetch(`/api/v1/orgs/${slug}/members`, {
      headers: authHeaders(),
    });
    if (resp.status === 401) { clearToken(); window.location.href = "/index.html"; return; }
    if (!resp.ok) { showError(`Failed to load members (${resp.status})`); return; }
    const data = await resp.json();

    const payload = getUserPayload();
    const myEmail = payload?.sub || payload?.email || "";
    const me = data.members.find(m => m.email === myEmail);
    currentRole = me ? me.role : "member";

    renderMembers(data.members);

    if (addMemberForm) {
      addMemberForm.style.display = canManageMembers(currentRole) ? "" : "none";
      const managerOpt = document.getElementById("role-manager-opt");
      if (managerOpt) managerOpt.style.display = currentRole === "creator" ? "" : "none";
    }
  } catch (err) {
    showError(`Network error: ${err.message}`);
  }

  document.querySelectorAll(".org-item").forEach(el => {
    el.classList.toggle("org-item-active", el.dataset.slug === slug);
  });
}

async function removeMember(slug, userId) {
  try {
    const resp = await fetch(`/api/v1/orgs/${slug}/members/${userId}`, {
      method: "DELETE", headers: authHeaders(),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      showError(`Remove failed: ${err.detail}`);
      return;
    }
    clearError();
    await selectOrg(slug);
  } catch (err) {
    showError(`Network error: ${err.message}`);
  }
}

async function changeMemberRole(slug, userId, role) {
  try {
    const resp = await fetch(`/api/v1/orgs/${slug}/members/${userId}/role`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ role }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      showError(`Role change failed: ${err.detail}`);
      return;
    }
    clearError();
    await selectOrg(slug);
  } catch (err) {
    showError(`Network error: ${err.message}`);
  }
}

// ── Add member form ───────────────────────────────────────────────────────────
if (addMemberForm) {
  addMemberForm.addEventListener("submit", async e => {
    e.preventDefault();
    clearError();
    let email, role;
    try {
      email = validateEmail(addEmailEl.value);
      role  = validateRole(addRoleEl.value);
    } catch (err) {
      showError(err.message);
      return;
    }
    if (addBtnEl) addBtnEl.disabled = true;
    try {
      const resp = await fetch(`/api/v1/orgs/${activeSlug}/members`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(buildMemberAddPayload(email, role)),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        showError(`Add member failed: ${err.detail}`);
        return;
      }
      addEmailEl.value = "";
      await selectOrg(activeSlug);
    } catch (err) {
      showError(`Network error: ${err.message}`);
    } finally {
      if (addBtnEl) addBtnEl.disabled = false;
    }
  });
}

// ── Create org form ───────────────────────────────────────────────────────────
if (newOrgForm) {
  newOrgForm.addEventListener("submit", async e => {
    e.preventDefault();
    clearError();
    let name, slug;
    try {
      name = validateOrgName(newNameEl.value);
      slug = validateSlug(newSlugEl.value);
    } catch (err) {
      showError(err.message);
      return;
    }
    if (newOrgBtnEl) newOrgBtnEl.disabled = true;
    try {
      const resp = await fetch("/api/v1/orgs", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ name, slug }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        showError(`Create org failed: ${err.detail}`);
        return;
      }
      newNameEl.value = "";
      newSlugEl.value = "";
      await loadOrgs();
    } catch (err) {
      showError(`Network error: ${err.message}`);
    } finally {
      if (newOrgBtnEl) newOrgBtnEl.disabled = false;
    }
  });
}

// ── Slug auto-fill from name ──────────────────────────────────────────────────
if (newNameEl && newSlugEl) {
  newNameEl.addEventListener("input", () => {
    if (!newSlugEl.dataset.dirty) {
      newSlugEl.value = newNameEl.value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "");
    }
  });
  newSlugEl.addEventListener("input", () => {
    newSlugEl.dataset.dirty = "1";
  });
}

// ── Load org list ─────────────────────────────────────────────────────────────
async function loadOrgs() {
  try {
    const resp = await fetch("/api/v1/orgs", { headers: authHeaders() });
    if (resp.status === 401) { clearToken(); window.location.href = "/index.html"; return; }
    if (!resp.ok) { showError(`Failed to load orgs (${resp.status})`); return; }
    const data = await resp.json();
    renderOrgList(data.items);
    if (data.items.length && !activeSlug) {
      await selectOrg(data.items[0].slug);
    }
  } catch (err) {
    showError(`Network error: ${err.message}`);
  }
}

loadOrgs();

} // end browser-only block
