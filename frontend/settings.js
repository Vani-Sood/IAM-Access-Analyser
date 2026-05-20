"use strict";

// ── pure functions (exported for tests) ───────────────────────────────────────

const VALID_SCOPES  = new Set(["read", "readwrite", "admin"]);
const VALID_EVENTS  = new Set(["analysis.complete", "privesc.detected", "compliance.failed"]);

function validateApiKeyName(name) {
  const trimmed = (name || "").trim();
  if (!trimmed) throw new Error("name must not be blank");
  return trimmed;
}

function validateApiKeyScope(scope) {
  if (!VALID_SCOPES.has(scope)) {
    throw new Error("scope must be one of: read, readwrite, admin");
  }
  return scope;
}

function validateWebhookUrl(url) {
  const trimmed = (url || "").trim();
  if (!trimmed.startsWith("https://")) {
    throw new Error("Webhook URL must use HTTPS (e.g. https://example.com/hook)");
  }
  return trimmed;
}

function validateWebhookEvents(events) {
  if (!events || events.length === 0) {
    throw new Error("At least one event is required");
  }
  const invalid = events.filter(e => !VALID_EVENTS.has(e));
  if (invalid.length) {
    throw new Error(`Invalid event(s): ${invalid.join(", ")}`);
  }
  return events;
}

function validateNewPassword(password) {
  const p = password || "";
  if (p.length < 8) throw new Error("Password must be at least 8 characters");
  if (!/[A-Z]/.test(p)) throw new Error("Password must contain at least one uppercase letter");
  if (!/[0-9]/.test(p)) throw new Error("Password must contain at least one digit");
  return p;
}

function validatePasswordMatch(password, confirm) {
  if (password !== confirm) throw new Error("Passwords do not match");
  return password;
}

function buildApiKeyPayload(name, scope, expiresInDays) {
  const payload = { name, scope };
  if (expiresInDays) payload.expires_in_days = expiresInDays;
  return payload;
}

function buildWebhookPayload(url, events) {
  return { url, events };
}

function maskKey(prefix) {
  return `${prefix}••••••••`;
}

// ── conditional export ────────────────────────────────────────────────────────
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    validateApiKeyName, validateApiKeyScope,
    validateWebhookUrl, validateWebhookEvents,
    validateNewPassword, validatePasswordMatch,
    buildApiKeyPayload, buildWebhookPayload, maskKey,
  };
}

// ── browser-only DOM logic (skipped in Node/Jest) ─────────────────────────────
if (typeof module === "undefined") {

const errorBanner    = document.getElementById("error-banner");
const errorMsg       = document.getElementById("error-message");
const successBanner  = document.getElementById("success-banner");
const successMsg     = document.getElementById("success-message");

function showError(msg) {
  if (errorMsg)    errorMsg.textContent = msg;
  if (successBanner) successBanner.classList.remove("active");
  if (errorBanner) {
    errorBanner.classList.add("active");
    setTimeout(() => errorBanner.classList.remove("active"), 30000);
  }
}

function showSuccess(msg) {
  if (successMsg)    successMsg.textContent = msg;
  if (errorBanner)   errorBanner.classList.remove("active");
  if (successBanner) {
    successBanner.classList.add("active");
    setTimeout(() => successBanner.classList.remove("active"), 30000);
  }
}

function clearMessages() {
  if (errorBanner)   errorBanner.classList.remove("active");
  if (successBanner) successBanner.classList.remove("active");
}

function escapeHtml(str) {
  if (typeof str !== "string") return String(str);
  return str
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function formatDate(isoStr) {
  if (!isoStr) return "—";
  const d = new Date(isoStr);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

// ── API Keys section ──────────────────────────────────────────────────────────
const apiKeysBody    = document.getElementById("apikeys-body");
const apiKeysEmpty   = document.getElementById("apikeys-empty");
const newKeyForm     = document.getElementById("new-apikey-form");
const newKeyName     = document.getElementById("new-key-name");
const newKeyScope    = document.getElementById("new-key-scope");
const newKeyExpires  = document.getElementById("new-key-expires");
const newKeyBtn      = document.getElementById("create-key-btn");
const newKeyResult   = document.getElementById("new-key-result");
const newKeyValue    = document.getElementById("new-key-value");
const copyKeyBtn     = document.getElementById("copy-key-btn");

function renderApiKeys(keys) {
  if (!keys.length) {
    if (apiKeysBody)  apiKeysBody.innerHTML = "";
    if (apiKeysEmpty) apiKeysEmpty.style.display = "";
    return;
  }
  if (apiKeysEmpty) apiKeysEmpty.style.display = "none";
  const now = Date.now();
  apiKeysBody.innerHTML = keys.map(k => {
    const expired = k.expires_at && new Date(k.expires_at).getTime() < now;
    const expiryLabel = k.expires_at
      ? (expired
          ? `<span style="color:var(--color-error);font-size:12px">Expired ${formatDate(k.expires_at)}</span>`
          : `<span style="font-size:12px;color:var(--color-muted)">${formatDate(k.expires_at)}</span>`)
      : `<span style="font-size:12px;color:var(--color-muted)">Never</span>`;
    return `
    <tr>
      <td style="font-weight:600">${escapeHtml(k.name)}</td>
      <td style="font-family:monospace;font-size:13px">${escapeHtml(maskKey(k.prefix))}</td>
      <td><span class="finding-badge">${escapeHtml(k.scope)}</span></td>
      <td style="font-size:13px;color:var(--color-muted)">${formatDate(k.created_at)}</td>
      <td style="font-size:13px;color:var(--color-muted)">${k.last_used_at ? formatDate(k.last_used_at) : "Never"}</td>
      <td>${expiryLabel}</td>
      <td>
        ${k.is_active && !expired
          ? `<button class="btn-secondary revoke-key-btn" data-key-id="${k.id}"
                style="font-size:13px;padding:4px 10px;color:var(--color-error)">
              Revoke
             </button>`
          : `<span style="font-size:12px;color:var(--color-muted);font-style:italic">${expired ? "Expired" : "Revoked"}</span>`
        }
      </td>
    </tr>`;
  }).join("");

  apiKeysBody.querySelectorAll(".revoke-key-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      if (!confirm("Revoke this API key? Apps using it will stop working.")) return;
      await revokeApiKey(parseInt(btn.dataset.keyId, 10));
    });
  });
}

async function loadApiKeys() {
  try {
    const resp = await fetch("/api/v1/apikeys", { headers: authHeaders() });
    if (!resp.ok) return;
    const data = await resp.json();
    renderApiKeys(data.items);
  } catch { /* non-critical */ }
}

async function revokeApiKey(id) {
  try {
    const resp = await fetch(`/api/v1/apikeys/${id}`, {
      method: "DELETE", headers: authHeaders(),
    });
    if (!resp.ok) { showError(`Revoke failed (${resp.status})`); return; }
    showSuccess("API key revoked.");
    await loadApiKeys();
  } catch (err) { showError(`Network error: ${err.message}`); }
}

if (newKeyForm) {
  newKeyForm.addEventListener("submit", async e => {
    e.preventDefault();
    clearMessages();
    let name, scope;
    try {
      name  = validateApiKeyName(newKeyName.value);
      scope = validateApiKeyScope(newKeyScope.value);
    } catch (err) { showError(err.message); return; }
    const expiresInDays = newKeyExpires && newKeyExpires.value
      ? parseInt(newKeyExpires.value, 10) : null;
    if (newKeyBtn) newKeyBtn.disabled = true;
    try {
      const resp = await fetch("/api/v1/apikeys", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(buildApiKeyPayload(name, scope, expiresInDays)),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        showError(`Create failed: ${err.detail}`);
        return;
      }
      const created = await resp.json();
      if (newKeyResult) newKeyResult.style.display = "";
      if (newKeyValue)  newKeyValue.value = created.key;
      newKeyName.value = "";
      if (newKeyExpires) newKeyExpires.value = "";
      await loadApiKeys();
      showSuccess("API key created. Copy it now — it won't be shown again.");
    } catch (err) { showError(`Network error: ${err.message}`);
    } finally { if (newKeyBtn) newKeyBtn.disabled = false; }
  });
}

if (copyKeyBtn && newKeyValue) {
  copyKeyBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(newKeyValue.value).catch(() => {});
    copyKeyBtn.textContent = "Copied!";
    setTimeout(() => { copyKeyBtn.textContent = "Copy"; }, 2000);
  });
}

// ── Webhooks section ──────────────────────────────────────────────────────────
const webhooksBody  = document.getElementById("webhooks-body");
const webhooksEmpty = document.getElementById("webhooks-empty");
const newHookForm   = document.getElementById("new-webhook-form");
const newHookUrl    = document.getElementById("new-hook-url");
const newHookBtn    = document.getElementById("create-hook-btn");

function getSelectedEvents() {
  return Array.from(
    document.querySelectorAll(".hook-event-cb:checked")
  ).map(cb => cb.value);
}

function renderWebhooks(hooks) {
  if (!hooks.length) {
    if (webhooksBody)  webhooksBody.innerHTML = "";
    if (webhooksEmpty) webhooksEmpty.style.display = "";
    return;
  }
  if (webhooksEmpty) webhooksEmpty.style.display = "none";
  webhooksBody.innerHTML = hooks.map(h => `
    <tr>
      <td style="font-family:monospace;font-size:13px;word-break:break-all">
        ${escapeHtml(h.url)}
      </td>
      <td style="font-size:13px">${h.events.map(e => escapeHtml(e)).join(", ")}</td>
      <td><span class="finding-badge ${h.is_active ? "badge-low" : ""}">
        ${h.is_active ? "Active" : "Disabled"}
      </span></td>
      <td style="font-size:13px;color:var(--color-muted)">${h.failure_count}</td>
      <td style="display:flex;gap:6px;padding:10px 12px">
        <button class="btn-secondary test-hook-btn" data-hook-id="${h.id}"
                style="font-size:13px;padding:4px 10px">Test</button>
        <button class="btn-secondary delete-hook-btn" data-hook-id="${h.id}"
                style="font-size:13px;padding:4px 10px;color:var(--color-error)">Delete</button>
      </td>
    </tr>`).join("");

  webhooksBody.querySelectorAll(".delete-hook-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      if (!confirm("Delete this webhook?")) return;
      await deleteWebhook(parseInt(btn.dataset.hookId, 10));
    });
  });

  webhooksBody.querySelectorAll(".test-hook-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      await testWebhook(parseInt(btn.dataset.hookId, 10));
    });
  });
}

async function loadWebhooks() {
  try {
    const resp = await fetch("/api/v1/webhooks", { headers: authHeaders() });
    if (!resp.ok) return;
    const data = await resp.json();
    renderWebhooks(data.items);
  } catch { /* non-critical */ }
}

async function deleteWebhook(id) {
  try {
    const resp = await fetch(`/api/v1/webhooks/${id}`, {
      method: "DELETE", headers: authHeaders(),
    });
    if (!resp.ok) { showError(`Delete failed (${resp.status})`); return; }
    showSuccess("Webhook deleted.");
    await loadWebhooks();
  } catch (err) { showError(`Network error: ${err.message}`); }
}

async function testWebhook(id) {
  try {
    const resp = await fetch(`/api/v1/webhooks/${id}/test`, {
      method: "POST", headers: authHeaders(),
    });
    if (!resp.ok) { showError(`Test failed (${resp.status})`); return; }
    showSuccess("Test event queued.");
  } catch (err) { showError(`Network error: ${err.message}`); }
}

if (newHookForm) {
  newHookForm.addEventListener("submit", async e => {
    e.preventDefault();
    clearMessages();
    let url, events;
    try {
      url    = validateWebhookUrl(newHookUrl.value);
      events = validateWebhookEvents(getSelectedEvents());
    } catch (err) { showError(err.message); return; }
    if (newHookBtn) newHookBtn.disabled = true;
    try {
      const resp = await fetch("/api/v1/webhooks", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(buildWebhookPayload(url, events)),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        showError(`Create failed: ${err.detail}`);
        return;
      }
      newHookUrl.value = "";
      document.querySelectorAll(".hook-event-cb").forEach(cb => { cb.checked = false; });
      await loadWebhooks();
      showSuccess("Webhook registered.");
    } catch (err) { showError(`Network error: ${err.message}`);
    } finally { if (newHookBtn) newHookBtn.disabled = false; }
  });
}

// ── Password change section ───────────────────────────────────────────────────
const pwForm         = document.getElementById("password-form");
const currentPwEl    = document.getElementById("current-password");
const newPwEl        = document.getElementById("new-password");
const confirmPwEl    = document.getElementById("confirm-password");
const changePwBtn    = document.getElementById("change-password-btn");

if (pwForm) {
  pwForm.addEventListener("submit", async e => {
    e.preventDefault();
    clearMessages();
    let newPw;
    try {
      newPw = validateNewPassword(newPwEl.value);
      validatePasswordMatch(newPw, confirmPwEl.value);
    } catch (err) { showError(err.message); return; }
    if (changePwBtn) changePwBtn.disabled = true;
    try {
      const resp = await fetch("/api/v1/auth/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({
          current_password: currentPwEl.value,
          new_password: newPw,
        }),
      });
      if (resp.status === 401) { clearToken(); window.location.href = "/index.html"; return; }
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        showError(`Password change failed: ${err.detail}`);
        return;
      }
      currentPwEl.value = "";
      newPwEl.value     = "";
      confirmPwEl.value = "";
      showSuccess("Password changed successfully.");
    } catch (err) { showError(`Network error: ${err.message}`);
    } finally { if (changePwBtn) changePwBtn.disabled = false; }
  });
}

// ── Init ──────────────────────────────────────────────────────────────────────
(async () => {
  await Promise.all([loadApiKeys(), loadWebhooks()]);
})();

} // end browser-only block
