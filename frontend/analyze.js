"use strict";

// ── pure functions (exported for tests) ───────────────────────────────────────

function validateJson(text) {
  const trimmed = (text || "").trim();
  if (!trimmed) throw new Error("Policy JSON is required");
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error("Invalid JSON — please check your policy and try again");
  }
  if (
    parsed &&
    typeof parsed === "object" &&
    "policy" in parsed &&
    !("Statement" in parsed) &&
    !("Version" in parsed)
  ) {
    return parsed.policy;
  }
  return parsed;
}

function buildJsonPayload(policy, cloud) {
  return { mode: "json", cloud, policy };
}

const AWS_ROLE_ARN_RE =
  /^arn:aws:iam::\d{12}:role\/[\w+=,.@/-]{1,512}$/;

function validateRoleArn(arn) {
  const trimmed = (arn || "").trim();
  if (!trimmed) return null;
  if (!AWS_ROLE_ARN_RE.test(trimmed)) {
    throw new Error(
      "Invalid Role ARN — expected arn:aws:iam::<account_id>:role/<name> " +
        "(or leave blank for single-account direct scan)"
    );
  }
  return trimmed;
}

function buildLivePayload(cloud, roleArn) {
  const payload = { mode: "live", cloud };
  if (cloud === "aws") {
    const arn = validateRoleArn(roleArn);
    if (arn) payload.role_arn = arn;
  }
  return payload;
}

function getActiveTab(hash) {
  const VALID = ["json", "live"];
  const tab = ((hash || "").replace("#", ""));
  return VALID.includes(tab) ? tab : "json";
}

// ── conditional export ────────────────────────────────────────────────────────
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    validateJson,
    buildJsonPayload,
    buildLivePayload,
    validateRoleArn,
    getActiveTab,
  };
}

// ── browser-only DOM logic (skipped in Node/Jest) ─────────────────────────────
if (typeof module === "undefined") {

const cloudSelectEl    = document.getElementById("cloud-select");
const analyzeBtn       = document.getElementById("analyze-btn");
const liveScanBtn      = document.getElementById("live-scan-btn");
const clearBtn         = document.getElementById("clear-btn");
const textarea         = document.getElementById("policy-input");
const fileInput        = document.getElementById("file-input");
const dropZone         = document.getElementById("drop-zone");
const loadingEl        = document.getElementById("loading");
const errorBanner      = document.getElementById("error-banner");
const errorMsg         = document.getElementById("error-message");
const tabBtns          = document.querySelectorAll(".tab-btn");
const tabPanels        = document.querySelectorAll(".tab-panel");

function setLoading(active) {
  if (analyzeBtn) analyzeBtn.disabled = active;
  if (liveScanBtn) liveScanBtn.disabled = active;
  if (loadingEl) loadingEl.classList.toggle("active", active);
}

function showError(msg) {
  if (errorMsg) errorMsg.textContent = msg;
  if (errorBanner) {
    errorBanner.classList.add("active");
    setTimeout(() => errorBanner.classList.remove("active"), 30000);
  }
}

function clearError() {
  if (errorBanner) errorBanner.classList.remove("active");
}

function switchTab(tab) {
  tabBtns.forEach(btn => btn.classList.toggle("tab-active", btn.dataset.tab === tab));
  tabPanels.forEach(panel => panel.classList.toggle("hidden", panel.dataset.panel !== tab));
  window.location.hash = tab;
}

async function pollStatus(analysisId, intervalMs = 2000, maxAttempts = 240) {
  // Total budget ≈ 0.5s + 9*2s + 231*3s = ~12min.
  // Live AWS/GCP scans can take 5+ min on accounts with many IAM entities.
  for (let i = 0; i < maxAttempts; i++) {
    const delay = i === 0 ? 500 : (i < 10 ? intervalMs : intervalMs + 1000);
    await new Promise(r => setTimeout(r, delay));
    try {
      const resp = await fetch(`/api/v1/analyses/${analysisId}/status`, {
        headers: authHeaders(),
      });
      if (!resp.ok) {
        showError(`Status check failed (${resp.status})`);
        setLoading(false);
        return null;
      }
      const data = await resp.json();
      if (data.status === "completed") return analysisId;
      if (data.status === "failed") {
        showError("Analysis failed in worker. Please try again.");
        setLoading(false);
        return null;
      }
    } catch (err) {
      showError(`Network error: ${err.message}`);
      setLoading(false);
      return null;
    }
  }
  showError("Analysis timed out. Please try again.");
  setLoading(false);
  return null;
}

async function submitPayload(payload) {
  clearError();
  setLoading(true);
  try {
    const resp = await fetch("/api/v1/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (resp.status === 401) { clearToken(); window.location.href = "/index.html"; return; }
    if (resp.status === 429) { showError("Rate limit exceeded. Please wait."); setLoading(false); return; }
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      showError(`Analysis failed (${resp.status}): ${JSON.stringify(err.detail)}`);
      setLoading(false);
      return;
    }
    const queued = await resp.json();
    const id = await pollStatus(queued.id);
    if (id) window.location.href = `/analysis.html?id=${id}`;
  } catch (err) {
    showError(`Network error: ${err.message}`);
    setLoading(false);
  }
}

// ── tab switching ─────────────────────────────────────────────────────────────
tabBtns.forEach(btn => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

// initialise tab from hash
switchTab(getActiveTab(window.location.hash));

// ── JSON tab form ─────────────────────────────────────────────────────────────
const form = document.getElementById("policy-form");
if (form) {
  form.addEventListener("submit", e => {
    e.preventDefault();
    let parsed;
    try {
      parsed = validateJson(textarea.value);
    } catch (err) {
      showError(err.message);
      return;
    }
    submitPayload(buildJsonPayload(parsed, cloudSelectEl.value));
  });
}

if (clearBtn) {
  clearBtn.addEventListener("click", () => {
    if (textarea) textarea.value = "";
    clearError();
  });
}

// ── Live scan form ────────────────────────────────────────────────────────────
// Single-account direct mode only. Multi-account (sts:AssumeRole) ARN input
// is hidden in analyze.html; re-enable both the markup block and the
// roleArn read below to restore cross-account scans.
const liveCloudSelect = document.getElementById("live-cloud-select");
if (liveScanBtn) {
  liveScanBtn.addEventListener("click", () => {
    const cloud = liveCloudSelect ? liveCloudSelect.value : "aws";
    try {
      submitPayload(buildLivePayload(cloud));
    } catch (err) {
      showError(err.message);
    }
  });
}

// ── drag and drop ─────────────────────────────────────────────────────────────
if (dropZone) {
  dropZone.addEventListener("click", () => fileInput && fileInput.click());
  dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("drag-over"); });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
  dropZone.addEventListener("drop", e => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const r = new FileReader();
    r.onload = ev => { if (textarea) textarea.value = ev.target.result; };
    r.readAsText(file);
  });
}

if (fileInput) {
  fileInput.addEventListener("change", e => {
    const file = e.target.files[0];
    if (!file) return;
    const r = new FileReader();
    r.onload = ev => { if (textarea) textarea.value = ev.target.result; };
    r.readAsText(file);
  });
}
} // end browser-only block
