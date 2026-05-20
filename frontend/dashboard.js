"use strict";

// ── DOM refs ─────────────────────────────────────────────────────────────────
const form              = document.getElementById("policy-form");
const textarea          = document.getElementById("policy-input");
const analyzeBtn        = document.getElementById("analyze-btn");
const clearBtn          = document.getElementById("clear-btn");
const fileInput         = document.getElementById("file-input");
const dropZone          = document.getElementById("drop-zone");
const loading           = document.getElementById("loading");
const errorBanner       = document.getElementById("error-banner");
const errorMessage      = document.getElementById("error-message");
const results           = document.getElementById("results");
const scoreNumber       = document.getElementById("score-number");
const scoreLabel        = document.getElementById("score-label");
const severityLabel     = document.getElementById("severity-label");
const findingsList      = document.getElementById("findings");
const findingsCount     = document.getElementById("findings-count");
const suggestionsEl     = document.getElementById("suggestions-content");
const reportPanel       = document.getElementById("report-panel");
const downloadBtn       = document.getElementById("download-report-btn");
const cloudSelect       = document.getElementById("cloud-select");
const compliancePanel         = document.getElementById("compliance-panel");
const complianceFramework     = document.getElementById("compliance-framework");
const runComplianceBtn        = document.getElementById("run-compliance-btn");
const exportComplianceBtn     = document.getElementById("export-compliance-btn");
const complianceScoreRow      = document.getElementById("compliance-score-row");
const complianceScoreBadge    = document.getElementById("compliance-score-badge");
const complianceCounts        = document.getElementById("compliance-counts");
const complianceControlsContainer = document.getElementById("compliance-controls-container");
const complianceControlsBody  = document.getElementById("compliance-controls-body");
const complianceLoading       = document.getElementById("compliance-loading");
const historySidebar = document.getElementById("history-sidebar");
const historyClose   = document.getElementById("history-close");
const historyList    = document.getElementById("history-list");

let cyInstance      = null;
let activeHistoryId = null;

// ── Severity maps ─────────────────────────────────────────────────────────────
const SEVERITY_CLASS = {
  CRITICAL: "risk-critical", HIGH: "risk-high", MEDIUM: "risk-medium", LOW: "risk-low",
};
const BADGE_CLASS = {
  CRITICAL: "badge-critical", HIGH: "badge-high", MEDIUM: "badge-medium", LOW: "badge-low",
};
const NODE_COLOR = {
  policy: "#1a3a3a", statement: "#b8a4ed", resource: "#e8b94a", principal: "#a4d4c5",
};

function severityTextColor(sev) {
  if (sev === "CRITICAL") return "#ef4444";
  if (sev === "HIGH")     return "#f59e0b";
  if (sev === "MEDIUM")   return "#e8b94a";
  return "#22c55e";
}

function getRiskColor(w) {
  if (w >= 8.0) return "#ef4444";
  if (w >= 6.0) return "#f59e0b";
  if (w >= 4.0) return "#e8b94a";
  return "#22c55e";
}
function getRiskClass(w) {
  if (w >= 8.0) return "detail-risk-critical";
  if (w >= 6.0) return "detail-risk-high";
  if (w >= 4.0) return "detail-risk-medium";
  return "detail-risk-low";
}

// ── State helpers ─────────────────────────────────────────────────────────────
function setLoading(active) {
  analyzeBtn.disabled = active;
  loading.classList.toggle("active", active);
}
function showError(msg) {
  errorMessage.textContent = msg;
  errorBanner.classList.add("active");
  setTimeout(() => errorBanner.classList.remove("active"), 30000);
}
function clearError() { errorBanner.classList.remove("active"); }

// ── Utilities ─────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  if (typeof str !== "string") return String(str);
  return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
            .replace(/"/g,"&quot;").replace(/'/g,"&#x27;");
}
function formatDate(isoStr) {
  const d = new Date(isoStr);
  return d.toLocaleDateString(undefined,{month:"short",day:"numeric"}) + " " +
         d.toLocaleTimeString(undefined,{hour:"2-digit",minute:"2-digit"});
}

// ── Render: risk badge ────────────────────────────────────────────────────────
function renderRiskBadge(score, severity) {
  const riskEl = document.getElementById("risk-score");
  Object.values(SEVERITY_CLASS).forEach(c => riskEl.classList.remove(c));
  riskEl.classList.add(SEVERITY_CLASS[severity] || "risk-low");
  scoreNumber.textContent = score.toFixed(1);
  scoreLabel.textContent  = "/ 10  Risk Score";
  severityLabel.textContent = severity;
}

// ── Render: findings ──────────────────────────────────────────────────────────
function renderFindings(findings) {
  findingsCount.textContent = findings.length;
  if (!findings.length) {
    findingsList.innerHTML = '<p style="color:var(--color-muted);font-size:14px">No findings detected.</p>';
    return;
  }
  findingsList.innerHTML = findings.map(f => `
    <div class="finding-item">
      <span class="finding-badge ${BADGE_CLASS[f.severity] || ""}">${f.severity}</span>
      <div>
        <div class="finding-message">${escapeHtml(f.message)}</div>
        <div class="finding-rule">${escapeHtml(f.rule_id)}</div>
      </div>
    </div>`).join("");
}

// ── Render: graph ─────────────────────────────────────────────────────────────
function showDetailPanel(nodeData) {
  const panel  = document.getElementById("node-detail");
  const typeEl = document.getElementById("detail-type");
  const lblEl  = document.getElementById("detail-label");
  const metaEl = document.getElementById("detail-meta");
  typeEl.textContent = nodeData.node_type.toUpperCase();
  lblEl.textContent  = nodeData.fullLabel || nodeData.label;
  const meta = nodeData.metadata || {};
  let html = "";
  if (meta.effect)                   html += `<span>Effect: <strong>${meta.effect}</strong></span>`;
  if (meta.statement_idx !== undefined) html += `<span>Statement: #${meta.statement_idx}</span>`;
  if (meta.risk_weight !== undefined)
    html += `<span>Risk: <strong class="${getRiskClass(meta.risk_weight)}">${meta.risk_weight}</strong></span>`;
  if (meta.raw) html += `<span>Principal: ${escapeHtml(meta.raw)}</span>`;
  metaEl.innerHTML = html || "<span>No metadata.</span>";
  panel.style.display = "block";
}
function hideDetailPanel() {
  const p = document.getElementById("node-detail");
  if (p) p.style.display = "none";
}

function renderGraph(graphData) {
  if (cyInstance) { cyInstance.destroy(); cyInstance = null; }
  hideDetailPanel();

  const nodes = graphData.nodes.map(n => ({
    data: {
      id: n.id, label: n.label.length > 22 ? n.label.slice(0,20)+"…" : n.label,
      fullLabel: n.label, node_type: n.node_type,
      metadata: n.metadata||{}, riskWeight: (n.metadata||{}).risk_weight,
    },
  }));
  const edges = graphData.edges.map(e => ({
    data: { source: e.source, target: e.target, label: e.edge_type, edge_type: e.edge_type },
  }));

  cyInstance = cytoscape({
    container: document.getElementById("cy"),
    elements: { nodes, edges },
    style: [
      { selector:"node", style:{
          label:"data(label)",
          "background-color": n => n.data("node_type")==="action"
            ? getRiskColor(n.data("riskWeight")||1)
            : NODE_COLOR[n.data("node_type")]||"#9a9a9a",
          color:"#fff","font-size":11,"text-valign":"center","text-halign":"center",
          "text-wrap":"wrap","text-max-width":88,width:80,height:38,
          shape: n => { const t=n.data("node_type");
            if(t==="policy"||t==="statement") return "round-rectangle";
            if(t==="resource") return "diamond"; return "ellipse"; },
          "border-width":0,
      }},
      { selector:"node[node_type='policy']",    style:{width:100,height:44,"font-size":12,"font-weight":600}},
      { selector:"node[node_type='statement']", style:{width:90,height:36,opacity:0.88}},
      { selector:"node:selected",               style:{"border-width":3,"border-color":"#0a0a0a"}},
      { selector:"edge", style:{width:1.5,"line-color":"#d0ccc0","target-arrow-color":"#d0ccc0",
          "target-arrow-shape":"triangle","curve-style":"bezier",opacity:0.7}},
      { selector:"edge[edge_type='TRUSTS']", style:{"line-color":"#a4d4c5","target-arrow-color":"#a4d4c5","line-style":"dashed"}},
      { selector:"edge[edge_type='GRANTS']", style:{"line-color":"#ff4d8b","target-arrow-color":"#ff4d8b",opacity:0.5}},
    ],
    layout:{ name:"dagre",directed:true,padding:28,spacingFactor:1.3,
             rankDir:"TB",nodeSep:40,rankSep:60 },
    userZoomingEnabled:true, userPanningEnabled:true, minZoom:0.2, maxZoom:4,
  });
  cyInstance.on("tap","node", evt => showDetailPanel(evt.target.data()));
  cyInstance.on("tap", evt => { if(evt.target===cyInstance) hideDetailPanel(); });
  cyInstance.fit();
}

// ── Render: AI suggestions ────────────────────────────────────────────────────
function renderSuggestions(suggestions, originalPolicy) {
  if (suggestions.error) {
    suggestionsEl.innerHTML = `<p style="color:var(--color-muted);font-size:14px">
      AI suggestions unavailable: ${escapeHtml(suggestions.error)}</p>`;
    return;
  }
  const origJson = JSON.stringify(JSON.parse(originalPolicy), null, 2);
  const suggJson = suggestions.least_privilege_policy
    ? JSON.stringify(suggestions.least_privilege_policy, null, 2)
    : "No suggestion generated.";
  const changes = (suggestions.changes||[]).map(c => `
    <div class="change-item">
      <span class="change-original">${escapeHtml(c.original)}</span> →
      <span class="change-replacement">${escapeHtml(Array.isArray(c.replacement)?c.replacement.join(", "):c.replacement)}</span>
      <div class="change-reason">${escapeHtml(c.reason||"")}</div>
    </div>`).join("");
  suggestionsEl.innerHTML = `
    <div class="suggestions-grid">
      <div class="policy-pane"><div class="pane-label">Original Policy</div>
        <pre class="policy-code">${escapeHtml(origJson)}</pre></div>
      <div class="policy-pane"><div class="pane-label">Least-Privilege Suggestion</div>
        <pre class="policy-code">${escapeHtml(suggJson)}</pre></div>
    </div>
    ${changes?`<div class="changes-list">${changes}</div>`:""}`;
}

// ── Analysis pipeline ─────────────────────────────────────────────────────────
async function analyzePolicy(policyJson) {
  clearError();
  setLoading(true);
  results.classList.add("hidden");

  let parsed;
  try {
    parsed = JSON.parse(policyJson);
    if (parsed && typeof parsed === "object" && "policy" in parsed
        && !("Statement" in parsed) && !("Version" in parsed)) {
      parsed = parsed.policy;
    }
  } catch {
    showError("Invalid JSON — please check your policy and try again.");
    setLoading(false);
    return;
  }

  try {
    const resp = await fetch("/api/v1/analyze", {
      method:"POST",
      headers:{ "Content-Type":"application/json", ...authHeaders() },
      body: JSON.stringify({ mode:"json", cloud:cloudSelect.value, policy:parsed }),
    });
    if (resp.status === 401) { clearToken(); window.location.href="/index.html"; return; }
    if (resp.status === 429) { showError("Rate limit exceeded. Please wait."); setLoading(false); return; }
    if (!resp.ok) {
      const err = await resp.json().catch(()=>({detail:resp.statusText}));
      showError(`Analysis failed (${resp.status}): ${JSON.stringify(err.detail)}`);
      setLoading(false);
      return;
    }
    const queued = await resp.json();
    activeHistoryId = queued.id;
    const result = await pollAnalysisStatus(queued.id);
    if (!result) return;
    renderRiskBadge(result.risk_score, result.severity);
    renderFindings(result.findings);
    renderGraph(result.graph_data);
    renderSuggestions(result.suggestions, policyJson);
    results.classList.remove("hidden");
    reportPanel.style.display = "";
    compliancePanel.style.display = "";
    resetCompliancePanel();
  } catch (err) {
    showError(`Network error: ${err.message}`);
  } finally {
    setLoading(false);
  }
}

async function pollAnalysisStatus(analysisId, intervalMs=2000, maxAttempts=60) {
  for (let i=0; i<maxAttempts; i++) {
    await new Promise(r => setTimeout(r, i===0?500:intervalMs));
    try {
      const resp = await fetch(`/api/v1/analyses/${analysisId}/status`, { headers:authHeaders() });
      if (!resp.ok) { showError(`Status check failed (${resp.status})`); setLoading(false); return null; }
      const data = await resp.json();
      if (data.status==="completed") return data.result;
      if (data.status==="failed") { showError("Analysis failed in worker. Please try again."); setLoading(false); return null; }
    } catch (err) { showError(`Network error: ${err.message}`); setLoading(false); return null; }
  }
  showError("Analysis timed out.");
  setLoading(false);
  return null;
}

// ── History sidebar ───────────────────────────────────────────────────────────
function openHistory() {
  historySidebar.classList.add("open");
  loadHistory();
}
function closeHistorySidebar() { historySidebar.classList.remove("open"); }
if (historyClose) historyClose.addEventListener("click", closeHistorySidebar);

async function loadHistory() {
  try {
    const resp = await fetch("/api/v1/analyses?limit=50&offset=0", { headers:authHeaders() });
    if (!resp.ok) return;
    const data = await resp.json();
    renderHistoryList(data.items);
  } catch { /* non-critical */ }
}

function renderHistoryList(items) {
  if (!items||!items.length) {
    historyList.innerHTML = '<p class="history-empty">No past analyses yet.</p>';
    return;
  }
  historyList.innerHTML = items.map(item => `
    <div class="history-item${item.id===activeHistoryId?" active":""}"
         data-id="${item.id}" role="button" tabindex="0">
      <div class="history-score" style="color:${severityTextColor(item.severity)}">${item.risk_score.toFixed(1)}</div>
      <div class="history-meta">
        <div class="history-meta-top"><span class="badge ${BADGE_CLASS[item.severity]||""}">${item.severity}</span></div>
        <div class="history-date">${formatDate(item.created_at)}</div>
      </div>
    </div>`).join("");

  historyList.querySelectorAll(".history-item").forEach(el => {
    const handler = () => loadHistoryItem(parseInt(el.dataset.id, 10));
    el.addEventListener("click", handler);
    el.addEventListener("keydown", e => { if (e.key==="Enter"||e.key===" ") handler(); });
  });
}

async function loadHistoryItem(id) {
  try {
    const resp = await fetch(`/api/v1/analyses/${id}`, { headers:authHeaders() });
    if (!resp.ok) return;
    const data = await resp.json();
    activeHistoryId = id;
    renderRiskBadge(data.risk_score, data.severity);
    renderFindings(data.findings);
    renderGraph(data.graph_data);
    renderSuggestions(data.suggestions, data.policy_json||"{}");
    results.classList.remove("hidden");
    reportPanel.style.display = "";
    compliancePanel.style.display = "";
    resetCompliancePanel();
    loadHistory();
    closeHistorySidebar();
    window.scrollTo({top:0,behavior:"smooth"});
  } catch { /* non-critical */ }
}

// ── Compliance panel ──────────────────────────────────────────────────────────
function resetCompliancePanel() {
  complianceScoreRow.style.display = "none";
  complianceControlsContainer.style.display = "none";
  exportComplianceBtn.style.display = "none";
  complianceLoading.style.display = "none";
  complianceControlsBody.innerHTML = "";
  complianceCounts.innerHTML = "";
  complianceScoreBadge.className = "compliance-score-badge";
  complianceScoreBadge.textContent = "—";
}

function renderComplianceReport(data) {
  const score = data.score;
  const cls = score>=80?"score-high":score>=60?"score-med":"score-low";
  complianceScoreBadge.textContent = `${score}%`;
  complianceScoreBadge.className = `compliance-score-badge ${cls}`;
  complianceCounts.innerHTML = `
    <div class="compliance-count-item"><span class="count-num count-pass">${data.passed}</span><span class="count-lbl">Passed</span></div>
    <div class="compliance-count-item"><span class="count-num count-fail">${data.failed}</span><span class="count-lbl">Failed</span></div>
    <div class="compliance-count-item"><span class="count-num count-warn">${data.warnings}</span><span class="count-lbl">Warnings</span></div>
    <div class="compliance-count-item"><span class="count-num count-na">${data.not_applicable}</span><span class="count-lbl">N/A</span></div>`;
  complianceControlsBody.innerHTML = data.controls.map(c => `
    <tr>
      <td><code>${escapeHtml(c.control_id)}</code></td>
      <td>${escapeHtml(c.title)}</td>
      <td><span class="compliance-badge badge-${c.status}">${escapeHtml(c.status.replace("_"," "))}</span></td>
      <td><span class="risk-badge-${c.risk_level}">${escapeHtml(c.risk_level)}</span></td>
      <td class="compliance-details">${c.details.map(d=>escapeHtml(d)).join("<br>")}</td>
    </tr>`).join("");
  complianceScoreRow.style.display = "flex";
  complianceControlsContainer.style.display = "";
  exportComplianceBtn.style.display = "";
}

runComplianceBtn.addEventListener("click", async () => {
  if (!activeHistoryId) return;
  const fw = complianceFramework.value;
  complianceLoading.style.display = "flex";
  complianceScoreRow.style.display = "none";
  complianceControlsContainer.style.display = "none";
  exportComplianceBtn.style.display = "none";
  runComplianceBtn.disabled = true;
  try {
    const resp = await fetch(`/api/v1/analyses/${activeHistoryId}/compliance?framework=${fw}`, { headers:authHeaders() });
    if (!resp.ok) { showError(`Compliance check failed (${resp.status})`); return; }
    renderComplianceReport(await resp.json());
  } catch (err) { showError(`Compliance error: ${err.message}`); }
  finally { complianceLoading.style.display="none"; runComplianceBtn.disabled=false; }
});

exportComplianceBtn.addEventListener("click", async () => {
  if (!activeHistoryId) return;
  const fw = complianceFramework.value;
  exportComplianceBtn.textContent = "Exporting…";
  exportComplianceBtn.disabled = true;
  try {
    const resp = await fetch(`/api/v1/analyses/${activeHistoryId}/compliance?framework=${fw}&format=xlsx`, { headers:authHeaders() });
    if (!resp.ok) { showError(`Export failed (${resp.status})`); return; }
    const url = URL.createObjectURL(await resp.blob());
    const a = document.createElement("a");
    a.href = url; a.download = `compliance_${activeHistoryId}_${fw}.xlsx`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) { showError(`Export error: ${err.message}`); }
  finally { exportComplianceBtn.textContent="Export XLSX"; exportComplianceBtn.disabled=false; }
});

// ── PDF download ──────────────────────────────────────────────────────────────
downloadBtn.addEventListener("click", async () => {
  if (!activeHistoryId) return;
  downloadBtn.textContent = "Generating…";
  downloadBtn.disabled = true;
  try {
    const resp = await fetch(`/api/v1/analyses/${activeHistoryId}/report?format=pdf`, { headers:authHeaders() });
    if (!resp.ok) { showError(`Report failed (${resp.status})`); return; }
    const url = URL.createObjectURL(await resp.blob());
    const a = document.createElement("a");
    a.href = url; a.download = `iam_analysis_${activeHistoryId}.pdf`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) { showError(`Download error: ${err.message}`); }
  finally { downloadBtn.textContent="Download PDF Report"; downloadBtn.disabled=false; }
});

// ── Form events ───────────────────────────────────────────────────────────────
form.addEventListener("submit", e => {
  e.preventDefault();
  const val = textarea.value.trim();
  if (!val) { showError("Paste a policy JSON first."); return; }
  analyzePolicy(val);
});

clearBtn.addEventListener("click", () => {
  textarea.value = "";
  results.classList.add("hidden");
  reportPanel.style.display = "none";
  compliancePanel.style.display = "none";
  resetCompliancePanel();
  clearError();
});

dropZone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", e => {
  const file = e.target.files[0];
  if (!file) return;
  const r = new FileReader();
  r.onload = ev => { textarea.value = ev.target.result; };
  r.readAsText(file);
});
dropZone.addEventListener("dragover",  e => { e.preventDefault(); dropZone.classList.add("drag-over"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
dropZone.addEventListener("drop", e => {
  e.preventDefault(); dropZone.classList.remove("drag-over");
  const file = e.dataTransfer.files[0]; if (!file) return;
  const r = new FileReader();
  r.onload = ev => { textarea.value = ev.target.result; };
  r.readAsText(file);
});

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const fitBtn   = document.getElementById("fit-btn");
  const closeBtn = document.getElementById("detail-close");
  if (fitBtn)   fitBtn.addEventListener("click",   () => { if(cyInstance) cyInstance.fit(); });
  if (closeBtn) closeBtn.addEventListener("click", hideDetailPanel);
});
