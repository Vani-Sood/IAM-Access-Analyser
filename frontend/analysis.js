"use strict";

// ── pure functions (exported for tests) ───────────────────────────────────────

function getAnalysisId(search) {
  if (!search) return null;
  const params = new URLSearchParams(search);
  const raw = params.get("id");
  if (!raw) return null;
  const num = parseInt(raw, 10);
  return Number.isFinite(num) && num > 0 ? num : null;
}

function formatRiskScore(score) {
  return score.toFixed(1);
}

const SEVERITY_CLASS = {
  CRITICAL: "risk-critical",
  HIGH:     "risk-high",
  MEDIUM:   "risk-medium",
  LOW:      "risk-low",
};

const BADGE_CLASS = {
  CRITICAL: "badge-critical",
  HIGH:     "badge-high",
  MEDIUM:   "badge-medium",
  LOW:      "badge-low",
};

function getSeverityClass(severity) {
  return SEVERITY_CLASS[severity] || "risk-low";
}

function getBadgeClass(severity) {
  return BADGE_CLASS[severity] || "";
}

function escapeHtml(str) {
  if (typeof str !== "string") return String(str);
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

function getRiskColor(score) {
  if (score >= 8.0) return "#ef4444";
  if (score >= 6.0) return "#f59e0b";
  if (score >= 4.0) return "#e8b94a";
  return "#22c55e";
}

function buildComplianceUrl(id, framework, format) {
  const base = `/api/v1/analyses/${id}/compliance?framework=${framework}`;
  return format ? `${base}&format=${format}` : base;
}

function buildReportUrl(id, format) {
  return `/api/v1/analyses/${id}/report?format=${format}`;
}

function buildInheritanceUrl(id, fromNode, toNode) {
  return `/api/v1/analyses/${id}/inheritance` +
    `?from_node=${encodeURIComponent(fromNode)}` +
    `&to_node=${encodeURIComponent(toNode)}`;
}

function buildNodeOptions(nodes, allowedTypes) {
  return nodes.filter(n => allowedTypes.includes(n.node_type));
}

function renderInheritanceResult(data) {
  return `
<div class="inheritance-result">
  <div class="inheritance-chain">
    <span class="chain-node chain-from">${escapeHtml(data.from_node)}</span>
    <span class="chain-arrow">→</span>
    <span class="chain-node chain-lca">
      <strong>${escapeHtml(data.lca_label)}</strong>
      <small class="lca-type">${escapeHtml(data.lca_node_type)}</small>
    </span>
    <span class="chain-arrow">←</span>
    <span class="chain-node chain-to">${escapeHtml(data.to_node)}</span>
  </div>
</div>`.trim();
}

function renderInheritanceEmpty() {
  return '<p class="inheritance-empty">No common ancestor found for these nodes.</p>';
}

// ── conditional export ────────────────────────────────────────────────────────
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    getAnalysisId, formatRiskScore,
    getSeverityClass, getBadgeClass,
    escapeHtml, getRiskColor,
    buildComplianceUrl, buildReportUrl,
    buildInheritanceUrl, buildNodeOptions,
    renderInheritanceResult, renderInheritanceEmpty,
  };
}

// ── browser-only DOM logic (skipped in Node/Jest) ─────────────────────────────
if (typeof module === "undefined") {

// constants reused from exports above (closures share scope)
const NODE_COLOR = {
  policy:    "#1a3a3a",
  statement: "#b8a4ed",
  resource:  "#e8b94a",
  principal: "#a4d4c5",
};

let cyInstance     = null;
let activeId       = null;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const errorBanner  = document.getElementById("error-banner");
const errorMsg     = document.getElementById("error-message");
const loadingEl    = document.getElementById("page-loading");
const riskScoreEl  = document.getElementById("risk-score");
const scoreNumber  = document.getElementById("score-number");
const scoreLabel   = document.getElementById("score-label");
const severityLbl  = document.getElementById("severity-label");
const findingsList = document.getElementById("findings");
const findingsCount= document.getElementById("findings-count");
const suggestionsEl= document.getElementById("suggestions-content");
const reportPanel  = document.getElementById("report-panel");
const downloadBtn  = document.getElementById("download-report-btn");
const compliancePanel         = document.getElementById("compliance-panel");
const complianceFramework     = document.getElementById("compliance-framework");
const runComplianceBtn        = document.getElementById("run-compliance-btn");
const exportComplianceBtn     = document.getElementById("export-compliance-btn");
const complianceScoreRow      = document.getElementById("compliance-score-row");
const complianceScoreBadge    = document.getElementById("compliance-score-badge");
const complianceCounts        = document.getElementById("compliance-counts");
const complianceControlsCont  = document.getElementById("compliance-controls-container");
const complianceControlsBody  = document.getElementById("compliance-controls-body");
const complianceLoadingEl     = document.getElementById("compliance-loading");
const privescSection          = document.getElementById("privesc-section");
const privescContent          = document.getElementById("privesc-content");
const privescLoadBtn          = document.getElementById("load-privesc-btn");
const inheritanceSection      = document.getElementById("inheritance-section");
const inheritanceFrom         = document.getElementById("inheritance-from");
const inheritanceTo           = document.getElementById("inheritance-to");
const runInheritanceBtn       = document.getElementById("run-inheritance-btn");
const inheritanceLoadingEl    = document.getElementById("inheritance-loading");
const inheritanceResult       = document.getElementById("inheritance-result");

function showError(msg) {
  if (errorMsg)    errorMsg.textContent = msg;
  if (errorBanner) errorBanner.classList.add("active");
}

function setPageLoading(active) {
  if (loadingEl) loadingEl.classList.toggle("active", active);
}

// ── Render: risk badge ────────────────────────────────────────────────────────
function renderRiskBadge(score, severity) {
  Object.values(SEVERITY_CLASS).forEach(c => riskScoreEl.classList.remove(c));
  riskScoreEl.classList.add(getSeverityClass(severity));
  scoreNumber.textContent = formatRiskScore(score);
  scoreLabel.textContent  = "/ 10  Risk Score";
  severityLbl.textContent = severity;
}

// ── Render: findings ──────────────────────────────────────────────────────────
function renderFindings(findings) {
  findingsCount.textContent = findings.length;
  if (!findings.length) {
    findingsList.innerHTML =
      '<p style="color:var(--color-muted);font-size:14px">No findings detected.</p>';
    return;
  }
  findingsList.innerHTML = findings.map(f => `
    <div class="finding-item">
      <span class="finding-badge ${getBadgeClass(f.severity)}">${f.severity}</span>
      <div>
        <div class="finding-message">${escapeHtml(f.message)}</div>
        <div class="finding-rule">${escapeHtml(f.rule_id)}</div>
      </div>
    </div>`).join("");
}

// ── Render: graph ─────────────────────────────────────────────────────────────
function hideDetailPanel() {
  const p = document.getElementById("node-detail");
  if (p) p.style.display = "none";
}

function showDetailPanel(nodeData) {
  const panel  = document.getElementById("node-detail");
  const typeEl = document.getElementById("detail-type");
  const lblEl  = document.getElementById("detail-label");
  const metaEl = document.getElementById("detail-meta");
  if (!panel) return;
  typeEl.textContent = nodeData.node_type.toUpperCase();
  lblEl.textContent  = nodeData.fullLabel || nodeData.label;
  const meta = nodeData.metadata || {};
  let html = "";
  if (meta.effect)
    html += `<span>Effect: <strong>${meta.effect}</strong></span>`;
  if (meta.statement_idx !== undefined)
    html += `<span>Statement: #${meta.statement_idx}</span>`;
  if (meta.risk_weight !== undefined)
    html += `<span>Risk: <strong style="color:${getRiskColor(meta.risk_weight)}">${meta.risk_weight}</strong></span>`;
  if (meta.raw)
    html += `<span>Principal: ${escapeHtml(meta.raw)}</span>`;
  metaEl.innerHTML = html || "<span>No metadata.</span>";
  panel.style.display = "block";
}

function renderGraph(graphData) {
  if (cyInstance) { cyInstance.destroy(); cyInstance = null; }
  hideDetailPanel();

  const nodes = graphData.nodes.map(n => ({
    data: {
      id: n.id,
      label: n.label.length > 22 ? n.label.slice(0, 20) + "…" : n.label,
      fullLabel: n.label,
      node_type: n.node_type,
      metadata: n.metadata || {},
      riskWeight: (n.metadata || {}).risk_weight,
    },
  }));
  const edges = graphData.edges.map(e => ({
    data: { source: e.source, target: e.target, label: e.edge_type, edge_type: e.edge_type },
  }));

  cyInstance = cytoscape({
    container: document.getElementById("cy"),
    elements: { nodes, edges },
    style: [
      { selector: "node", style: {
        label: "data(label)",
        "background-color": n => n.data("node_type") === "action"
          ? getRiskColor(n.data("riskWeight") || 1)
          : NODE_COLOR[n.data("node_type")] || "#9a9a9a",
        color: "#fff", "font-size": 11,
        "text-valign": "center", "text-halign": "center",
        "text-wrap": "wrap", "text-max-width": 88,
        width: 80, height: 38,
        shape: n => {
          const t = n.data("node_type");
          if (t === "policy" || t === "statement") return "round-rectangle";
          if (t === "resource") return "diamond";
          return "ellipse";
        },
        "border-width": 0,
      }},
      { selector: "node[node_type='policy']",    style: { width: 100, height: 44, "font-size": 12, "font-weight": 600 } },
      { selector: "node[node_type='statement']", style: { width: 90, height: 36, opacity: 0.88 } },
      { selector: "node:selected",               style: { "border-width": 3, "border-color": "#0a0a0a" } },
      { selector: "edge", style: {
        width: 1.5, "line-color": "#d0ccc0",
        "target-arrow-color": "#d0ccc0", "target-arrow-shape": "triangle",
        "curve-style": "bezier", opacity: 0.7,
      }},
      { selector: "edge[edge_type='TRUSTS']", style: { "line-color": "#a4d4c5", "target-arrow-color": "#a4d4c5", "line-style": "dashed" } },
      { selector: "edge[edge_type='GRANTS']", style: { "line-color": "#ff4d8b", "target-arrow-color": "#ff4d8b", opacity: 0.5 } },
    ],
    layout: { name: "dagre", directed: true, padding: 28, spacingFactor: 1.3, rankDir: "TB", nodeSep: 40, rankSep: 60 },
    userZoomingEnabled: true, userPanningEnabled: true, minZoom: 0.2, maxZoom: 4,
  });
  cyInstance.on("tap", "node", evt => showDetailPanel(evt.target.data()));
  cyInstance.on("tap", evt => { if (evt.target === cyInstance) hideDetailPanel(); });
  cyInstance.fit();
}

// ── Render: AI suggestions ────────────────────────────────────────────────────
function renderSuggestions(suggestions, originalPolicy) {
  if (!suggestionsEl) return;
  if (suggestions.error) {
    suggestionsEl.innerHTML = `<p style="color:var(--color-muted);font-size:14px">
      AI suggestions unavailable: ${escapeHtml(suggestions.error)}</p>`;
    return;
  }
  let origJson;
  try {
    origJson = JSON.stringify(JSON.parse(originalPolicy), null, 2);
  } catch {
    origJson = originalPolicy || "{}";
  }
  const suggJson = suggestions.least_privilege_policy
    ? JSON.stringify(suggestions.least_privilege_policy, null, 2)
    : "No suggestion generated.";
  const changes = (suggestions.changes || []).map(c => `
    <div class="change-item">
      <span class="change-original">${escapeHtml(c.original)}</span> →
      <span class="change-replacement">${escapeHtml(
        Array.isArray(c.replacement) ? c.replacement.join(", ") : c.replacement
      )}</span>
      <div class="change-reason">${escapeHtml(c.reason || "")}</div>
    </div>`).join("");
  suggestionsEl.innerHTML = `
    <div class="suggestions-grid">
      <div class="policy-pane"><div class="pane-label">Original Policy</div>
        <pre class="policy-code">${escapeHtml(origJson)}</pre></div>
      <div class="policy-pane"><div class="pane-label">Least-Privilege Suggestion</div>
        <pre class="policy-code">${escapeHtml(suggJson)}</pre></div>
    </div>
    ${changes ? `<div class="changes-list">${changes}</div>` : ""}`;
}

// ── Render: privesc paths ─────────────────────────────────────────────────────
function renderPrivesc(data) {
  if (!privescContent) return;
  if (!data.paths || !data.paths.length) {
    privescContent.innerHTML =
      '<p style="color:var(--color-muted);font-size:14px">No privilege escalation paths detected.</p>';
    return;
  }
  privescContent.innerHTML = data.paths.map(p => `
    <div class="privesc-item">
      <div class="privesc-header">
        <span class="finding-badge ${getBadgeClass(p.severity)}">${p.severity}</span>
        <span class="privesc-route">${escapeHtml(p.source_node)} → ${escapeHtml(p.target_node)}</span>
      </div>
      <p class="privesc-desc">${escapeHtml(p.description)}</p>
      ${p.dangerous_actions.length ? `
        <div class="privesc-actions">
          ${p.dangerous_actions.map(a => `<code>${escapeHtml(a)}</code>`).join(" ")}
        </div>` : ""}
    </div>`).join("");
}

// ── Compliance panel ──────────────────────────────────────────────────────────
function resetCompliancePanel() {
  if (complianceScoreRow)     complianceScoreRow.style.display    = "none";
  if (complianceControlsCont) complianceControlsCont.style.display = "none";
  if (exportComplianceBtn)    exportComplianceBtn.style.display   = "none";
  if (complianceLoadingEl)    complianceLoadingEl.style.display   = "none";
  if (complianceControlsBody) complianceControlsBody.innerHTML    = "";
  if (complianceCounts)       complianceCounts.innerHTML          = "";
  if (complianceScoreBadge) {
    complianceScoreBadge.className   = "compliance-score-badge";
    complianceScoreBadge.textContent = "—";
  }
}

function renderComplianceReport(data) {
  const score = data.score;
  const cls = score >= 80 ? "score-high" : score >= 60 ? "score-med" : "score-low";
  complianceScoreBadge.textContent = `${score}%`;
  complianceScoreBadge.className   = `compliance-score-badge ${cls}`;
  complianceCounts.innerHTML = `
    <div class="compliance-count-item"><span class="count-num count-pass">${data.passed}</span><span class="count-lbl">Passed</span></div>
    <div class="compliance-count-item"><span class="count-num count-fail">${data.failed}</span><span class="count-lbl">Failed</span></div>
    <div class="compliance-count-item"><span class="count-num count-warn">${data.warnings}</span><span class="count-lbl">Warnings</span></div>
    <div class="compliance-count-item"><span class="count-num count-na">${data.not_applicable}</span><span class="count-lbl">N/A</span></div>`;
  complianceControlsBody.innerHTML = data.controls.map(c => `
    <tr>
      <td><code>${escapeHtml(c.control_id)}</code></td>
      <td>${escapeHtml(c.title)}</td>
      <td><span class="compliance-badge badge-${c.status}">${escapeHtml(c.status.replace("_", " "))}</span></td>
      <td><span class="risk-badge-${c.risk_level}">${escapeHtml(c.risk_level)}</span></td>
      <td class="compliance-details">${c.details.map(d => escapeHtml(d)).join("<br>")}</td>
    </tr>`).join("");
  complianceScoreRow.style.display    = "flex";
  complianceControlsCont.style.display = "";
  exportComplianceBtn.style.display   = "";
}

// ── Load analysis data ────────────────────────────────────────────────────────
async function loadAnalysis(id) {
  setPageLoading(true);
  try {
    const resp = await fetch(`/api/v1/analyses/${id}`, { headers: authHeaders() });
    if (resp.status === 401) { clearToken(); window.location.href = "/index.html"; return; }
    if (!resp.ok) {
      showError(`Failed to load analysis (${resp.status})`);
      setPageLoading(false);
      return;
    }
    const data = await resp.json();
    activeId = id;
    renderRiskBadge(data.risk_score, data.severity);
    renderFindings(data.findings);
    renderGraph(data.graph_data);
    renderSuggestions(data.suggestions, data.policy_json || "{}");

    const metaEl = document.getElementById("analysis-meta");
    if (metaEl) {
      const created = new Date(data.created_at);
      const dateStr = created.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) +
                      " " + created.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
      metaEl.textContent = `Analysis #${data.id} · ${dateStr}`;
    }

    if (reportPanel)        reportPanel.style.display        = "";
    if (compliancePanel)    compliancePanel.style.display    = "";
    if (privescSection)     privescSection.style.display     = "";
    if (inheritanceSection) inheritanceSection.style.display = "";
    resetCompliancePanel();
    populateInheritanceDropdowns(data.graph_data.nodes);
  } catch (err) {
    showError(`Network error: ${err.message}`);
  } finally {
    setPageLoading(false);
  }
}

// ── Inheritance lookup ────────────────────────────────────────────────────────
function populateInheritanceDropdowns(nodes) {
  if (!inheritanceFrom || !inheritanceTo) return;
  const ALL_TYPES = ["policy", "statement", "action", "resource", "principal"];
  const opts = buildNodeOptions(nodes, ALL_TYPES);
  const optHtml = opts.map(n =>
    `<option value="${escapeHtml(n.id)}">${escapeHtml(n.label)}</option>`
  ).join("");
  inheritanceFrom.innerHTML = '<option value="">Select first node…</option>' + optHtml;
  inheritanceTo.innerHTML   = '<option value="">Select second node…</option>' + optHtml;
}

if (runInheritanceBtn) {
  runInheritanceBtn.addEventListener("click", async () => {
    if (!activeId) return;
    const fromNode = inheritanceFrom ? inheritanceFrom.value : "";
    const toNode   = inheritanceTo   ? inheritanceTo.value   : "";
    if (!fromNode || !toNode) {
      showError("Select both nodes before running inheritance lookup.");
      return;
    }
    if (inheritanceLoadingEl) inheritanceLoadingEl.style.display = "flex";
    if (inheritanceResult)    inheritanceResult.innerHTML = "";
    runInheritanceBtn.disabled = true;
    try {
      const resp = await fetch(
        buildInheritanceUrl(activeId, fromNode, toNode),
        { headers: authHeaders() }
      );
      if (resp.status === 422 || resp.status === 404) {
        if (inheritanceResult) inheritanceResult.innerHTML = renderInheritanceEmpty();
        return;
      }
      if (!resp.ok) { showError(`Inheritance lookup failed (${resp.status})`); return; }
      if (inheritanceResult) inheritanceResult.innerHTML = renderInheritanceResult(await resp.json());
    } catch (err) {
      showError(`Network error: ${err.message}`);
    } finally {
      if (inheritanceLoadingEl) inheritanceLoadingEl.style.display = "none";
      runInheritanceBtn.disabled = false;
    }
  });
}

// ── Privesc load ──────────────────────────────────────────────────────────────
if (privescLoadBtn) {
  privescLoadBtn.addEventListener("click", async () => {
    if (!activeId) return;
    privescLoadBtn.disabled = true;
    privescLoadBtn.textContent = "Loading…";
    try {
      const resp = await fetch(`/api/v1/analyses/${activeId}/privesc`, { headers: authHeaders() });
      if (!resp.ok) { showError(`Privesc load failed (${resp.status})`); return; }
      renderPrivesc(await resp.json());
      privescLoadBtn.style.display = "none";
    } catch (err) {
      showError(`Network error: ${err.message}`);
    } finally {
      privescLoadBtn.disabled = false;
      privescLoadBtn.textContent = "Check Privilege Escalation";
    }
  });
}

// ── Compliance events ─────────────────────────────────────────────────────────
if (runComplianceBtn) {
  runComplianceBtn.addEventListener("click", async () => {
    if (!activeId) return;
    const fw = complianceFramework.value;
    complianceLoadingEl.style.display   = "flex";
    complianceScoreRow.style.display    = "none";
    complianceControlsCont.style.display = "none";
    exportComplianceBtn.style.display   = "none";
    runComplianceBtn.disabled = true;
    try {
      const resp = await fetch(buildComplianceUrl(activeId, fw, null), { headers: authHeaders() });
      if (!resp.ok) { showError(`Compliance check failed (${resp.status})`); return; }
      renderComplianceReport(await resp.json());
    } catch (err) {
      showError(`Compliance error: ${err.message}`);
    } finally {
      complianceLoadingEl.style.display = "none";
      runComplianceBtn.disabled = false;
    }
  });
}

if (exportComplianceBtn) {
  exportComplianceBtn.addEventListener("click", async () => {
    if (!activeId) return;
    const fw = complianceFramework.value;
    exportComplianceBtn.textContent = "Exporting…";
    exportComplianceBtn.disabled = true;
    try {
      const resp = await fetch(buildComplianceUrl(activeId, fw, "xlsx"), { headers: authHeaders() });
      if (!resp.ok) { showError(`Export failed (${resp.status})`); return; }
      const url = URL.createObjectURL(await resp.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = `compliance_${activeId}_${fw}.xlsx`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      showError(`Export error: ${err.message}`);
    } finally {
      exportComplianceBtn.textContent = "Export XLSX";
      exportComplianceBtn.disabled = false;
    }
  });
}

// ── PDF download ──────────────────────────────────────────────────────────────
if (downloadBtn) {
  downloadBtn.addEventListener("click", async () => {
    if (!activeId) return;
    downloadBtn.textContent = "Generating…";
    downloadBtn.disabled = true;
    try {
      const resp = await fetch(buildReportUrl(activeId, "pdf"), { headers: authHeaders() });
      if (!resp.ok) { showError(`Report failed (${resp.status})`); return; }
      const url = URL.createObjectURL(await resp.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = `iam_analysis_${activeId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      showError(`Download error: ${err.message}`);
    } finally {
      downloadBtn.textContent = "Download PDF Report";
      downloadBtn.disabled = false;
    }
  });
}

// ── Graph fit button ──────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const fitBtn   = document.getElementById("fit-btn");
  const closeBtn = document.getElementById("detail-close");
  if (fitBtn)   fitBtn.addEventListener("click",   () => { if (cyInstance) cyInstance.fit(); });
  if (closeBtn) closeBtn.addEventListener("click", hideDetailPanel);

  const id = getAnalysisId(window.location.search);
  if (!id) {
    showError("No analysis ID in URL. Go back and run an analysis.");
    return;
  }
  loadAnalysis(id);
});

} // end browser-only block
