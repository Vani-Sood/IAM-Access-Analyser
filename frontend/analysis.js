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

const _ARN_SERVICE_LABELS = {
  s3: "S3", iam: "IAM", ec2: "EC2", lambda: "Lambda",
  kms: "KMS", secretsmanager: "Secrets Manager", rds: "RDS",
  dynamodb: "DynamoDB", sqs: "SQS", sns: "SNS",
  cloudformation: "CloudFormation", sts: "STS",
};

function describeResource(arn) {
  if (arn === "*") return "All resources (wildcard)";
  if (!arn.startsWith("arn:")) return arn;
  const parts = arn.split(":", 6);
  if (parts.length < 6) return arn;
  const svc = _ARN_SERVICE_LABELS[parts[2]] || parts[2].toUpperCase();
  const res = parts[5];
  if (res === "*") return `All ${svc} resources`;
  if (res.endsWith(":*") || res.endsWith("/*")) return `${svc}: ${res}`;
  return `${svc}: ${res}`;
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
    describeResource,
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
  findingsList.innerHTML = findings.map(f => {
    const sourceTag = f.policy_source
      ? `<span style="font-size:11px;background:var(--color-surface-2,#f0ede6);color:var(--color-muted);border-radius:4px;padding:1px 6px;font-family:ui-monospace,monospace;margin-left:6px">${escapeHtml(f.policy_source)}</span>`
      : "";
    const resources = Array.isArray(f.affected_resources) && f.affected_resources.length
      ? `<div class="finding-resources">
           <span style="font-size:11px;color:var(--color-muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em">Affecting</span>
           <ul style="margin:4px 0 0 0;padding-left:16px;list-style:disc">
             ${f.affected_resources.slice(0, 5).map(r =>
               `<li style="font-size:12px;color:var(--color-ink)">
                  <span style="font-family:ui-monospace,monospace;word-break:break-all">${escapeHtml(r)}</span>
                  <span style="color:var(--color-muted);margin-left:4px">(${escapeHtml(describeResource(r))})</span>
                </li>`
             ).join("")}
             ${f.affected_resources.length > 5
               ? `<li style="font-size:12px;color:var(--color-muted)">+${f.affected_resources.length - 5} more</li>`
               : ""}
           </ul>
         </div>`
      : "";
    return `
    <div class="finding-item">
      <span class="finding-badge ${getBadgeClass(f.severity)}">${f.severity}</span>
      <div style="flex:1;min-width:0">
        <div class="finding-message">${escapeHtml(f.message)}${sourceTag}</div>
        <div class="finding-rule">${escapeHtml(f.rule_id)}</div>
        ${resources}
      </div>
    </div>`;
  }).join("");
}

// ── Render: graph ─────────────────────────────────────────────────────────────
function _graphNodeLabel(data) {
  const l = data.label || "";
  if (data.node_type === "resource") {
    if (l === "*") return "*";
    if (l.startsWith("arn:")) {
      // arn:aws:s3:::mybucket/* → mybucket/*
      // arn:aws:iam::123:role/Admin → role/Admin
      const parts = l.split(":");
      const res = parts.slice(5).join(":").replace(/^[^/]*\//, "") || parts[2];
      const short = res || parts[2] || l;
      return short.length > 16 ? short.slice(0, 14) + "…" : short;
    }
    return l.length > 16 ? l.slice(0, 14) + "…" : l;
  }
  return l.length > 16 ? l.slice(0, 14) + "…" : l;
}

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

  const container = document.getElementById("cy");
  if (!container || !graphData || !graphData.nodes || !graphData.nodes.length) return;
  container.innerHTML = "";

  // Build adjacency list
  const nodeMap = {};
  const childrenOf = {};
  graphData.nodes.forEach(n => { nodeMap[n.id] = n; childrenOf[n.id] = []; });
  graphData.edges.forEach(e => { if (childrenOf[e.source]) childrenOf[e.source].push(e.target); });

  const rootNode = graphData.nodes.find(n => n.node_type === "policy") || graphData.nodes[0];

  const _SVC = {
    s3:"S3", iam:"IAM", ec2:"EC2", lambda:"Lambda", rds:"RDS",
    dynamodb:"DynamoDB", kms:"KMS", sts:"STS", sns:"SNS", sqs:"SQS",
    cloudwatch:"CloudWatch", logs:"CW Logs", secretsmanager:"Secrets Mgr",
    cloudformation:"CloudFormation", route53:"Route53",
  };

  function _stmtLabelFromKids(kids, effect) {
    const svcs = {};
    kids.filter(k => k.node_type === "action").forEach(k => {
      const svc = (k.label || "").split(":")[0].toLowerCase();
      if (svc && svc !== "*") svcs[svc] = (svcs[svc] || 0) + 1;
    });
    const top = Object.entries(svcs).sort((a, b) => b[1] - a[1])[0];
    if (!top) return null;
    const name = _SVC[top[0]] || top[0].toUpperCase();
    const extra = Object.keys(svcs).length > 1 ? ` +${Object.keys(svcs).length - 1}` : "";
    return `${name}${extra} (${effect})`;
  }

  function makeTreeNode(id, seen = new Set()) {
    if (seen.has(id) || !nodeMap[id]) return null;
    seen.add(id);
    const n = nodeMap[id];
    const kids = (childrenOf[id] || []).map(c => makeTreeNode(c, new Set(seen))).filter(Boolean);
    let label = n.label;
    if (n.node_type === "statement" && kids.length) {
      const effect = (n.metadata || {}).effect || "Allow";
      label = _stmtLabelFromKids(kids, effect) || label;
    }
    return { id: n.id, label, fullLabel: n.label,
             node_type: n.node_type, metadata: n.metadata || {},
             riskWeight: (n.metadata || {}).risk_weight,
             children: kids.length ? kids : undefined };
  }

  const treeData = makeTreeNode(rootNode.id);
  if (!treeData) return;

  const cw = container.clientWidth || 900;
  const ch = container.clientHeight || 460;
  const margin = { top: 20, right: 60, bottom: 20, left: 130 };
  const _lock = { on: false };

  const svg = d3.select(container).append("svg")
    .attr("width", "100%").attr("height", "100%");

  const zoom = d3.zoom().scaleExtent([0.1, 3])
    .filter(evt => !_lock.on && ((!evt.ctrlKey || evt.type === "wheel") && !evt.button))
    .on("zoom", evt => zoomG.attr("transform", evt.transform));

  const zoomG = svg.append("g");
  svg.call(zoom);
  svg.call(zoom.transform, d3.zoomIdentity.translate(margin.left, ch / 2));

  const g = zoomG.append("g");
  const linkLayer = g.append("g").attr("fill", "none");
  const nodeLayer = g.append("g");

  const treemap = d3.tree().nodeSize([52, 220]);
  let root = d3.hierarchy(treeData);
  let uid = 0;
  root.each(d => { d._uid = ++uid; });

  // Start with statements collapsed
  root.each(d => {
    if (d.depth >= 1 && d.children) { d._children = d.children; d.children = null; }
  });

  const NW = { policy: 120, statement: 110, action: 100, resource: 100 };
  const NH = 36;

  function nColor(d) {
    return d.data.node_type === "action"
      ? getRiskColor(d.data.riskWeight || 1)
      : NODE_COLOR[d.data.node_type] || "#9a9a9a";
  }
  function nW(d) { return NW[d.data.node_type] || 100; }

  function update(src) {
    treemap(root);
    const nodes = root.descendants();
    const links = root.links();

    // links
    const ls = linkLayer.selectAll("path.tl").data(links, d => d.target._uid);
    const sy0 = src._y0 ?? src.y, sx0 = src._x0 ?? src.x;

    ls.enter().append("path").attr("class", "tl")
      .attr("stroke-width", 1.5).attr("opacity", 0)
      .attr("d", () => `M${sy0},${sx0}C${sy0},${sx0},${sy0},${sx0},${sy0},${sx0}`)
      .merge(ls).transition().duration(260)
      .attr("opacity", 0.65)
      .attr("stroke", d => nColor(d.target))
      .attr("d", d => {
        const sx = d.source.x, sy = d.source.y + nW(d.source) / 2;
        const tx = d.target.x, ty = d.target.y - nW(d.target) / 2;
        const mx = (sy + ty) / 2;
        return `M${sy},${sx}C${mx},${sx},${mx},${tx},${ty},${tx}`;
      });

    ls.exit().transition().duration(260).attr("opacity", 0)
      .attr("d", () => `M${src.y},${src.x}C${src.y},${src.x},${src.y},${src.x},${src.y},${src.x}`)
      .remove();

    // nodes
    const ns = nodeLayer.selectAll("g.tn").data(nodes, d => d._uid);

    const ne = ns.enter().append("g").attr("class", "tn")
      .attr("transform", () => `translate(${sy0},${sx0})`)
      .attr("opacity", 0)
      .style("cursor", d => (d.children || d._children) ? "pointer" : "default")
      .on("click", (evt, d) => {
        evt.stopPropagation();
        if (d.children || d._children) {
          if (d.children) { d._children = d.children; d.children = null; }
          else { d.children = d._children; d._children = null; }
          update(d);
        } else {
          showDetailPanel(d.data);
        }
      });

    ne.append("rect").attr("rx", 6).attr("ry", 6)
      .attr("x", d => -nW(d) / 2).attr("y", -NH / 2)
      .attr("width", d => nW(d)).attr("height", NH)
      .attr("fill", d => nColor(d))
      .attr("stroke", "rgba(255,255,255,0.18)").attr("stroke-width", 1);

    ne.filter(d => d.children || d._children)
      .append("circle").attr("class", "xdot")
      .attr("cx", d => nW(d) / 2 + 7).attr("cy", 0).attr("r", 5).attr("stroke-width", 2);

    ne.append("text").attr("dy", "0.35em").attr("text-anchor", "middle")
      .attr("fill", "#fff").attr("font-size", 10).attr("pointer-events", "none")
      .attr("font-family", "ui-sans-serif,system-ui,sans-serif");

    const nu = ne.merge(ns);
    nu.transition().duration(260)
      .attr("transform", d => `translate(${d.y},${d.x})`).attr("opacity", 1);

    nu.select("circle.xdot")
      .attr("fill", d => d._children ? nColor(d) : "#fff")
      .attr("stroke", d => nColor(d));

    nu.select("text")
      .text(d => _graphNodeLabel(d.data));

    ns.exit().transition().duration(260)
      .attr("transform", () => `translate(${src.y},${src.x})`).attr("opacity", 0).remove();

    nodes.forEach(d => { d._x0 = d.x; d._y0 = d.y; });
  }

  update(root);

  cyInstance = {
    destroy() { const c = document.getElementById("cy"); if (c) c.innerHTML = ""; },
    fit() {
      const c = document.getElementById("cy");
      const h = c ? c.clientHeight : 460;
      svg.transition().duration(400)
        .call(zoom.transform, d3.zoomIdentity.translate(margin.left, h / 2));
    },
    userZoomingEnabled(e) { _lock.on = !e; },
    userPanningEnabled(e) { _lock.on = !e; },
  };
}

// ── Render: AI suggestions ────────────────────────────────────────────────────
function renderSuggestions(suggestions, originalPolicy) {
  if (!suggestionsEl) return;
  if (suggestions.error) {
    const _msgs = {
      quota_exceeded:  "Gemini API quota exceeded — check your billing/quota at Google AI Studio.",
      invalid_api_key: "Gemini API key is invalid or not configured.",
      ai_unavailable:  "AI service temporarily unavailable.",
    };
    const _msg = _msgs[suggestions.error] || `AI unavailable: ${suggestions.error}`;
    suggestionsEl.innerHTML = `<p style="color:var(--color-muted);font-size:14px">${escapeHtml(_msg)}</p>`;
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

// ── Graph fit + lock-zoom buttons ────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const fitBtn      = document.getElementById("fit-btn");
  const lockZoomBtn = document.getElementById("lock-zoom-btn");
  const closeBtn    = document.getElementById("detail-close");
  if (fitBtn)   fitBtn.addEventListener("click", () => { if (cyInstance) cyInstance.fit(); });
  if (closeBtn) closeBtn.addEventListener("click", hideDetailPanel);

  const lockLabel   = document.getElementById("lock-label");
  const lockShackle = document.getElementById("lock-shackle");
  let zoomLocked = false;
  if (lockZoomBtn) {
    lockZoomBtn.addEventListener("click", () => {
      zoomLocked = !zoomLocked;
      if (cyInstance) {
        cyInstance.userZoomingEnabled(!zoomLocked);
        cyInstance.userPanningEnabled(!zoomLocked);
      }
      if (lockLabel)   lockLabel.textContent = zoomLocked ? "Unlock" : "Lock";
      if (lockShackle) lockShackle.setAttribute("d",
        zoomLocked ? "M7 11V7a5 5 0 0 1 10 0v4" : "M7 11V7a5 5 0 0 1 9.9-1"
      );
      lockZoomBtn.title        = zoomLocked ? "Unlock zoom & pan" : "Lock zoom & pan";
      lockZoomBtn.style.opacity = zoomLocked ? "1" : "0.7";
    });
  }

  const id = getAnalysisId(window.location.search);
  if (!id) {
    showError("No analysis ID in URL. Go back and run an analysis.");
    return;
  }
  loadAnalysis(id);
});

} // end browser-only block
