"use strict";

// ── pure functions (exported for tests) ───────────────────────────────────────

function calcSeverityPercent(dist, severity) {
  const total = Object.values(dist).reduce((s, n) => s + n, 0);
  if (total === 0) return 0;
  return Math.round(((dist[severity] || 0) / total) * 100);
}

function topHeatmapEntries(heatmap, n) {
  return heatmap.slice(0, n);
}

function trendToChartData(trend) {
  return {
    labels:    trend.map(t => t.date),
    counts:    trend.map(t => t.count),
    avgRisks:  trend.map(t => t.avg_risk),
  };
}

function formatAvgRisk(score) {
  return score.toFixed(1);
}

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high:     "#f59e0b",
  medium:   "#e8b94a",
  low:      "#22c55e",
  info:     "#6a6a6a",
};

function severityColor(severity) {
  return SEVERITY_COLORS[severity.toLowerCase()] || "#9a9a9a";
}

function heatmapIntensity(count, maxCount) {
  if (maxCount === 0) return 0.0;
  return Math.min(count / maxCount, 1.0);
}

// ── conditional export ────────────────────────────────────────────────────────
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    calcSeverityPercent, topHeatmapEntries, trendToChartData,
    formatAvgRisk, severityColor, heatmapIntensity,
  };
}

// ── browser-only DOM logic (skipped in Node/Jest) ─────────────────────────────
if (typeof module === "undefined") {

const errorBanner   = document.getElementById("error-banner");
const errorMsg      = document.getElementById("error-message");
const loadingEl     = document.getElementById("page-loading");
const totalEl       = document.getElementById("stat-total");
const avgRiskEl     = document.getElementById("stat-avg-risk");
const orgSlugEl     = document.getElementById("stat-org");
const distBarEl     = document.getElementById("severity-dist");
const heatmapEl     = document.getElementById("heatmap-grid");
const heatmapEmpty  = document.getElementById("heatmap-empty");

function showError(msg) {
  if (errorMsg)    errorMsg.textContent = msg;
  if (errorBanner) errorBanner.classList.add("active");
}

function setLoading(active) {
  if (loadingEl) loadingEl.classList.toggle("active", active);
}

// ── Render: severity distribution bars ───────────────────────────────────────
function renderSeverityDist(dist) {
  if (!distBarEl) return;
  const severities = ["critical", "high", "medium", "low", "info"];
  distBarEl.innerHTML = severities.map(sev => {
    const pct = calcSeverityPercent(dist, sev);
    const count = dist[sev] || 0;
    const color = severityColor(sev);
    return `
      <div class="dist-row">
        <span class="dist-label">${sev.toUpperCase()}</span>
        <div class="dist-bar-track">
          <div class="dist-bar-fill"
               style="width:${pct}%;background:${color}"></div>
        </div>
        <span class="dist-count">${count}</span>
      </div>`;
  }).join("");
}

// ── Render: heatmap grid (top 20 actions) ────────────────────────────────────
function renderHeatmap(heatmap) {
  if (!heatmapEl) return;
  const top = topHeatmapEntries(heatmap, 20);
  if (!top.length) {
    if (heatmapEmpty) heatmapEmpty.style.display = "";
    return;
  }
  if (heatmapEmpty) heatmapEmpty.style.display = "none";
  const maxCount = top[0].count;
  heatmapEl.innerHTML = top.map(entry => {
    const intensity = heatmapIntensity(entry.count, maxCount);
    const bg = `rgba(255, 77, 139, ${0.1 + intensity * 0.85})`;
    return `
      <div class="heatmap-cell" style="background:${bg}"
           title="${entry.action} — ${entry.count} occurrence${entry.count !== 1 ? "s" : ""}">
        <div class="heatmap-action">${entry.action}</div>
        <div class="heatmap-count">${entry.count}</div>
      </div>`;
  }).join("");
}

// ── Render: trend chart (D3 area chart) ──────────────────────────────────────
function renderTrendChart(trend) {
  const el = document.getElementById("trend-chart");
  if (!el || typeof d3 === "undefined") return;
  el.innerHTML = "";
  if (!trend || !trend.length) return;

  const data = trend.map(t => ({ date: t.date, count: t.count, risk: t.avg_risk }));

  const margin = { top: 20, right: 24, bottom: 48, left: 44 };
  const totalW = el.clientWidth || 560;
  const totalH = 220;
  const W = totalW - margin.left - margin.right;
  const H = totalH - margin.top - margin.bottom;

  const svg = d3.select(el).append("svg")
    .attr("width", "100%")
    .attr("height", totalH)
    .attr("viewBox", `0 0 ${totalW} ${totalH}`)
    .attr("preserveAspectRatio", "xMidYMid meet");

  const defs = svg.append("defs");
  const gradId = "trend-area-grad";
  const grad = defs.append("linearGradient")
    .attr("id", gradId).attr("x1", 0).attr("y1", 0).attr("x2", 0).attr("y2", 1);
  grad.append("stop").attr("offset", "0%")
    .attr("stop-color", "#1a3a3a").attr("stop-opacity", 0.22);
  grad.append("stop").attr("offset", "100%")
    .attr("stop-color", "#1a3a3a").attr("stop-opacity", 0.02);

  const g = svg.append("g").attr("transform", `translate(${margin.left},${margin.top})`);

  const x = d3.scalePoint().domain(data.map(d => d.date)).range([0, W]).padding(0.3);
  const y = d3.scaleLinear()
    .domain([0, d3.max(data, d => d.count) * 1.15 || 1])
    .range([H, 0]).nice();

  // Grid lines
  g.append("g").attr("class", "grid")
    .call(d3.axisLeft(y).ticks(5).tickSize(-W).tickFormat(""))
    .call(gg => {
      gg.select(".domain").remove();
      gg.selectAll("line")
        .attr("stroke", "#e5e5e5").attr("stroke-dasharray", "0");
    });

  // Area fill
  const area = d3.area()
    .x(d => x(d.date))
    .y0(H).y1(d => y(d.count))
    .curve(d3.curveCatmullRom.alpha(0.5));

  g.append("path").datum(data)
    .attr("fill", `url(#${gradId})`)
    .attr("d", area);

  // Line
  const line = d3.line()
    .x(d => x(d.date))
    .y(d => y(d.count))
    .curve(d3.curveCatmullRom.alpha(0.5));

  g.append("path").datum(data)
    .attr("fill", "none")
    .attr("stroke", "#1a3a3a")
    .attr("stroke-width", 2.2)
    .attr("d", line);

  // Dots
  g.selectAll("circle").data(data).enter().append("circle")
    .attr("cx", d => x(d.date))
    .attr("cy", d => y(d.count))
    .attr("r", 4)
    .attr("fill", "#1a3a3a")
    .attr("stroke", "#fffaf0")
    .attr("stroke-width", 2);

  // X axis
  const maxTicks = Math.floor(W / 72);
  const step = Math.max(1, Math.ceil(data.length / maxTicks));
  const xTicks = data.filter((_, i) => i % step === 0).map(d => d.date);
  g.append("g").attr("transform", `translate(0,${H})`)
    .call(d3.axisBottom(x).tickValues(xTicks).tickSize(4))
    .call(ax => {
      ax.select(".domain").attr("stroke", "#e5e5e5");
      ax.selectAll("text")
        .attr("fill", "#6a6a6a").attr("font-size", 11)
        .attr("transform", "rotate(-35)").attr("text-anchor", "end")
        .attr("dx", "-0.4em").attr("dy", "0.6em");
      ax.selectAll(".tick line").attr("stroke", "#e5e5e5");
    });

  // Y axis
  g.append("g")
    .call(d3.axisLeft(y).ticks(5).tickFormat(d3.format("d")))
    .call(ax => {
      ax.select(".domain").remove();
      ax.selectAll("text").attr("fill", "#6a6a6a").attr("font-size", 11);
      ax.selectAll(".tick line").attr("stroke", "#e5e5e5");
    });
}

// ── Load dashboard data ───────────────────────────────────────────────────────
async function loadDashboard() {
  setLoading(true);
  try {
    const resp = await fetch("/api/v1/dashboard/summary", {
      headers: authHeaders(),
    });
    if (resp.status === 401) { clearToken(); window.location.href = "/index.html"; return; }
    if (!resp.ok) { showError(`Failed to load dashboard (${resp.status})`); return; }

    const data = await resp.json();

    if (totalEl)   totalEl.textContent = data.total_analyses;
    if (avgRiskEl) avgRiskEl.textContent = formatAvgRisk(data.avg_risk_score);
    if (orgSlugEl) orgSlugEl.textContent = data.org_slug || "Personal";

    renderSeverityDist(data.severity_distribution);
    renderHeatmap(data.heatmap);
    renderTrendChart(data.trend);
  } catch (err) {
    showError(`Network error: ${err.message}`);
  } finally {
    setLoading(false);
  }
}

loadDashboard();

} // end browser-only block
