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

// ── Render: trend chart (Chart.js) ───────────────────────────────────────────
function renderTrendChart(trend) {
  const canvas = document.getElementById("trend-chart");
  if (!canvas || !window.Chart) return;
  const { labels, counts, avgRisks } = trendToChartData(trend);

  if (window._trendChart) { window._trendChart.destroy(); }

  window._trendChart = new Chart(canvas, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          type: "bar",
          label: "Analyses",
          data: counts,
          backgroundColor: "rgba(184, 164, 237, 0.6)",
          borderColor: "rgba(184, 164, 237, 1)",
          borderWidth: 1,
          yAxisID: "yCount",
        },
        {
          type: "line",
          label: "Avg Risk",
          data: avgRisks,
          borderColor: "#ff4d8b",
          backgroundColor: "transparent",
          pointBackgroundColor: "#ff4d8b",
          tension: 0.3,
          yAxisID: "yRisk",
        },
      ],
    },
    options: {
      responsive: true,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { position: "bottom" } },
      scales: {
        yCount: {
          type: "linear", position: "left",
          title: { display: true, text: "Analyses" },
          ticks: { precision: 0 },
        },
        yRisk: {
          type: "linear", position: "right",
          min: 0, max: 10,
          title: { display: true, text: "Avg Risk Score" },
          grid: { drawOnChartArea: false },
        },
      },
    },
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
