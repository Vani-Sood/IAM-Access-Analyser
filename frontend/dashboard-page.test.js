/**
 * @jest-environment jsdom
 */
"use strict";

const {
  calcSeverityPercent,
  topHeatmapEntries,
  trendToChartData,
  formatAvgRisk,
  severityColor,
  heatmapIntensity,
} = require("./dashboard-page.js");

// ── calcSeverityPercent ───────────────────────────────────────────────────────

describe("calcSeverityPercent", () => {
  const dist = { critical: 2, high: 3, medium: 3, low: 2, info: 0 };

  test("calculates percent for critical", () => {
    expect(calcSeverityPercent(dist, "critical")).toBe(20);
  });

  test("calculates percent for high", () => {
    expect(calcSeverityPercent(dist, "high")).toBe(30);
  });

  test("returns 0 for info when 0", () => {
    expect(calcSeverityPercent(dist, "info")).toBe(0);
  });

  test("returns 0 when total is 0", () => {
    const empty = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    expect(calcSeverityPercent(empty, "critical")).toBe(0);
  });

  test("rounds to nearest integer", () => {
    const d = { critical: 1, high: 0, medium: 0, low: 0, info: 0 };
    expect(calcSeverityPercent(d, "critical")).toBe(100);
  });

  test("calculates medium percent", () => {
    expect(calcSeverityPercent(dist, "medium")).toBe(30);
  });
});

// ── topHeatmapEntries ─────────────────────────────────────────────────────────

describe("topHeatmapEntries", () => {
  const heatmap = [
    { service: "s3",  action: "s3:getobject",    count: 10 },
    { service: "iam", action: "iam:listusers",    count: 8  },
    { service: "ec2", action: "ec2:describeinstances", count: 5 },
    { service: "rds", action: "rds:describedbinstances", count: 2 },
  ];

  test("returns top n entries", () => {
    const result = topHeatmapEntries(heatmap, 2);
    expect(result).toHaveLength(2);
    expect(result[0].action).toBe("s3:getobject");
    expect(result[1].action).toBe("iam:listusers");
  });

  test("returns all when n >= length", () => {
    expect(topHeatmapEntries(heatmap, 10)).toHaveLength(4);
  });

  test("returns empty array for empty heatmap", () => {
    expect(topHeatmapEntries([], 5)).toHaveLength(0);
  });

  test("does not mutate original array", () => {
    const original = [...heatmap];
    topHeatmapEntries(heatmap, 2);
    expect(heatmap).toEqual(original);
  });

  test("returns n=0 as empty", () => {
    expect(topHeatmapEntries(heatmap, 0)).toHaveLength(0);
  });
});

// ── trendToChartData ──────────────────────────────────────────────────────────

describe("trendToChartData", () => {
  const trend = [
    { date: "2026-04-15", count: 2, avg_risk: 7.1 },
    { date: "2026-04-16", count: 3, avg_risk: 5.4 },
    { date: "2026-04-17", count: 1, avg_risk: 8.0 },
  ];

  test("extracts labels as dates", () => {
    const result = trendToChartData(trend);
    expect(result.labels).toEqual(["2026-04-15", "2026-04-16", "2026-04-17"]);
  });

  test("extracts counts", () => {
    const result = trendToChartData(trend);
    expect(result.counts).toEqual([2, 3, 1]);
  });

  test("extracts avgRisks", () => {
    const result = trendToChartData(trend);
    expect(result.avgRisks).toEqual([7.1, 5.4, 8.0]);
  });

  test("returns empty arrays for empty trend", () => {
    const result = trendToChartData([]);
    expect(result.labels).toEqual([]);
    expect(result.counts).toEqual([]);
    expect(result.avgRisks).toEqual([]);
  });
});

// ── formatAvgRisk ─────────────────────────────────────────────────────────────

describe("formatAvgRisk", () => {
  test("formats to 1 decimal", () => {
    expect(formatAvgRisk(6.523)).toBe("6.5");
  });

  test("formats integer", () => {
    expect(formatAvgRisk(8)).toBe("8.0");
  });

  test("formats zero", () => {
    expect(formatAvgRisk(0)).toBe("0.0");
  });

  test("formats 10", () => {
    expect(formatAvgRisk(10)).toBe("10.0");
  });
});

// ── severityColor ─────────────────────────────────────────────────────────────

describe("severityColor", () => {
  test("critical returns red", () => {
    expect(severityColor("critical")).toBe("#ef4444");
  });

  test("high returns amber", () => {
    expect(severityColor("high")).toBe("#f59e0b");
  });

  test("medium returns ochre", () => {
    expect(severityColor("medium")).toBe("#e8b94a");
  });

  test("low returns green", () => {
    expect(severityColor("low")).toBe("#22c55e");
  });

  test("info returns muted blue-grey", () => {
    expect(severityColor("info")).toBe("#6a6a6a");
  });

  test("unknown returns grey fallback", () => {
    expect(severityColor("unknown")).toBe("#9a9a9a");
  });

  test("uppercase CRITICAL also maps", () => {
    expect(severityColor("CRITICAL")).toBe("#ef4444");
  });
});

// ── heatmapIntensity ──────────────────────────────────────────────────────────

describe("heatmapIntensity", () => {
  test("max count returns 1.0", () => {
    expect(heatmapIntensity(10, 10)).toBe(1.0);
  });

  test("zero count returns 0.0", () => {
    expect(heatmapIntensity(0, 10)).toBe(0.0);
  });

  test("half count returns 0.5", () => {
    expect(heatmapIntensity(5, 10)).toBe(0.5);
  });

  test("returns 0 when maxCount is 0", () => {
    expect(heatmapIntensity(0, 0)).toBe(0.0);
  });

  test("clamps at 1.0 even if count > maxCount", () => {
    expect(heatmapIntensity(15, 10)).toBe(1.0);
  });
});
