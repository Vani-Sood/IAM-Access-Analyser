/**
 * @jest-environment jsdom
 */
"use strict";

const {
  getAnalysisId,
  formatRiskScore,
  getSeverityClass,
  getBadgeClass,
  escapeHtml,
  getRiskColor,
  buildComplianceUrl,
  buildReportUrl,
  buildInheritanceUrl,
  buildNodeOptions,
  renderInheritanceResult,
  renderInheritanceEmpty,
} = require("./analysis.js");

// ── getAnalysisId ─────────────────────────────────────────────────────────────

describe("getAnalysisId", () => {
  test("parses numeric id from query string", () => {
    expect(getAnalysisId("?id=42")).toBe(42);
  });

  test("parses id=1", () => {
    expect(getAnalysisId("?id=1")).toBe(1);
  });

  test("parses id with other params present", () => {
    expect(getAnalysisId("?foo=bar&id=99&baz=1")).toBe(99);
  });

  test("returns null for empty string", () => {
    expect(getAnalysisId("")).toBeNull();
  });

  test("returns null when no id param", () => {
    expect(getAnalysisId("?foo=bar")).toBeNull();
  });

  test("returns null for non-numeric id", () => {
    expect(getAnalysisId("?id=abc")).toBeNull();
  });

  test("returns null for id=0", () => {
    expect(getAnalysisId("?id=0")).toBeNull();
  });

  test("returns null for null input", () => {
    expect(getAnalysisId(null)).toBeNull();
  });
});

// ── formatRiskScore ───────────────────────────────────────────────────────────

describe("formatRiskScore", () => {
  test("formats decimal to 1 place", () => {
    expect(formatRiskScore(7.532)).toBe("7.5");
  });

  test("formats integer to 1 decimal place", () => {
    expect(formatRiskScore(10)).toBe("10.0");
  });

  test("formats zero", () => {
    expect(formatRiskScore(0)).toBe("0.0");
  });

  test("rounds correctly", () => {
    expect(formatRiskScore(8.96)).toBe("9.0");
  });

  test("formats low score", () => {
    expect(formatRiskScore(1.23)).toBe("1.2");
  });
});

// ── getSeverityClass ──────────────────────────────────────────────────────────

describe("getSeverityClass", () => {
  test("CRITICAL returns risk-critical", () => {
    expect(getSeverityClass("CRITICAL")).toBe("risk-critical");
  });

  test("HIGH returns risk-high", () => {
    expect(getSeverityClass("HIGH")).toBe("risk-high");
  });

  test("MEDIUM returns risk-medium", () => {
    expect(getSeverityClass("MEDIUM")).toBe("risk-medium");
  });

  test("LOW returns risk-low", () => {
    expect(getSeverityClass("LOW")).toBe("risk-low");
  });

  test("unknown severity returns risk-low fallback", () => {
    expect(getSeverityClass("UNKNOWN")).toBe("risk-low");
  });

  test("empty string returns risk-low fallback", () => {
    expect(getSeverityClass("")).toBe("risk-low");
  });
});

// ── getBadgeClass ─────────────────────────────────────────────────────────────

describe("getBadgeClass", () => {
  test("CRITICAL returns badge-critical", () => {
    expect(getBadgeClass("CRITICAL")).toBe("badge-critical");
  });

  test("HIGH returns badge-high", () => {
    expect(getBadgeClass("HIGH")).toBe("badge-high");
  });

  test("MEDIUM returns badge-medium", () => {
    expect(getBadgeClass("MEDIUM")).toBe("badge-medium");
  });

  test("LOW returns badge-low", () => {
    expect(getBadgeClass("LOW")).toBe("badge-low");
  });

  test("unknown severity returns empty string", () => {
    expect(getBadgeClass("UNKNOWN")).toBe("");
  });
});

// ── escapeHtml ────────────────────────────────────────────────────────────────

describe("escapeHtml", () => {
  test("escapes ampersand", () => {
    expect(escapeHtml("a & b")).toBe("a &amp; b");
  });

  test("escapes less-than", () => {
    expect(escapeHtml("<script>")).toBe("&lt;script&gt;");
  });

  test("escapes quotes", () => {
    expect(escapeHtml('"hello"')).toBe("&quot;hello&quot;");
  });

  test("escapes single quotes", () => {
    expect(escapeHtml("it's")).toBe("it&#x27;s");
  });

  test("returns plain string unchanged", () => {
    expect(escapeHtml("hello world")).toBe("hello world");
  });

  test("coerces non-string to string first", () => {
    expect(escapeHtml(42)).toBe("42");
  });

  test("handles empty string", () => {
    expect(escapeHtml("")).toBe("");
  });
});

// ── getRiskColor ──────────────────────────────────────────────────────────────

describe("getRiskColor", () => {
  test("score >= 8.0 returns critical red", () => {
    expect(getRiskColor(8.0)).toBe("#ef4444");
    expect(getRiskColor(9.9)).toBe("#ef4444");
    expect(getRiskColor(10)).toBe("#ef4444");
  });

  test("score >= 6.0 returns high amber", () => {
    expect(getRiskColor(6.0)).toBe("#f59e0b");
    expect(getRiskColor(7.9)).toBe("#f59e0b");
  });

  test("score >= 4.0 returns medium ochre", () => {
    expect(getRiskColor(4.0)).toBe("#e8b94a");
    expect(getRiskColor(5.9)).toBe("#e8b94a");
  });

  test("score < 4.0 returns low green", () => {
    expect(getRiskColor(3.9)).toBe("#22c55e");
    expect(getRiskColor(0)).toBe("#22c55e");
  });
});

// ── buildComplianceUrl ────────────────────────────────────────────────────────

describe("buildComplianceUrl", () => {
  test("builds url without format", () => {
    expect(buildComplianceUrl(42, "cis", null))
      .toBe("/api/v1/analyses/42/compliance?framework=cis");
  });

  test("builds url with xlsx format", () => {
    expect(buildComplianceUrl(42, "cis", "xlsx"))
      .toBe("/api/v1/analyses/42/compliance?framework=cis&format=xlsx");
  });

  test("builds url with json format", () => {
    expect(buildComplianceUrl(99, "nist", "json"))
      .toBe("/api/v1/analyses/99/compliance?framework=nist&format=json");
  });

  test("omits format when undefined", () => {
    expect(buildComplianceUrl(1, "soc2", undefined))
      .toBe("/api/v1/analyses/1/compliance?framework=soc2");
  });

  test("supports all three frameworks", () => {
    expect(buildComplianceUrl(1, "cis",  null)).toContain("framework=cis");
    expect(buildComplianceUrl(1, "nist", null)).toContain("framework=nist");
    expect(buildComplianceUrl(1, "soc2", null)).toContain("framework=soc2");
  });
});

// ── buildReportUrl ────────────────────────────────────────────────────────────

describe("buildReportUrl", () => {
  test("builds pdf report url", () => {
    expect(buildReportUrl(42, "pdf"))
      .toBe("/api/v1/analyses/42/report?format=pdf");
  });

  test("builds json report url", () => {
    expect(buildReportUrl(7, "json"))
      .toBe("/api/v1/analyses/7/report?format=json");
  });
});

// ── buildInheritanceUrl ───────────────────────────────────────────────────────

describe("buildInheritanceUrl", () => {
  test("query-param shape with simple node ids", () => {
    expect(buildInheritanceUrl(42, "node_a", "node_b"))
      .toBe("/api/v1/analyses/42/inheritance?from_node=node_a&to_node=node_b");
  });

  test("encodes special characters in node ids", () => {
    const url = buildInheritanceUrl(1, "arn:aws/role", "s3:::bucket/*");
    expect(url).toContain("from_node=arn%3Aaws%2Frole");
    expect(url).toContain("to_node=s3%3A%3A%3Abucket%2F*");
  });
});

// ── buildNodeOptions ──────────────────────────────────────────────────────────

describe("buildNodeOptions", () => {
  const nodes = [
    { id: "p1", label: "Admin Policy",  node_type: "policy" },
    { id: "a1", label: "s3:GetObject",  node_type: "action" },
    { id: "r1", label: "s3 bucket",     node_type: "resource" },
    { id: "pr1", label: "arn:role/Dev", node_type: "principal" },
  ];

  test("filters nodes to requested types only", () => {
    const result = buildNodeOptions(nodes, ["policy", "resource"]);
    expect(result).toHaveLength(2);
    expect(result.map(n => n.id)).toEqual(["p1", "r1"]);
  });

  test("returns empty array when no nodes match type", () => {
    const result = buildNodeOptions(nodes, ["statement"]);
    expect(result).toHaveLength(0);
  });

  test("returns all nodes when all types requested", () => {
    const result = buildNodeOptions(nodes, [
      "policy", "action", "resource", "principal",
    ]);
    expect(result).toHaveLength(4);
  });
});

// ── renderInheritanceResult ───────────────────────────────────────────────────

describe("renderInheritanceResult", () => {
  const data = {
    analysis_id: 1,
    from_node: "arn:aws:iam::123:role/Admin",
    to_node: "arn:aws:s3:::bucket/*",
    lca_node_id: "stmt_0",
    lca_node_type: "statement",
    lca_label: "Admin Policy Stmt 0",
  };

  test("renders LCA label and node type in chain output", () => {
    const html = renderInheritanceResult(data);
    expect(html).toContain("Admin Policy Stmt 0");
    expect(html).toContain("statement");
  });

  test("renders from_node and to_node in chain display", () => {
    const html = renderInheritanceResult(data);
    expect(html).toContain("arn:aws:iam::123:role/Admin");
    expect(html).toContain("arn:aws:s3:::bucket/*");
  });

  test("escapes html in lca_label to prevent XSS", () => {
    const malicious = { ...data, lca_label: '<script>alert(1)</script>' };
    const html = renderInheritanceResult(malicious);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });
});

// ── renderInheritanceEmpty ────────────────────────────────────────────────────

describe("renderInheritanceEmpty", () => {
  test("returns non-empty html string for 404 empty state", () => {
    const html = renderInheritanceEmpty();
    expect(typeof html).toBe("string");
    expect(html.length).toBeGreaterThan(0);
    expect(html).toContain("No common ancestor");
  });
});
