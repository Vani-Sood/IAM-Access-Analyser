/**
 * @jest-environment jsdom
 */
"use strict";

const {
  buildHistoryUrl,
  totalPages,
  calcOffset,
  getPageFromSearch,
  matchesSeverityFilter,
  truncateHash,
} = require("./history.js");

// ── buildHistoryUrl ───────────────────────────────────────────────────────────

describe("buildHistoryUrl", () => {
  test("builds url with limit and offset", () => {
    expect(buildHistoryUrl(20, 0))
      .toBe("/api/v1/analyses?limit=20&offset=0");
  });

  test("builds url for second page", () => {
    expect(buildHistoryUrl(20, 20))
      .toBe("/api/v1/analyses?limit=20&offset=20");
  });

  test("builds url with custom limit", () => {
    expect(buildHistoryUrl(10, 30))
      .toBe("/api/v1/analyses?limit=10&offset=30");
  });

  test("offset of 0 is included", () => {
    expect(buildHistoryUrl(50, 0)).toContain("offset=0");
  });
});

// ── totalPages ────────────────────────────────────────────────────────────────

describe("totalPages", () => {
  test("exact multiple", () => {
    expect(totalPages(40, 20)).toBe(2);
  });

  test("rounds up partial page", () => {
    expect(totalPages(41, 20)).toBe(3);
  });

  test("single item", () => {
    expect(totalPages(1, 20)).toBe(1);
  });

  test("exactly one page", () => {
    expect(totalPages(20, 20)).toBe(1);
  });

  test("zero items returns 0", () => {
    expect(totalPages(0, 20)).toBe(0);
  });

  test("large dataset", () => {
    expect(totalPages(1000, 20)).toBe(50);
  });
});

// ── calcOffset ────────────────────────────────────────────────────────────────

describe("calcOffset", () => {
  test("page 1 returns 0", () => {
    expect(calcOffset(1, 20)).toBe(0);
  });

  test("page 2 returns limit", () => {
    expect(calcOffset(2, 20)).toBe(20);
  });

  test("page 3 returns 2 * limit", () => {
    expect(calcOffset(3, 20)).toBe(40);
  });

  test("works with limit 10", () => {
    expect(calcOffset(4, 10)).toBe(30);
  });
});

// ── getPageFromSearch ─────────────────────────────────────────────────────────

describe("getPageFromSearch", () => {
  test("parses page 1", () => {
    expect(getPageFromSearch("?page=1")).toBe(1);
  });

  test("parses page 5", () => {
    expect(getPageFromSearch("?page=5")).toBe(5);
  });

  test("returns 1 when no page param", () => {
    expect(getPageFromSearch("")).toBe(1);
  });

  test("returns 1 for null input", () => {
    expect(getPageFromSearch(null)).toBe(1);
  });

  test("returns 1 for page=0 (invalid)", () => {
    expect(getPageFromSearch("?page=0")).toBe(1);
  });

  test("returns 1 for non-numeric page", () => {
    expect(getPageFromSearch("?page=abc")).toBe(1);
  });

  test("parses page alongside other params", () => {
    expect(getPageFromSearch("?severity=HIGH&page=3")).toBe(3);
  });
});

// ── matchesSeverityFilter ─────────────────────────────────────────────────────

describe("matchesSeverityFilter", () => {
  const highItem     = { severity: "HIGH",     risk_score: 7.0 };
  const criticalItem = { severity: "CRITICAL", risk_score: 9.0 };
  const lowItem      = { severity: "LOW",      risk_score: 1.5 };

  test("empty filter matches all", () => {
    expect(matchesSeverityFilter(highItem,     "")).toBe(true);
    expect(matchesSeverityFilter(criticalItem, "")).toBe(true);
    expect(matchesSeverityFilter(lowItem,      "")).toBe(true);
  });

  test("HIGH filter matches HIGH item", () => {
    expect(matchesSeverityFilter(highItem, "HIGH")).toBe(true);
  });

  test("HIGH filter excludes CRITICAL item", () => {
    expect(matchesSeverityFilter(criticalItem, "HIGH")).toBe(false);
  });

  test("CRITICAL filter matches CRITICAL item", () => {
    expect(matchesSeverityFilter(criticalItem, "CRITICAL")).toBe(true);
  });

  test("LOW filter matches LOW item", () => {
    expect(matchesSeverityFilter(lowItem, "LOW")).toBe(true);
  });

  test("MEDIUM filter excludes HIGH item", () => {
    expect(matchesSeverityFilter(highItem, "MEDIUM")).toBe(false);
  });
});

// ── truncateHash ──────────────────────────────────────────────────────────────

describe("truncateHash", () => {
  test("returns full hash when shorter than max", () => {
    expect(truncateHash("abc123", 10)).toBe("abc123");
  });

  test("truncates long hash and appends ellipsis", () => {
    const hash = "abcdef1234567890abcdef";
    expect(truncateHash(hash, 8)).toBe("abcdef12…");
  });

  test("exact length returns full string", () => {
    expect(truncateHash("abcdef12", 8)).toBe("abcdef12");
  });

  test("handles empty string", () => {
    expect(truncateHash("", 8)).toBe("");
  });

  test("default max is 12 chars", () => {
    const hash = "0123456789abcdef";
    expect(truncateHash(hash)).toBe("0123456789ab…");
  });
});
