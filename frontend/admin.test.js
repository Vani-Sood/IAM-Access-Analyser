/**
 * @jest-environment jsdom
 */
"use strict";

const {
  buildAuditUrl,
  formatPayload,
  truncateAuditHash,
  auditTotalPages,
  auditCalcOffset,
  auditGetPage,
} = require("./admin.js");

// ── buildAuditUrl ─────────────────────────────────────────────────────────────

describe("buildAuditUrl", () => {
  test("builds url without event type filter", () => {
    expect(buildAuditUrl(50, 0, null))
      .toBe("/api/v1/admin/audit-log?limit=50&offset=0");
  });

  test("builds url with event type filter", () => {
    expect(buildAuditUrl(50, 0, "org.create"))
      .toBe("/api/v1/admin/audit-log?limit=50&offset=0&event_type=org.create");
  });

  test("builds url with pagination offset", () => {
    expect(buildAuditUrl(50, 50, null))
      .toBe("/api/v1/admin/audit-log?limit=50&offset=50");
  });

  test("builds url with event type and offset", () => {
    expect(buildAuditUrl(20, 40, "analysis.complete"))
      .toBe("/api/v1/admin/audit-log?limit=20&offset=40&event_type=analysis.complete");
  });

  test("omits event_type when undefined", () => {
    expect(buildAuditUrl(50, 0, undefined))
      .toBe("/api/v1/admin/audit-log?limit=50&offset=0");
  });

  test("omits event_type when empty string", () => {
    expect(buildAuditUrl(50, 0, ""))
      .toBe("/api/v1/admin/audit-log?limit=50&offset=0");
  });
});

// ── formatPayload ─────────────────────────────────────────────────────────────

describe("formatPayload", () => {
  test("formats simple object as compact JSON", () => {
    expect(formatPayload({ org_id: 1 })).toBe('{"org_id":1}');
  });

  test("formats nested object", () => {
    const payload = { org_id: 2, slug: "acme" };
    expect(formatPayload(payload)).toBe('{"org_id":2,"slug":"acme"}');
  });

  test("returns empty braces for empty object", () => {
    expect(formatPayload({})).toBe("{}");
  });

  test("returns string for null input", () => {
    expect(formatPayload(null)).toBe("null");
  });
});

// ── truncateAuditHash ─────────────────────────────────────────────────────────

describe("truncateAuditHash", () => {
  test("truncates long sha256 hash to 12 chars", () => {
    const hash = "a".repeat(64);
    expect(truncateAuditHash(hash)).toBe("a".repeat(12) + "…");
  });

  test("returns full string when 12 chars or fewer", () => {
    expect(truncateAuditHash("abc123")).toBe("abc123");
  });

  test("handles empty string", () => {
    expect(truncateAuditHash("")).toBe("");
  });

  test("returns exactly 13 chars for hash longer than 12", () => {
    const hash = "0123456789abcdef";
    const result = truncateAuditHash(hash);
    expect(result).toBe("0123456789ab…");
    expect(result.length).toBe(13);
  });
});

// ── auditTotalPages ───────────────────────────────────────────────────────────

describe("auditTotalPages", () => {
  test("returns 0 for empty result", () => {
    expect(auditTotalPages(0, 50)).toBe(0);
  });

  test("returns 1 when total <= limit", () => {
    expect(auditTotalPages(50, 50)).toBe(1);
    expect(auditTotalPages(30, 50)).toBe(1);
  });

  test("rounds up partial page", () => {
    expect(auditTotalPages(51, 50)).toBe(2);
  });

  test("handles large dataset", () => {
    expect(auditTotalPages(500, 50)).toBe(10);
  });
});

// ── auditCalcOffset ───────────────────────────────────────────────────────────

describe("auditCalcOffset", () => {
  test("page 1 returns 0", () => {
    expect(auditCalcOffset(1, 50)).toBe(0);
  });

  test("page 2 returns 50", () => {
    expect(auditCalcOffset(2, 50)).toBe(50);
  });

  test("page 3 returns 100", () => {
    expect(auditCalcOffset(3, 50)).toBe(100);
  });
});

// ── auditGetPage ──────────────────────────────────────────────────────────────

describe("auditGetPage", () => {
  test("parses page from search string", () => {
    expect(auditGetPage("?page=3")).toBe(3);
  });

  test("returns 1 for empty string", () => {
    expect(auditGetPage("")).toBe(1);
  });

  test("returns 1 for null", () => {
    expect(auditGetPage(null)).toBe(1);
  });

  test("returns 1 for page=0", () => {
    expect(auditGetPage("?page=0")).toBe(1);
  });

  test("returns 1 for non-numeric page", () => {
    expect(auditGetPage("?page=abc")).toBe(1);
  });
});
