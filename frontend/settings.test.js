/**
 * @jest-environment jsdom
 */
"use strict";

const {
  validateApiKeyName,
  validateApiKeyScope,
  validateWebhookUrl,
  validateWebhookEvents,
  validateNewPassword,
  validatePasswordMatch,
  buildApiKeyPayload,
  buildWebhookPayload,
  maskKey,
} = require("./settings.js");

// ── validateApiKeyName ────────────────────────────────────────────────────────

describe("validateApiKeyName", () => {
  test("returns trimmed name for valid input", () => {
    expect(validateApiKeyName("My Key")).toBe("My Key");
  });

  test("trims surrounding whitespace", () => {
    expect(validateApiKeyName("  CI Key  ")).toBe("CI Key");
  });

  test("throws on empty string", () => {
    expect(() => validateApiKeyName("")).toThrow("name must not be blank");
  });

  test("throws on whitespace-only string", () => {
    expect(() => validateApiKeyName("   ")).toThrow("name must not be blank");
  });
});

// ── validateApiKeyScope ───────────────────────────────────────────────────────

describe("validateApiKeyScope", () => {
  test("accepts read scope", () => {
    expect(validateApiKeyScope("read")).toBe("read");
  });

  test("accepts readwrite scope", () => {
    expect(validateApiKeyScope("readwrite")).toBe("readwrite");
  });

  test("accepts admin scope", () => {
    expect(validateApiKeyScope("admin")).toBe("admin");
  });

  test("throws on unknown scope", () => {
    expect(() => validateApiKeyScope("write")).toThrow("scope must be");
  });

  test("throws on empty string", () => {
    expect(() => validateApiKeyScope("")).toThrow("scope must be");
  });

  test("throws on uppercase READ", () => {
    expect(() => validateApiKeyScope("READ")).toThrow("scope must be");
  });
});

// ── validateWebhookUrl ────────────────────────────────────────────────────────

describe("validateWebhookUrl", () => {
  test("accepts https url", () => {
    expect(validateWebhookUrl("https://example.com/hook")).toBe("https://example.com/hook");
  });

  test("trims whitespace", () => {
    expect(validateWebhookUrl("  https://example.com/hook  "))
      .toBe("https://example.com/hook");
  });

  test("throws on http url", () => {
    expect(() => validateWebhookUrl("http://example.com/hook"))
      .toThrow("HTTPS");
  });

  test("throws on empty string", () => {
    expect(() => validateWebhookUrl("")).toThrow("HTTPS");
  });

  test("throws on non-url string", () => {
    expect(() => validateWebhookUrl("not a url")).toThrow("HTTPS");
  });

  test("throws on ftp url", () => {
    expect(() => validateWebhookUrl("ftp://example.com/hook")).toThrow("HTTPS");
  });
});

// ── validateWebhookEvents ─────────────────────────────────────────────────────

describe("validateWebhookEvents", () => {
  test("accepts analysis.complete", () => {
    expect(validateWebhookEvents(["analysis.complete"]))
      .toEqual(["analysis.complete"]);
  });

  test("accepts multiple valid events", () => {
    const events = ["analysis.complete", "privesc.detected"];
    expect(validateWebhookEvents(events)).toEqual(events);
  });

  test("accepts all three valid events", () => {
    const events = ["analysis.complete", "privesc.detected", "compliance.failed"];
    expect(validateWebhookEvents(events)).toEqual(events);
  });

  test("throws on empty array", () => {
    expect(() => validateWebhookEvents([])).toThrow("At least one event");
  });

  test("throws on unknown event", () => {
    expect(() => validateWebhookEvents(["unknown.event"])).toThrow("Invalid event");
  });

  test("throws when one event is invalid", () => {
    expect(() => validateWebhookEvents(["analysis.complete", "bad.event"]))
      .toThrow("Invalid event");
  });
});

// ── validateNewPassword ───────────────────────────────────────────────────────

describe("validateNewPassword", () => {
  test("accepts valid password", () => {
    expect(validateNewPassword("Secure123")).toBe("Secure123");
  });

  test("accepts password with special chars", () => {
    expect(validateNewPassword("P@ssword1")).toBe("P@ssword1");
  });

  test("throws on too short (under 8 chars)", () => {
    expect(() => validateNewPassword("Ab1")).toThrow("8");
  });

  test("throws on missing uppercase", () => {
    expect(() => validateNewPassword("password1")).toThrow("uppercase");
  });

  test("throws on missing digit", () => {
    expect(() => validateNewPassword("Password")).toThrow("digit");
  });

  test("throws on empty string", () => {
    expect(() => validateNewPassword("")).toThrow("8");
  });

  test("accepts exactly 8 chars with requirements", () => {
    expect(validateNewPassword("Abcde12!")).toBe("Abcde12!");
  });
});

// ── validatePasswordMatch ─────────────────────────────────────────────────────

describe("validatePasswordMatch", () => {
  test("returns password when both match", () => {
    expect(validatePasswordMatch("Secure123", "Secure123")).toBe("Secure123");
  });

  test("throws when passwords differ", () => {
    expect(() => validatePasswordMatch("Secure123", "Different1"))
      .toThrow("do not match");
  });

  test("throws on empty confirm", () => {
    expect(() => validatePasswordMatch("Secure123", ""))
      .toThrow("do not match");
  });
});

// ── buildApiKeyPayload ────────────────────────────────────────────────────────

describe("buildApiKeyPayload", () => {
  test("builds correct payload", () => {
    expect(buildApiKeyPayload("CI Key", "read"))
      .toEqual({ name: "CI Key", scope: "read" });
  });

  test("builds admin scope payload", () => {
    const result = buildApiKeyPayload("Admin", "admin");
    expect(result.scope).toBe("admin");
    expect(result.name).toBe("Admin");
  });
});

// ── buildWebhookPayload ───────────────────────────────────────────────────────

describe("buildWebhookPayload", () => {
  test("builds payload with url and events", () => {
    expect(buildWebhookPayload("https://example.com/hook", ["analysis.complete"]))
      .toEqual({ url: "https://example.com/hook", events: ["analysis.complete"] });
  });

  test("includes multiple events", () => {
    const events = ["analysis.complete", "privesc.detected"];
    const result = buildWebhookPayload("https://example.com/wh", events);
    expect(result.events).toHaveLength(2);
  });
});

// ── maskKey ───────────────────────────────────────────────────────────────────

describe("maskKey", () => {
  test("appends mask to prefix", () => {
    expect(maskKey("vani_abc12345")).toBe("vani_abc12345••••••••");
  });

  test("appends mask to any prefix string", () => {
    expect(maskKey("vani_xy")).toBe("vani_xy••••••••");
  });

  test("handles empty prefix", () => {
    expect(maskKey("")).toBe("••••••••");
  });
});
