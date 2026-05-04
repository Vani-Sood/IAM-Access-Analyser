/**
 * @jest-environment jsdom
 */
"use strict";

const {
  validateJson,
  buildJsonPayload,
  buildLivePayload,
  getActiveTab,
} = require("./analyze.js");

// ── validateJson ──────────────────────────────────────────────────────────────

describe("validateJson", () => {
  test("parses valid IAM policy JSON", () => {
    const result = validateJson('{"Version":"2012-10-17","Statement":[]}');
    expect(result).toEqual({ Version: "2012-10-17", Statement: [] });
  });

  test("throws on empty string", () => {
    expect(() => validateJson("")).toThrow("Policy JSON is required");
  });

  test("throws on whitespace-only string", () => {
    expect(() => validateJson("   ")).toThrow("Policy JSON is required");
  });

  test("throws on invalid JSON", () => {
    expect(() => validateJson("{not valid}")).toThrow("Invalid JSON");
  });

  test("unwraps {policy: ...} wrapper format", () => {
    const inner = { Version: "2012-10-17", Statement: [] };
    const wrapped = JSON.stringify({ policy: inner });
    expect(validateJson(wrapped)).toEqual(inner);
  });

  test("does not unwrap when Statement key present", () => {
    const policy = { policy: "x", Statement: [], Version: "2012-10-17" };
    const result = validateJson(JSON.stringify(policy));
    expect(result).toEqual(policy);
  });

  test("does not unwrap when Version key present", () => {
    const policy = { policy: "x", Version: "2012-10-17" };
    const result = validateJson(JSON.stringify(policy));
    expect(result).toEqual(policy);
  });

  test("parses policy with statements array", () => {
    const policy = {
      Version: "2012-10-17",
      Statement: [{ Effect: "Allow", Action: "s3:*", Resource: "*" }],
    };
    expect(validateJson(JSON.stringify(policy))).toEqual(policy);
  });
});

// ── buildJsonPayload ──────────────────────────────────────────────────────────

describe("buildJsonPayload", () => {
  const policy = { Version: "2012-10-17", Statement: [] };

  test("returns mode json payload for aws", () => {
    expect(buildJsonPayload(policy, "aws")).toEqual({
      mode: "json",
      cloud: "aws",
      policy,
    });
  });

  test("returns mode json payload for azure", () => {
    const result = buildJsonPayload(policy, "azure");
    expect(result.mode).toBe("json");
    expect(result.cloud).toBe("azure");
    expect(result.policy).toBe(policy);
  });

  test("returns mode json payload for gcp", () => {
    const result = buildJsonPayload(policy, "gcp");
    expect(result.mode).toBe("json");
    expect(result.cloud).toBe("gcp");
  });

  test("does not mutate the policy object", () => {
    const original = { Version: "2012-10-17", Statement: [] };
    const copy = { ...original };
    buildJsonPayload(original, "aws");
    expect(original).toEqual(copy);
  });
});

// ── buildLivePayload ──────────────────────────────────────────────────────────

describe("buildLivePayload", () => {
  test("returns live mode payload for aws", () => {
    expect(buildLivePayload("aws")).toEqual({ mode: "live", cloud: "aws" });
  });

  test("returns live mode payload for azure", () => {
    expect(buildLivePayload("azure")).toEqual({ mode: "live", cloud: "azure" });
  });

  test("returns live mode payload for gcp", () => {
    expect(buildLivePayload("gcp")).toEqual({ mode: "live", cloud: "gcp" });
  });
});

// ── getActiveTab ──────────────────────────────────────────────────────────────

describe("getActiveTab", () => {
  test("returns json for #json hash", () => {
    expect(getActiveTab("#json")).toBe("json");
  });

  test("returns live for #live hash", () => {
    expect(getActiveTab("#live")).toBe("live");
  });

  test("returns json as default for empty string", () => {
    expect(getActiveTab("")).toBe("json");
  });

  test("returns json as default for unknown hash", () => {
    expect(getActiveTab("#unknown")).toBe("json");
  });

  test("returns json as default for null/undefined", () => {
    expect(getActiveTab(null)).toBe("json");
    expect(getActiveTab(undefined)).toBe("json");
  });
});
