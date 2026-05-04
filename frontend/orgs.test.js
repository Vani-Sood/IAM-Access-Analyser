/**
 * @jest-environment jsdom
 */
"use strict";

const {
  validateOrgName,
  validateSlug,
  validateRole,
  validateEmail,
  buildMemberAddPayload,
  getRoleRank,
  canManageMembers,
  canRemoveMember,
} = require("./orgs.js");

// ── validateOrgName ───────────────────────────────────────────────────────────

describe("validateOrgName", () => {
  test("returns trimmed name for valid input", () => {
    expect(validateOrgName("My Org")).toBe("My Org");
  });

  test("trims surrounding whitespace", () => {
    expect(validateOrgName("  Acme  ")).toBe("Acme");
  });

  test("throws on empty string", () => {
    expect(() => validateOrgName("")).toThrow("name must not be blank");
  });

  test("throws on whitespace-only string", () => {
    expect(() => validateOrgName("   ")).toThrow("name must not be blank");
  });

  test("accepts single character name", () => {
    expect(validateOrgName("A")).toBe("A");
  });
});

// ── validateSlug ──────────────────────────────────────────────────────────────

describe("validateSlug", () => {
  test("accepts lowercase alphanumeric", () => {
    expect(validateSlug("myorg")).toBe("myorg");
  });

  test("accepts hyphen-separated slug", () => {
    expect(validateSlug("my-org")).toBe("my-org");
  });

  test("accepts numbers", () => {
    expect(validateSlug("org123")).toBe("org123");
  });

  test("accepts complex valid slug", () => {
    expect(validateSlug("acme-corp-2024")).toBe("acme-corp-2024");
  });

  test("throws on uppercase letters", () => {
    expect(() => validateSlug("MyOrg")).toThrow("slug must be");
  });

  test("throws on leading hyphen", () => {
    expect(() => validateSlug("-myorg")).toThrow("slug must be");
  });

  test("throws on trailing hyphen", () => {
    expect(() => validateSlug("myorg-")).toThrow("slug must be");
  });

  test("throws on spaces", () => {
    expect(() => validateSlug("my org")).toThrow("slug must be");
  });

  test("throws on empty string", () => {
    expect(() => validateSlug("")).toThrow("slug must be");
  });

  test("throws on double hyphen", () => {
    expect(() => validateSlug("my--org")).toThrow("slug must be");
  });
});

// ── validateRole ──────────────────────────────────────────────────────────────

describe("validateRole", () => {
  test("accepts owner", () => {
    expect(validateRole("owner")).toBe("owner");
  });

  test("accepts admin", () => {
    expect(validateRole("admin")).toBe("admin");
  });

  test("accepts member", () => {
    expect(validateRole("member")).toBe("member");
  });

  test("throws on unknown role", () => {
    expect(() => validateRole("superuser")).toThrow("role must be");
  });

  test("throws on empty string", () => {
    expect(() => validateRole("")).toThrow("role must be");
  });

  test("throws on uppercase MEMBER", () => {
    expect(() => validateRole("MEMBER")).toThrow("role must be");
  });
});

// ── validateEmail ─────────────────────────────────────────────────────────────

describe("validateEmail", () => {
  test("accepts standard email", () => {
    expect(validateEmail("user@example.com")).toBe("user@example.com");
  });

  test("accepts email with subdomain", () => {
    expect(validateEmail("alice@mail.example.org")).toBe("alice@mail.example.org");
  });

  test("trims whitespace", () => {
    expect(validateEmail("  user@example.com  ")).toBe("user@example.com");
  });

  test("throws on missing @", () => {
    expect(() => validateEmail("notanemail")).toThrow("valid email");
  });

  test("throws on missing domain", () => {
    expect(() => validateEmail("user@")).toThrow("valid email");
  });

  test("throws on empty string", () => {
    expect(() => validateEmail("")).toThrow("valid email");
  });
});

// ── buildMemberAddPayload ─────────────────────────────────────────────────────

describe("buildMemberAddPayload", () => {
  test("builds payload with email and role", () => {
    expect(buildMemberAddPayload("user@example.com", "member"))
      .toEqual({ email: "user@example.com", role: "member" });
  });

  test("builds payload with admin role", () => {
    const result = buildMemberAddPayload("admin@example.com", "admin");
    expect(result.role).toBe("admin");
    expect(result.email).toBe("admin@example.com");
  });
});

// ── getRoleRank ───────────────────────────────────────────────────────────────

describe("getRoleRank", () => {
  test("owner has rank 3", () => {
    expect(getRoleRank("owner")).toBe(3);
  });

  test("admin has rank 2", () => {
    expect(getRoleRank("admin")).toBe(2);
  });

  test("member has rank 1", () => {
    expect(getRoleRank("member")).toBe(1);
  });

  test("unknown role has rank 0", () => {
    expect(getRoleRank("unknown")).toBe(0);
  });

  test("empty string has rank 0", () => {
    expect(getRoleRank("")).toBe(0);
  });
});

// ── canManageMembers ──────────────────────────────────────────────────────────

describe("canManageMembers", () => {
  test("owner can manage members", () => {
    expect(canManageMembers("owner")).toBe(true);
  });

  test("admin can manage members", () => {
    expect(canManageMembers("admin")).toBe(true);
  });

  test("member cannot manage members", () => {
    expect(canManageMembers("member")).toBe(false);
  });

  test("unknown role cannot manage members", () => {
    expect(canManageMembers("viewer")).toBe(false);
  });
});

// ── canRemoveMember ───────────────────────────────────────────────────────────

describe("canRemoveMember", () => {
  test("owner can remove regular member", () => {
    expect(canRemoveMember("owner", "member", 1)).toBe(true);
  });

  test("owner can remove admin", () => {
    expect(canRemoveMember("owner", "admin", 1)).toBe(true);
  });

  test("owner cannot remove last owner", () => {
    expect(canRemoveMember("owner", "owner", 1)).toBe(false);
  });

  test("owner can remove owner when more than one owner", () => {
    expect(canRemoveMember("owner", "owner", 2)).toBe(true);
  });

  test("admin cannot remove anyone (not owner)", () => {
    expect(canRemoveMember("admin", "member", 3)).toBe(false);
  });

  test("member cannot remove anyone", () => {
    expect(canRemoveMember("member", "member", 3)).toBe(false);
  });
});
