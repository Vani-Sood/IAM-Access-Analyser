/**
 * @jest-environment jsdom
 */
"use strict";

// shared.js uses conditional exports for testability
const {
  getToken, setToken, clearToken, isLoggedIn,
  authHeaders, getUserPayload, isAdmin,
  getRefreshToken, setRefreshToken, clearRefreshToken,
  apiFetch, _resetRefreshState, _setNavigate,
} = require("./shared.js");

// ── helpers ──────────────────────────────────────────────────────────────────

function makeJwt(payload) {
  const header  = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body    = btoa(JSON.stringify(payload));
  return `${header}.${body}.sig`;
}

// ── token storage ─────────────────────────────────────────────────────────────

describe("token storage", () => {
  beforeEach(() => localStorage.clear());

  test("getToken returns null when nothing stored", () => {
    expect(getToken()).toBeNull();
  });

  test("setToken persists token; getToken retrieves it", () => {
    setToken("abc123");
    expect(getToken()).toBe("abc123");
  });

  test("clearToken removes token", () => {
    setToken("abc123");
    clearToken();
    expect(getToken()).toBeNull();
  });

  test("isLoggedIn false when no token", () => {
    expect(isLoggedIn()).toBe(false);
  });

  test("isLoggedIn true when token present", () => {
    setToken("tok");
    expect(isLoggedIn()).toBe(true);
  });
});

// ── authHeaders ───────────────────────────────────────────────────────────────

describe("authHeaders", () => {
  beforeEach(() => localStorage.clear());

  test("returns empty object when not logged in", () => {
    expect(authHeaders()).toEqual({});
  });

  test("returns Authorization header when logged in", () => {
    setToken("mytoken");
    expect(authHeaders()).toEqual({ Authorization: "Bearer mytoken" });
  });
});

// ── getUserPayload ────────────────────────────────────────────────────────────

describe("getUserPayload", () => {
  beforeEach(() => localStorage.clear());

  test("returns null when no token", () => {
    expect(getUserPayload()).toBeNull();
  });

  test("decodes JWT payload correctly", () => {
    const payload = { sub: "42", email: "x@y.com", role: "user" };
    setToken(makeJwt(payload));
    const result = getUserPayload();
    expect(result.sub).toBe("42");
    expect(result.email).toBe("x@y.com");
  });

  test("returns null for malformed token", () => {
    setToken("not.a.jwt");
    expect(getUserPayload()).toBeNull();
  });
});

// ── refresh token storage ─────────────────────────────────────────────────────

describe("refresh token storage", () => {
  beforeEach(() => localStorage.clear());

  test("getRefreshToken returns null when nothing stored", () => {
    expect(getRefreshToken()).toBeNull();
  });

  test("setRefreshToken persists; getRefreshToken retrieves", () => {
    setRefreshToken("rt123");
    expect(getRefreshToken()).toBe("rt123");
  });

  test("clearRefreshToken removes token", () => {
    setRefreshToken("rt123");
    clearRefreshToken();
    expect(getRefreshToken()).toBeNull();
  });
});

// ── apiFetch — token refresh ──────────────────────────────────────────────────

describe("apiFetch token refresh", () => {
  beforeEach(() => {
    localStorage.clear();
    _resetRefreshState();
    jest.resetAllMocks();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test("401 triggers refresh then retries original request with new token", async () => {
    setToken("expired-access");
    setRefreshToken("valid-refresh");

    global.fetch = jest.fn(async (url, opts) => {
      if (url === "/api/v1/auth/refresh") {
        return { ok: true, status: 200, json: async () => ({ access_token: "new-access" }) };
      }
      const auth = (opts?.headers || {}).Authorization || "";
      if (auth === "Bearer expired-access") return { status: 401 };
      if (auth === "Bearer new-access")     return { status: 200, ok: true, json: async () => ({}) };
      return { status: 500 };
    });

    const resp = await apiFetch("/api/v1/analyses");
    expect(resp.status).toBe(200);
    expect(getToken()).toBe("new-access");
  });

  test("concurrent 401s trigger exactly one refresh POST", async () => {
    setToken("stale");
    setRefreshToken("refresh-tok");

    let refreshCount = 0;
    global.fetch = jest.fn(async (url, opts) => {
      if (url === "/api/v1/auth/refresh") {
        refreshCount++;
        await new Promise(r => setTimeout(r, 5));
        return { ok: true, status: 200, json: async () => ({ access_token: "fresh" }) };
      }
      const auth = (opts?.headers || {}).Authorization || "";
      if (auth === "Bearer stale") return { status: 401 };
      return { status: 200, ok: true, json: async () => ({}) };
    });

    await Promise.all(Array.from({ length: 5 }, () => apiFetch("/api/v1/analyses")));
    expect(refreshCount).toBe(1);
  });

  test("refresh failure clears tokens and redirects to /index.html", async () => {
    setToken("expired");
    setRefreshToken("bad-refresh");

    let redirected = "";
    _setNavigate((url) => { redirected = url; });

    global.fetch = jest.fn(async (url) => {
      if (url === "/api/v1/auth/refresh") return { ok: false, status: 401 };
      return { status: 401 };
    });

    const resp = await apiFetch("/api/v1/analyses");
    expect(resp).toBeNull();
    expect(getToken()).toBeNull();
    expect(getRefreshToken()).toBeNull();
    expect(redirected).toBe("/index.html");
  });
});

// ── isAdmin ───────────────────────────────────────────────────────────────────

describe("isAdmin", () => {
  beforeEach(() => localStorage.clear());

  test("false when not logged in", () => {
    expect(isAdmin()).toBe(false);
  });

  test("false for regular user", () => {
    setToken(makeJwt({ role: "user" }));
    expect(isAdmin()).toBe(false);
  });

  test("true for admin role", () => {
    setToken(makeJwt({ role: "admin" }));
    expect(isAdmin()).toBe(true);
  });
});
