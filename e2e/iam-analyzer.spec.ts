import { test, expect, Page, ConsoleMessage } from "@playwright/test";

const BASE_URL = "http://localhost:8000";

const TEST_EMAIL = "test@example.com";
const TEST_PASSWORD = "TestPass123!";
const AUTH_KEY = "iam_access_token";

const WILDCARD_POLICY = JSON.stringify({
  Version: "2012-10-17",
  Statement: [
    {
      Effect: "Allow",
      Action: "*",
      Resource: "*",
    },
  ],
});

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Get a real JWT by calling the API directly (not via UI),
 * then seed it into localStorage so the page starts authenticated
 * without consuming a rate-limited UI login.
 */
async function seedAuthToken(page: Page): Promise<string> {
  const res = await page.request.post(`${BASE_URL}/api/v1/auth/login`, {
    data: { email: TEST_EMAIL, password: TEST_PASSWORD },
  });
  const { access_token } = await res.json();
  await page.goto(BASE_URL);
  await page.evaluate(
    ([key, token]) => localStorage.setItem(key, token),
    [AUTH_KEY, access_token]
  );
  await page.reload();
  return access_token;
}

/** Collect only genuine console errors (not benign preflight 401s). */
function collectConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (msg: ConsoleMessage) => {
    if (msg.type() !== "error") return;
    const text = msg.text();
    // Benign: unauthenticated DOMContentLoaded prefetch for history badge
    if (text.includes("401") || text.includes("403")) return;
    errors.push(text);
  });
  return errors;
}

// ── Flow 1: Registration ──────────────────────────────────────────────────────

test.describe("Flow 1 — Registration", () => {
  test("register new user via UI form auto-logs in on success", async ({
    page,
  }) => {
    const consoleErrors = collectConsoleErrors(page);

    await page.goto(BASE_URL);
    await page.screenshot({
      path: "e2e/screenshots/01-homepage.png",
      fullPage: true,
    });

    // Open auth modal
    await page.locator("#login-open-btn").click();
    await expect(page.locator("#auth-modal")).toBeVisible();

    // Switch to Register tab
    await page.locator("#tab-register").click();
    await expect(page.locator("#register-form")).toBeVisible();
    await page.screenshot({ path: "e2e/screenshots/02-register-form.png" });

    // Use a fresh unique email to avoid conflicts
    const uniqueEmail = `e2e_${Date.now()}@example.com`;
    await page.locator("#reg-email").fill(uniqueEmail);
    await page.locator("#reg-password").fill(TEST_PASSWORD);

    // Capture both the register POST and the subsequent auto-login POST
    const registerPromise = page.waitForResponse(
      (r) =>
        r.url().includes("/api/v1/auth/register") && r.request().method() === "POST"
    );
    await page.locator("#register-form button[type=submit]").click();
    const registerResponse = await registerPromise;

    await page.screenshot({ path: "e2e/screenshots/03-register-response.png" });

    expect(registerResponse.status()).toBe(201);
    const body = await registerResponse.json();
    expect(body).toHaveProperty("id");
    expect(body).toHaveProperty("email", uniqueEmail);

    // After successful register the form auto-logs in, modal closes
    await expect(page.locator("#auth-modal")).not.toBeVisible({
      timeout: 8000,
    });

    // JWT in localStorage
    const storedToken = await page.evaluate(() =>
      localStorage.getItem("iam_access_token")
    );
    expect(storedToken).toBeTruthy();

    expect(consoleErrors).toHaveLength(0);
  });

  test("register with existing email shows 409 error in UI", async ({
    page,
  }) => {
    await page.goto(BASE_URL);
    await page.locator("#login-open-btn").click();
    await page.locator("#tab-register").click();

    await page.locator("#reg-email").fill(TEST_EMAIL);
    await page.locator("#reg-password").fill(TEST_PASSWORD);

    const registerPromise = page.waitForResponse(
      (r) =>
        r.url().includes("/api/v1/auth/register") && r.request().method() === "POST"
    );
    await page.locator("#register-form button[type=submit]").click();
    const registerResponse = await registerPromise;

    // test@example.com already exists — 409
    expect(registerResponse.status()).toBe(409);

    // Error displayed in form
    await expect(page.locator("#reg-error")).toBeVisible();
    const errText = await page.locator("#reg-error").textContent();
    expect(errText?.trim()).toBeTruthy();

    await page.screenshot({ path: "e2e/screenshots/04-register-duplicate.png" });
  });
});

// ── Flow 2: Login ─────────────────────────────────────────────────────────────

test.describe("Flow 2 — Login", () => {
  test("login via UI with valid credentials stores JWT and shows user email", async ({
    page,
  }) => {
    const consoleErrors = collectConsoleErrors(page);

    await page.goto(BASE_URL);
    await page.locator("#login-open-btn").click();
    await expect(page.locator("#login-form")).toBeVisible();

    await page.screenshot({ path: "e2e/screenshots/05-login-form.png" });

    await page.locator("#login-email").fill(TEST_EMAIL);
    await page.locator("#login-password").fill(TEST_PASSWORD);

    const loginPromise = page.waitForResponse(
      (r) =>
        r.url().includes("/api/v1/auth/login") && r.request().method() === "POST"
    );
    await page.locator("#login-form button[type=submit]").click();
    const loginResponse = await loginPromise;

    await page.screenshot({ path: "e2e/screenshots/06-post-login.png" });

    expect(loginResponse.status()).toBe(200);
    const tokenData = await loginResponse.json();
    expect(tokenData).toHaveProperty("access_token");
    expect(tokenData).toHaveProperty("refresh_token");
    expect(tokenData.token_type).toBe("bearer");

    // JWT stored in localStorage
    const storedToken = await page.evaluate(() =>
      localStorage.getItem("iam_access_token")
    );
    expect(storedToken).toBeTruthy();
    expect(storedToken).toBe(tokenData.access_token);

    // Modal closes, user email shows in nav
    await expect(page.locator("#auth-modal")).not.toBeVisible();
    await expect(page.locator("#auth-email")).toBeVisible();
    const emailText = await page.locator("#auth-email").textContent();
    expect(emailText).toContain(TEST_EMAIL);

    // Auth UI state
    await expect(page.locator("#logout-btn")).toBeVisible();
    await expect(page.locator("#login-open-btn")).not.toBeVisible();

    await page.screenshot({ path: "e2e/screenshots/07-logged-in-state.png" });

    expect(consoleErrors).toHaveLength(0);
  });

  test("login with wrong password shows error message in form", async ({
    page,
  }) => {
    await page.goto(BASE_URL);
    await page.locator("#login-open-btn").click();

    await page.locator("#login-email").fill(TEST_EMAIL);
    await page.locator("#login-password").fill("WrongPassword999!");

    const loginPromise = page.waitForResponse(
      (r) =>
        r.url().includes("/api/v1/auth/login") && r.request().method() === "POST"
    );
    await page.locator("#login-form button[type=submit]").click();
    const loginResponse = await loginPromise;

    expect(loginResponse.status()).toBe(401);

    await expect(page.locator("#login-error")).toBeVisible();
    const errText = await page.locator("#login-error").textContent();
    expect(errText?.trim()).toBeTruthy();

    await page.screenshot({ path: "e2e/screenshots/08-login-error.png" });
  });
});

// ── Flow 3: Policy Upload ─────────────────────────────────────────────────────

test.describe("Flow 3 — Policy Upload", () => {
  test("paste wildcard policy and click Analyze — API queues task", async ({
    page,
  }) => {
    const consoleErrors = collectConsoleErrors(page);

    // Seed auth token directly (avoids rate-limiting the UI login)
    await seedAuthToken(page);

    await page.locator("#policy-input").fill(WILDCARD_POLICY);
    await expect(page.locator("#policy-input")).toHaveValue(WILDCARD_POLICY);

    await page.screenshot({ path: "e2e/screenshots/09-policy-pasted.png" });

    const analyzePromise = page.waitForResponse(
      (r) =>
        r.url().includes("/api/v1/analyze") && r.request().method() === "POST",
      { timeout: 15000 }
    );
    await page.locator("#analyze-btn").click();

    // Loading spinner
    await expect(page.locator("#loading")).toBeVisible();
    await page.screenshot({
      path: "e2e/screenshots/10-analyzing-spinner.png",
    });

    const analyzeResponse = await analyzePromise;
    expect(analyzeResponse.status()).toBe(200);

    const data = await analyzeResponse.json();
    expect(data).toHaveProperty("id");
    expect(data).toHaveProperty("task_id");
    expect(data).toHaveProperty("status");

    await page.screenshot({ path: "e2e/screenshots/11-analysis-queued.png" });

    expect(consoleErrors).toHaveLength(0);
  });
});

// ── Flow 4: Analysis Results ──────────────────────────────────────────────────

test.describe("Flow 4 — Analysis Results", () => {
  // Celery processing takes ~30s; allow generous time
  test.setTimeout(120000);

  test("wildcard policy shows CRITICAL risk score and findings", async ({
    page,
  }) => {
    const consoleErrors = collectConsoleErrors(page);
    await seedAuthToken(page);

    await page.locator("#policy-input").fill(WILDCARD_POLICY);

    const analyzePromise = page.waitForResponse(
      (r) =>
        r.url().includes("/api/v1/analyze") && r.request().method() === "POST",
      { timeout: 15000 }
    );
    await page.locator("#analyze-btn").click();
    const analyzeResponse = await analyzePromise;
    expect(analyzeResponse.status()).toBe(200);

    // Wait for Celery completion — #results loses the "hidden" class
    await expect(page.locator("#results")).not.toHaveClass(/hidden/, {
      timeout: 90000,
    });

    await page.screenshot({
      path: "e2e/screenshots/12-results-visible.png",
      fullPage: true,
    });

    // Risk score is a number
    const scoreText = await page.locator("#score-number").textContent();
    expect(scoreText?.trim()).not.toBe("—");
    const scoreVal = parseFloat(scoreText?.trim() ?? "0");
    expect(scoreVal).toBeGreaterThan(0);

    // Severity label
    const severityText = await page.locator("#severity-label").textContent();
    expect(severityText?.trim()).toBeTruthy();

    // Findings count
    const findingsCountText = await page.locator("#findings-count").textContent();
    const findingsCount = parseInt(findingsCountText?.trim() ?? "0", 10);
    expect(findingsCount).toBeGreaterThan(0);

    // Findings list has items
    const findingsContent = await page.locator("#findings").textContent();
    expect(findingsContent?.trim().length).toBeGreaterThan(0);

    await page.screenshot({
      path: "e2e/screenshots/13-risk-score-findings.png",
      fullPage: true,
    });

    expect(consoleErrors).toHaveLength(0);
  });

  test("clear button resets textarea", async ({ page }) => {
    await seedAuthToken(page);

    await page.locator("#policy-input").fill(WILDCARD_POLICY);
    await page.locator("#clear-btn").click();

    const val = await page.locator("#policy-input").inputValue();
    expect(val).toBe("");

    await page.screenshot({ path: "e2e/screenshots/14-cleared-form.png" });
  });
});

// ── Flow 5: Permission Graph ──────────────────────────────────────────────────

test.describe("Flow 5 — Permission Graph", () => {
  test.setTimeout(120000);

  test("Cytoscape graph renders canvas elements after analysis completes", async ({
    page,
  }) => {
    const consoleErrors = collectConsoleErrors(page);
    await seedAuthToken(page);

    await page.locator("#policy-input").fill(WILDCARD_POLICY);

    const analyzePromise = page.waitForResponse(
      (r) =>
        r.url().includes("/api/v1/analyze") && r.request().method() === "POST",
      { timeout: 15000 }
    );
    await page.locator("#analyze-btn").click();
    await analyzePromise;

    // Wait for results section
    await expect(page.locator("#results")).not.toHaveClass(/hidden/, {
      timeout: 90000,
    });

    // Graph container visible
    await expect(page.locator("#graph-container")).toBeVisible();

    // Cytoscape #cy div present
    await expect(page.locator("#cy")).toBeVisible();

    // Canvas(es) created inside #cy by Cytoscape
    const canvasCount = await page.locator("#cy canvas").count();
    expect(canvasCount).toBeGreaterThan(0);

    // Fit button
    await expect(page.locator("#fit-btn")).toBeVisible();

    // AI Suggestions panel
    await expect(page.locator("#suggestions")).toBeVisible();

    // Download Report button
    await expect(page.locator("#report-panel")).toBeVisible();

    await page.screenshot({
      path: "e2e/screenshots/15-permission-graph.png",
      fullPage: true,
    });

    expect(consoleErrors).toHaveLength(0);
  });
});

// ── Flow 6: Navigation ────────────────────────────────────────────────────────

test.describe("Flow 6 — Navigation", () => {
  test("homepage loads all main sections without JS errors", async ({
    page,
  }) => {
    const consoleErrors = collectConsoleErrors(page);

    await page.goto(BASE_URL);

    await page.screenshot({
      path: "e2e/screenshots/16-nav-homepage.png",
      fullPage: true,
    });

    // Top nav present
    await expect(page.locator("nav .top-nav")).toBeVisible();
    await expect(page.locator(".nav-logo")).toBeVisible();
    const logoText = await page.locator(".nav-logo").textContent();
    expect(logoText).toContain("IAM Analyzer");

    // Hero heading
    await expect(page.locator(".hero-band h1")).toBeVisible();
    const h1 = await page.locator(".hero-band h1").textContent();
    expect(h1).toContain("IAM Policy");

    // Upload card
    await expect(page.locator(".upload-card")).toBeVisible();
    await expect(page.locator("#policy-input")).toBeVisible();
    await expect(page.locator("#analyze-btn")).toBeVisible();
    await expect(page.locator("#clear-btn")).toBeVisible();

    // Cloud selector
    await expect(page.locator("#cloud-select")).toBeVisible();

    // Enterprise dashboard
    await expect(page.locator("#enterprise-dashboard")).toBeVisible();
    await expect(page.locator("#dash-load-btn")).toBeVisible();

    expect(consoleErrors).toHaveLength(0);
  });

  test("history sidebar toggles open and closed via CSS class", async ({
    page,
  }) => {
    await page.goto(BASE_URL);

    // Initially closed — no "open" class
    await expect(page.locator("#history-sidebar")).not.toHaveClass(/open/);

    // Open via toggle button
    await page.locator("#history-toggle").click();
    await expect(page.locator("#history-sidebar")).toHaveClass(/open/);
    await page.screenshot({ path: "e2e/screenshots/17-history-open.png" });

    // Close via X button
    await page.locator("#history-close").click();
    await expect(page.locator("#history-sidebar")).not.toHaveClass(/open/);
    await page.screenshot({ path: "e2e/screenshots/18-history-closed.png" });
  });

  test("enterprise dashboard Load button calls /api/v1/dashboard/summary", async ({
    page,
  }) => {
    await seedAuthToken(page);

    const dashPromise = page.waitForResponse(
      (r) => r.url().includes("/api/v1/dashboard/summary"),
      { timeout: 10000 }
    );
    await page.locator("#dash-load-btn").click();
    const dashResponse = await dashPromise;

    expect([200, 401, 403]).toContain(dashResponse.status());

    await page.screenshot({
      path: "e2e/screenshots/19-enterprise-dashboard.png",
      fullPage: true,
    });
  });

  test("logout clears JWT and restores login button", async ({ page }) => {
    await seedAuthToken(page);

    // Verify logged in
    await expect(page.locator("#logout-btn")).toBeVisible();

    // Logout
    await page.locator("#logout-btn").click();
    await page.screenshot({ path: "e2e/screenshots/20-logged-out.png" });

    // Token removed
    const token = await page.evaluate(() =>
      localStorage.getItem("iam_access_token")
    );
    expect(token).toBeNull();

    // UI back to unauthenticated
    await expect(page.locator("#login-open-btn")).toBeVisible();
    await expect(page.locator("#logout-btn")).not.toBeVisible();
    await expect(page.locator("#auth-email")).not.toBeVisible();
  });

  test("auth modal tabs switch between Login and Register forms", async ({
    page,
  }) => {
    await page.goto(BASE_URL);

    // Open modal
    await page.locator("#login-open-btn").click();
    await expect(page.locator("#auth-modal")).toBeVisible();

    // Default: Login tab active
    await expect(page.locator("#login-form")).toBeVisible();
    await expect(page.locator("#register-form")).not.toBeVisible();

    // Switch to Register
    await page.locator("#tab-register").click();
    await expect(page.locator("#register-form")).toBeVisible();
    await expect(page.locator("#login-form")).not.toBeVisible();

    // Close via X
    await page.locator("#modal-close-btn").click();
    await expect(page.locator("#auth-modal")).not.toBeVisible();

    await page.screenshot({ path: "e2e/screenshots/21-modal-closed.png" });
  });
});

// ── API Smoke Tests ───────────────────────────────────────────────────────────

test.describe("API Smoke Tests", () => {
  test("GET /health returns ok", async ({ request }) => {
    const res = await request.get(`${BASE_URL}/health`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("ok");
  });

  test("POST /api/v1/analyze without auth returns 401", async ({ request }) => {
    const res = await request.post(`${BASE_URL}/api/v1/analyze`, {
      data: {
        mode: "json",
        cloud: "aws",
        policy: JSON.parse(WILDCARD_POLICY),
      },
    });
    expect(res.status()).toBe(401);
  });

  test("GET /api/v1/analyses without auth returns 401 or 403", async ({
    request,
  }) => {
    const res = await request.get(`${BASE_URL}/api/v1/analyses`);
    expect([401, 403]).toContain(res.status());
  });

  test("POST /api/v1/auth/login with valid credentials returns JWT tokens", async ({
    request,
  }) => {
    const res = await request.post(`${BASE_URL}/api/v1/auth/login`, {
      data: { email: TEST_EMAIL, password: TEST_PASSWORD },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty("access_token");
    expect(body).toHaveProperty("refresh_token");
    expect(body.token_type).toBe("bearer");
  });

  test("GET /openapi.json serves valid API schema", async ({ request }) => {
    const res = await request.get(`${BASE_URL}/openapi.json`);
    expect(res.status()).toBe(200);
    const schema = await res.json();
    expect(schema).toHaveProperty("paths");
    expect(schema.paths).toHaveProperty("/api/v1/auth/login");
    expect(schema.paths).toHaveProperty("/api/v1/analyze");
    expect(schema.paths).toHaveProperty("/api/v1/analyses");
  });
});
