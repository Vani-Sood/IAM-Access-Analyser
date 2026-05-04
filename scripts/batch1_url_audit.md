# Batch 1 — Pre-flight URL Audit

Authoritative inventory of every URL prefix / fetch / router declaration site touched by Batch 2 (router prefix unification). No code change here. Used as Batch 2 acceptance checklist.

Generated: 2026-05-01. Repo root: `/home/parrot/VaniProject`.

Convention target (Batch 2): every public endpoint at `/api/v1/<resource>/...`. Routers self-declare full prefix. `main.py` adds no `prefix=` kwargs.

---

## A. Backend routers — declaration sites (8 files)

| # | File | Line | Current | Action (Batch 2) |
|---|------|------|---------|------------------|
| A1 | `backend/app/api/v1/auth.py` | 19 | `APIRouter(prefix="/auth", tags=["auth"])` | → `prefix="/api/v1/auth"` |
| A2 | `backend/app/api/v1/admin.py` | 18 | `APIRouter(prefix="/admin", tags=["admin"])` | → `prefix="/api/v1/admin"` |
| A3 | `backend/app/api/v1/analyze.py` | 22 | `APIRouter()` (no prefix; `main.py` adds `/api/v1`) | → `APIRouter(prefix="/api/v1/analyze", tags=["analyze"])` and update route `@router.post("/analyze")` (line 87) → `@router.post("")` |
| A4 | `backend/app/api/v1/analyses.py` | 17 | `APIRouter()` (no prefix; `main.py` adds `/api/v1`) | → `APIRouter(prefix="/api/v1/analyses", tags=["analyses"])`. Strip leading `/analyses` from each `@router.<verb>("/analyses/...")` (lines 90, 121, 150, 205, 264, 312, 387) → `("")`, `("/{analysis_id}/status")`, `("/{analysis_id}/inheritance")`, `("/{analysis_id}/report")`, `("/{analysis_id}/privesc")`, `("/{analysis_id}/compliance")`, `("/{analysis_id}")`. |
| A5 | `backend/app/api/v1/apikeys.py` | 18 | `APIRouter(prefix="/api/v1/apikeys", ...)` | ✅ already correct — no change |
| A6 | `backend/app/api/v1/orgs.py` | 16 | `APIRouter(prefix="/api/v1/orgs", ...)` | ✅ already correct — no change |
| A7 | `backend/app/api/v1/webhooks.py` | 21 | `APIRouter(prefix="/api/v1/webhooks", ...)` | ✅ already correct — no change |
| A8 | `backend/app/api/v1/dashboard.py` | 12 | `APIRouter(prefix="/api/v1/dashboard", ...)` | ✅ already correct — no change |

---

## B. Backend `main.py` — include_router sites (`backend/app/main.py`)

| # | Line | Current | Action |
|---|------|---------|--------|
| B1 | 99 | `app.include_router(auth_router)` | keep (no kwargs) — A1 now declares full prefix |
| B2 | 100 | `app.include_router(analyze_router, prefix="/api/v1")` | drop `prefix=` kwarg |
| B3 | 101 | `app.include_router(analyses_router, prefix="/api/v1")` | drop `prefix=` kwarg |
| B4 | 102 | `app.include_router(apikeys_router)` | keep |
| B5 | 103 | `app.include_router(dashboard_router)` | keep |
| B6 | 104 | `app.include_router(orgs_router)` | keep |
| B7 | 105 | `app.include_router(webhooks_router)` | keep |
| B8 | 106 | `app.include_router(admin_router)` | keep — A2 now declares full prefix |

Post-Batch 2 invariant: zero `prefix=` kwargs in `main.py`.

---

## C. Backend non-router URL literals

| # | File | Line | Current | Action |
|---|------|------|---------|--------|
| C1 | `backend/app/api/v1/deps.py` | 19 | `OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)` | → `tokenUrl="/api/v1/auth/login"` |

(Only one site — confirmed by grep across `backend/app/`.)

---

## D. Backend tests — `/auth/` and `/admin/` literals (4 files, 59 lines)

Touch list (full grep saved at `~/.claude/projects/-home-parrot-VaniProject/.../bduspbz75.txt`):

### D1. `backend/tests/test_auth_endpoints.py` — 30 lines
Lines: 1 (docstring), 38, 50, 58, 68, 78, 79, 85, 93, 105, 113, 124, 132, 142, 146, 150, 162, 166, 174, 178, 188, 192, 200, 228, 234, 247, 261, 267 (+ comment lines 45, 100, 157)
- `"/auth/register"` → `"/api/v1/auth/register"`
- `"/auth/login"` → `"/api/v1/auth/login"`
- `"/auth/refresh"` → `"/api/v1/auth/refresh"`

### D2. `backend/tests/test_apikeys.py` — 2 lines
- L39: `"/auth/register"` → `"/api/v1/auth/register"`
- L40: `"/auth/login"` → `"/api/v1/auth/login"`

### D3. `backend/tests/test_audit_endpoint.py` — 25 lines
Lines: 1 (docstring), 74, 83, 91, 96, 102, 108, 117, 123, 132, 133, 140, 146, 152, 160, 165, 170, 176, 181, 185, 190, 222, 227, 247, 253
- `"/admin/audit-log"` → `"/api/v1/admin/audit-log"`
- `"/admin/audit-log/export"` → `"/api/v1/admin/audit-log/export"`
- `"/admin/audit-log?…"` querystrings → prepend `/api/v1`
- `"/auth/login"` (L222), `"/auth/register"` (L247) → prepend `/api/v1`

### D4. `backend/tests/test_webhooks.py` — 2 lines
- L36: `"/auth/register"` → `"/api/v1/auth/register"`
- L37: `"/auth/login"` → `"/api/v1/auth/login"`

### Other test files — already correct (verify only, no diff expected)
`test_analyze_endpoint.py` (21), `test_analyses_endpoints.py` (18), `test_analysis_status.py` (10), `test_compliance_endpoint.py` (25), `test_dashboard_endpoint.py` (16), `test_lca_endpoint.py` (10), `test_multicloud_analyze.py` (23), `test_org_endpoints.py` (38), `test_privesc_endpoint.py` (16), `test_report_endpoint.py` (19), `test_rbac_analyses.py` (15), `test_frontend.py` (4), `test_deps.py` (4) — all use `/api/v1/...` already; Batch 2 must leave them untouched.

---

## E. Frontend — non-`/api/v1/` literals (3 files, 12 lines)

### E1. `frontend/index.html` — 4 fetch calls
- L107: `fetch("/auth/login", …)` → `/api/v1/auth/login`
- L134: `fetch("/auth/register", …)` → `/api/v1/auth/register`
- L142: `fetch("/auth/login", …)` → `/api/v1/auth/login`
- L163: `fetch("/auth/change-password", …)` → `/api/v1/auth/change-password`

### E2. `frontend/admin.js` — 2 sites
- L6: `` `/admin/audit-log?limit=${limit}&offset=${offset}` `` → prepend `/api/v1`
- L193: `fetch("/admin/audit-log/export", …)` → prepend `/api/v1`

### E3. `frontend/admin.test.js` — 6 expectations
- L20, 25, 30, 35, 40, 45: `.toBe("/admin/audit-log?…")` → prepend `/api/v1`

### Frontend — already correct (verify only)
- `orgs.js` (6 sites), `analyze.js` (2 sites), `analysis.js` (5 sites), `analysis.test.js` (6 sites), `history.js` (2 sites), `history.test.js` (3 sites), `dashboard.js` (8 sites), `dashboard-page.js` (1 site), `settings.js` (9 sites — incl. L364 `/api/v1/auth/change-password` which currently 404s; **fixed as side-effect of A1**), `shared.js` (apiFetch wrapper, no literal URL).

---

## F. E2E specs — `/auth/` literals

### F1. `e2e/iam-analyzer.spec.ts` — 8 sites
- L28: `request.post(\`${BASE_URL}/auth/login\`)` → `/api/v1/auth/login`
- L85, 123: `r.url().includes("/auth/register")` → `/api/v1/auth/register`
- L159, 205: `r.url().includes("/auth/login")` → `/api/v1/auth/login`
- L547: test name string `"POST /auth/login …"` → update label
- L550: `request.post(\`${BASE_URL}/auth/login\`)` → `/api/v1/auth/login`
- L565: `schema.paths` key `"/auth/login"` → `"/api/v1/auth/login"`

### F2. `e2e/report/data/*.md` — playwright HTML reports, generated artifacts. **Skip** — regenerate on next run.

---

## G. Site totals

| Bucket | Files | Sites |
|--------|-------|-------|
| A. Backend routers | 4 (modify) + 4 (verify) | 4 declarations + 8 route paths in `analyses.py` + 1 in `analyze.py` = 13 |
| B. main.py kwargs | 1 | 2 |
| C. backend non-router | 1 | 1 |
| D. backend tests | 4 | 59 |
| E. frontend src+test | 3 | 12 |
| F. e2e specs | 1 | 8 |
| **TOTAL** | **14 files** | **~95 sites** |

(Plan estimate: 40–60. Actual higher due to test_audit_endpoint and test_auth_endpoints density. No additional sites missed by scope grep on `/auth/` `/admin/` `/api/v1/` `apiFetch(` `fetch(`.)

---

## H. Already-correct invariants (must remain green)

- All `/api/v1/orgs`, `/api/v1/apikeys`, `/api/v1/webhooks`, `/api/v1/dashboard`, `/api/v1/analyze`, `/api/v1/analyses` sites in non-listed test/frontend files.
- `shared.js apiFetch` wrapper is URL-agnostic.
- `settings.js:364` already targets `/api/v1/auth/change-password` — this is the **bug** today (returns 404 because backend is at `/auth/change-password`); Batch 2 closes it automatically.

---

## I. Batch 2 acceptance checklist (derived)

- [ ] All 4 router files declare full `/api/v1/...` prefix.
- [ ] `main.py` contains zero `prefix=` kwargs in `include_router` calls.
- [ ] `deps.py:19` `tokenUrl` updated.
- [ ] All 4 listed test files updated (D1–D4).
- [ ] `index.html`, `admin.js`, `admin.test.js` updated (E1–E3).
- [ ] `e2e/iam-analyzer.spec.ts` updated (F1).
- [ ] `grep -rnE "/auth/|/admin/" backend/app frontend e2e | grep -v "/api/v1/"` returns zero matches.
- [ ] `pytest backend/tests` green (≥815 tests).
- [ ] `npm test --prefix frontend` (jest) green.
- [ ] `/openapi.json` shows every route under `/api/v1/`.
- [ ] `scripts/check_url_consistency.sh` (created in Batch 2) passes.

---

## J. Output for Batch 2

This file is the input checklist. Batch 2 PR description must reference each section (A–F) and tick the boxes in section I. Atomic commit — no partial merges.
