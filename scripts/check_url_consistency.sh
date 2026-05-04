#!/usr/bin/env bash
# CI grep gate — fails if any non-/api/v1/ public URL leaks back into source.
# Allows /auth/, /admin/ inside /api/v1/... paths only.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Ignore generated artefacts and node_modules / pycache.
EXCLUDES=(
  --exclude-dir=node_modules
  --exclude-dir=__pycache__
  --exclude-dir=.git
  --exclude-dir=report
  --exclude-dir='e2e/report'
)

# A URL literal is "/auth/..." or `/auth/...` (string/template) NOT under /api/v1.
# Match only quoted / template-literal openers immediately before the bare prefix.
PATTERN='["\x27\x60]/(?:auth|admin)/'

VIOLATIONS=$(grep -rPn "${EXCLUDES[@]}" \
  --include='*.py' --include='*.js' --include='*.ts' --include='*.tsx' --include='*.html' \
  -- "$PATTERN" backend/ frontend/ e2e/ scripts/ 2>/dev/null \
  | grep -v 'batch1_url_audit.md' \
  | grep -v 'check_url_consistency.sh' || true)

if [ -n "$VIOLATIONS" ]; then
  echo "FAIL: bare /auth/ or /admin/ URL literals (must be /api/v1/auth/ or /api/v1/admin/):"
  echo "$VIOLATIONS"
  exit 1
fi

# main.py must contain zero prefix= kwargs in include_router calls.
if grep -nE 'include_router\([^)]*prefix=' backend/app/main.py >/dev/null; then
  echo "FAIL: backend/app/main.py contains include_router(..., prefix=...) — drop kwargs."
  grep -nE 'include_router\([^)]*prefix=' backend/app/main.py
  exit 1
fi

echo "OK: URL prefix consistency verified."
