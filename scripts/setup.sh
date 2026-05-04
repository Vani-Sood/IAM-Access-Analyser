#!/usr/bin/env bash
# IAM Policy Analyzer — Project Bootstrap Script
# Idempotent: safe to run multiple times.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# PDF generation: fpdf2 (pure Python, no system libs required)
# Compliance reports: openpyxl
# AI suggestions: google-genai (Gemini)

# ── 1. Check Docker ────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  echo "ERROR: Docker is not installed or not in PATH."
  echo "Install Docker from: https://docs.docker.com/get-docker/"
  exit 1
fi

# ── 2. Check Docker Compose v2 plugin ────────────────────────────────────
if ! docker compose version &>/dev/null; then
  echo "ERROR: Docker Compose v2 plugin not found."
  echo "Upgrade Docker Desktop or install the plugin:"
  echo "  https://docs.docker.com/compose/install/"
  exit 1
fi

# ── 3. Check python3 ──────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 is not installed or not in PATH."
  echo "Install Python 3 from: https://www.python.org/downloads/"
  exit 1
fi

# ── 4. Copy .env.example → .env (only if .env does not exist) ─────────────
ENV_FILE="${PROJECT_ROOT}/.env"
ENV_EXAMPLE="${PROJECT_ROOT}/.env.example"

if [ ! -f "${ENV_FILE}" ]; then
  cp "${ENV_EXAMPLE}" "${ENV_FILE}"
  echo "Created .env from .env.example"
else
  echo "✓ .env already exists, skipping copy"
fi

# ── 5. Generate JWT_SECRET if still set to placeholder ────────────────────
PLACEHOLDER="REPLACE_WITH_GENERATED_SECRET"

if grep -q "${PLACEHOLDER}" "${ENV_FILE}"; then
  NEW_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  sed -i.bak "s/${PLACEHOLDER}/${NEW_SECRET}/" "${ENV_FILE}" && rm -f "${ENV_FILE}.bak"
  echo "✓ Generated JWT_SECRET"
else
  echo "✓ JWT_SECRET already configured"
fi

# ── 6. Next steps ─────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════"
echo " Setup complete! Next steps:"
echo "═══════════════════════════════════════════"
echo "1. Edit .env — set ADMIN_EMAIL, ADMIN_PASSWORD, GEMINI_API_KEY"
echo "2. (Optional) Add cloud scanner credentials to .env"
echo "3. Run: make up"
echo "4. Open: http://localhost:8000/docs"
echo "═══════════════════════════════════════════"
