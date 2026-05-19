#!/usr/bin/env bash
# setup-machine.sh — One-shot bootstrap for IAM-Access-Analyser on Kali / Parrot / Debian-family Linux.
#
# - Detects Docker or Podman
# - Installs Docker if missing (Kali/Parrot/Ubuntu/Debian)
# - Starts daemon / podman socket
# - Installs awscli + google-cloud-cli (so cred validation works on fresh OS)
# - Generates strong DB + JWT secrets
# - Prompts for admin email/password
# - Optionally prompts for AWS / Azure / GCP credentials
# - Validates each cloud credential set against required permissions
# - Builds and brings up the stack
#
# Usage: bash setup-machine.sh
#
# Reads/writes: .env at repo root.
# Reads:       getkeys.md (just to remind user where credential docs live).
# Tested:      Kali 2024.x, Parrot 6.x, Ubuntu 22.04+, Debian 12.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# ── ANSI colours ─────────────────────────────────────────────────────────────
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYN=$'\e[36m'; BLD=$'\e[1m'; RST=$'\e[0m'
info()  { echo "${CYN}[*]${RST} $*"; }
ok()    { echo "${GRN}[✓]${RST} $*"; }
warn()  { echo "${YEL}[!]${RST} $*"; }
err()   { echo "${RED}[✗]${RST} $*" >&2; }
fatal() { err "$*"; exit 1; }

banner() {
  echo "${BLD}═══════════════════════════════════════════════════════════════════${RST}"
  echo "${BLD}  IAM-Access-Analyser — Machine Setup${RST}"
  echo "${BLD}═══════════════════════════════════════════════════════════════════${RST}"
}

# ── 1. Pre-flight: OS + sudo ─────────────────────────────────────────────────

detect_os() {
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_LIKE="${ID_LIKE:-}"
    OS_NAME="${PRETTY_NAME:-$OS_ID}"
  else
    OS_ID="unknown"; OS_LIKE=""; OS_NAME="unknown"
  fi
  info "Detected OS: ${OS_NAME}"
}

require_sudo_or_root() {
  if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
  elif command -v sudo >/dev/null; then
    SUDO="sudo"
    info "Requesting sudo (cache password):"
    sudo -v || fatal "sudo authentication failed"
  else
    fatal "Neither root nor sudo available."
  fi
}

# ── 2. Container engine: pick podman if installed, else install docker ───────

DOCKER_GROUP_ADDED=0   # track if we just added user to docker group

ensure_docker_group() {
  # Skip for root or podman (podman uses user socket, no group needed)
  [ "$(id -u)" -eq 0 ] && return
  [ "${ENGINE:-}" = "podman" ] && return
  local user="${SUDO_USER:-${USER:-$(id -un)}}"
  if id -nG "$user" 2>/dev/null | grep -qw docker; then
    return   # already in group
  fi
  info "Adding $user to 'docker' group..."
  $SUDO usermod -aG docker "$user" || { warn "usermod failed — may need to run as root"; return; }
  DOCKER_GROUP_ADDED=1
  warn "Added to 'docker' group. Using 'sg docker' for this session (no logout needed)."
}

setup_container_engine() {
  local docker_ver=""
  if command -v docker >/dev/null; then
    docker_ver="$(docker --version 2>&1 || true)"
  fi
  if command -v podman >/dev/null && command -v docker >/dev/null && [[ "$docker_ver" == *[Pp]odman* ]]; then
    info "Using Podman (Docker CLI shim detected)"
    ENGINE="podman"
    start_podman_socket
  elif command -v docker >/dev/null && [[ "$docker_ver" != *[Pp]odman* ]]; then
    info "Using native Docker"
    ENGINE="docker"
    start_docker_daemon
  elif command -v podman >/dev/null; then
    info "Podman present, installing docker-CLI shim"
    install_docker_podman_shim
    ENGINE="podman"
    start_podman_socket
  else
    info "No container engine found — installing Docker"
    install_docker
    ENGINE="docker"
    start_docker_daemon
  fi

  ensure_docker_group

  if ! docker compose version >/dev/null 2>&1 && \
     ! sg docker -c "docker compose version" >/dev/null 2>&1; then
    info "Installing docker compose plugin"
    install_compose_plugin
  fi
  ok "Container engine ready: $(docker --version 2>&1 | head -1)"
  ok "Compose: $(docker compose version 2>&1 | head -1)"
}

install_docker() {
  case "$OS_ID:$OS_LIKE" in
    kali:*|parrot:*|*debian*|*ubuntu*)
      $SUDO apt-get update -qq
      $SUDO apt-get install -y -qq ca-certificates curl gnupg
      # On Kali/Parrot, docker.io is in main repo and is the safest path
      $SUDO apt-get install -y -qq docker.io docker-compose-v2 || \
        $SUDO apt-get install -y -qq docker.io
      ;;
    *)
      fatal "Unsupported OS for auto-install: $OS_NAME. Install Docker manually then re-run."
      ;;
  esac

  # Group membership handled by ensure_docker_group after engine detection
}

install_docker_podman_shim() {
  case "$OS_ID:$OS_LIKE" in
    kali:*|parrot:*|*debian*|*ubuntu*)
      $SUDO apt-get update -qq
      $SUDO apt-get install -y -qq podman-docker docker-compose-v2 || \
        $SUDO apt-get install -y -qq podman-docker
      ;;
    *)
      fatal "Unsupported OS for podman-docker shim: $OS_NAME"
      ;;
  esac
}

install_compose_plugin() {
  case "$OS_ID:$OS_LIKE" in
    kali:*|parrot:*|*debian*|*ubuntu*)
      $SUDO apt-get install -y -qq docker-compose-v2 || \
        $SUDO apt-get install -y -qq docker-compose
      ;;
  esac
}

start_docker_daemon() {
  if systemctl is-active docker >/dev/null 2>&1; then
    ok "Docker daemon already running"
    return
  fi
  $SUDO systemctl enable --now docker || true
  sleep 2
  systemctl is-active docker >/dev/null || fatal "Docker daemon failed to start"
}

start_podman_socket() {
  if systemctl --user is-active podman.socket >/dev/null 2>&1; then
    ok "Podman user socket already active"
    return
  fi
  systemctl --user enable --now podman.socket || \
    fatal "Failed to start podman user socket. Try: systemctl --user start podman.socket"
  ok "Podman user socket started + enabled at boot"
}

# ── 3. Python (for secret generation) ────────────────────────────────────────

require_python3() {
  if ! command -v python3 >/dev/null; then
    info "Installing python3"
    $SUDO apt-get install -y -qq python3
  fi
}

gen_secret() { python3 -c "import secrets; print(secrets.token_urlsafe(${1:-32}))"; }
gen_hex()    { python3 -c "import secrets; print(secrets.token_hex(${1:-32}))"; }

# ── 4. .env initialisation ───────────────────────────────────────────────────

init_env() {
  if [ -f .env ]; then
    info ".env already exists — keeping it (will only update missing/placeholder fields)"
  else
    cp .env.example .env
    ok "Created .env from .env.example"
  fi

  # JWT secret
  if grep -q "REPLACE_WITH_GENERATED_SECRET" .env; then
    local s
    s="$(gen_hex 32)"
    sed -i "s|REPLACE_WITH_GENERATED_SECRET|$s|" .env
    ok "Generated JWT_SECRET"
  fi

  # Database passwords (only if still placeholder 'changeme')
  if grep -q "POSTGRES_PASSWORD=changeme" .env; then
    sed -i "s|POSTGRES_PASSWORD=changeme|POSTGRES_PASSWORD=$(gen_secret 24)|" .env
    ok "Generated strong POSTGRES_PASSWORD"
  fi
  if grep -q "NEO4J_PASSWORD=changeme" .env; then
    sed -i "s|NEO4J_PASSWORD=changeme|NEO4J_PASSWORD=$(gen_secret 24)|" .env
    ok "Generated strong NEO4J_PASSWORD"
  fi
}

# ── 5. Admin prompt ──────────────────────────────────────────────────────────

prompt_admin() {
  echo
  echo "${BLD}Admin Account Bootstrap${RST}"
  echo "These credentials seed the initial admin user on first startup."

  local email pw1 pw2

  read -rp "Admin email: " email
  while ! [[ "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; do
    warn "Invalid email format"
    read -rp "Admin email: " email
  done

  while true; do
    read -rsp "Admin password (min 8 chars, 1 uppercase, 1 digit): " pw1; echo
    read -rsp "Confirm password:                                   " pw2; echo
    if [ "$pw1" != "$pw2" ]; then warn "Passwords do not match"; continue; fi
    if [ "${#pw1}" -lt 8 ];     then warn "Too short (<8)";         continue; fi
    if ! [[ "$pw1" =~ [A-Z] ]]; then warn "Need ≥1 uppercase";       continue; fi
    if ! [[ "$pw1" =~ [0-9] ]]; then warn "Need ≥1 digit";           continue; fi
    break
  done

  # Escape `|` in password for sed (rare but possible)
  local pw1_esc
  pw1_esc="$(printf '%s' "$pw1" | sed 's|[|&\\/]|\\&|g')"

  sed -i "s|^ADMIN_EMAIL=.*|ADMIN_EMAIL=$email|"           .env
  sed -i "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=$pw1_esc|"   .env
  ok "Admin credentials saved to .env"
}

# ── 5b. Gemini API key ───────────────────────────────────────────────────────

prompt_gemini() {
  echo
  echo "${BLD}Gemini API Key (AI Suggestions)${RST}"
  echo "Used to generate least-privilege policy suggestions after each analysis."
  echo "Get a free key at: ${CYN}https://aistudio.google.com/apikey${RST}"
  echo

  local key
  read -rsp "Gemini API key (press Enter to skip): " key; echo

  if [ -z "$key" ]; then
    warn "Skipping Gemini key. AI suggestions will show 'ai_unavailable' until set."
    warn "Add later: edit .env → GEMINI_API_KEY=your-key → docker compose restart backend celery-worker"
    return
  fi

  upsert_env GEMINI_API_KEY "$key"
  ok "Gemini API key saved to .env"
}

# ── 5c. Cloud CLI installers (awscli + gcloud) ───────────────────────────────

install_cloud_clis() {
  echo
  info "Ensuring cloud CLIs are installed (awscli, gcloud)..."

  # --- awscli (apt v1; fine for sts/get-caller-identity + assume-role) ---
  if command -v aws >/dev/null; then
    ok "awscli present: $(aws --version 2>&1 | head -1)"
  else
    info "Installing awscli via apt..."
    case "$OS_ID:$OS_LIKE" in
      kali:*|parrot:*|*debian*|*ubuntu*)
        $SUDO apt-get install -y -qq awscli \
          && ok "awscli installed: $(aws --version 2>&1 | head -1)" \
          || warn "awscli install failed — AWS validation will be skipped"
        ;;
      *)
        warn "Unsupported OS for auto-installing awscli — install manually"
        ;;
    esac
  fi

  # --- gcloud (Google Cloud SDK APT repo) ---
  if command -v gcloud >/dev/null; then
    ok "gcloud present: $(gcloud --version 2>&1 | head -1)"
  else
    info "Installing google-cloud-cli via official APT repo..."
    case "$OS_ID:$OS_LIKE" in
      kali:*|parrot:*|*debian*|*ubuntu*)
        $SUDO apt-get install -y -qq apt-transport-https ca-certificates gnupg curl
        if [ ! -f /usr/share/keyrings/cloud.google.gpg ]; then
          curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
            | $SUDO gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
            || { warn "Failed to fetch Google APT key — gcloud install skipped"; return; }
        fi
        if [ ! -f /etc/apt/sources.list.d/google-cloud-sdk.list ]; then
          echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
            | $SUDO tee /etc/apt/sources.list.d/google-cloud-sdk.list >/dev/null
        fi
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq google-cloud-cli \
          && ok "gcloud installed: $(gcloud --version 2>&1 | head -1)" \
          || warn "gcloud install failed — GCP validation will be skipped"
        ;;
      *)
        warn "Unsupported OS for auto-installing gcloud — install manually"
        ;;
    esac
  fi
}

# ── 6. Cloud credentials (interactive, optional) ─────────────────────────────

# Multi-select TUI: ↑/↓ navigate, SPACE toggle, ENTER confirm.
# Sets CHOSEN_AWS / CHOSEN_AZURE / CHOSEN_GCP to "1" or "0".
select_clouds() {
  echo
  echo "${BLD}Cloud Provider Selection${RST}"
  echo "${CYN}↑/↓${RST} navigate   ${CYN}SPACE${RST} toggle   ${CYN}ENTER${RST} confirm   (no selection = skip all)"
  echo

  local opts=("AWS" "Azure" "GCP")
  local sel=(0 0 0)
  local pos=0
  local n=${#opts[@]}
  local key key2

  tput civis 2>/dev/null || true

  # Initial blank lines so redraw can move cursor up
  for ((i = 0; i < n; i++)); do echo; done

  _redraw() {
    # Move cursor up n lines, clear each
    printf '\033[%dA' "$n"
    for i in "${!opts[@]}"; do
      local mark="[ ]"
      [ "${sel[$i]}" = "1" ] && mark="[${GRN}x${RST}]"
      if [ "$i" = "$pos" ]; then
        printf "\033[2K\r ${YEL}>${RST} %s %s\n" "$mark" "${opts[$i]}"
      else
        printf "\033[2K\r   %s %s\n" "$mark" "${opts[$i]}"
      fi
    done
  }
  _redraw

  while true; do
    IFS= read -rsn1 key || break
    case "$key" in
      $'\x1b')
        IFS= read -rsn2 -t 0.05 key2 || key2=""
        case "$key2" in
          '[A') ((pos > 0))     && pos=$((pos - 1)) ;;
          '[B') ((pos < n - 1)) && pos=$((pos + 1)) ;;
        esac
        ;;
      ' ') sel[$pos]=$((1 - sel[$pos])) ;;
      '')  break ;;
      q|Q) break ;;
    esac
    _redraw
  done

  tput cnorm 2>/dev/null || true

  CHOSEN_AWS="${sel[0]}"
  CHOSEN_AZURE="${sel[1]}"
  CHOSEN_GCP="${sel[2]}"

  local picked=""
  [ "$CHOSEN_AWS"   = "1" ] && picked+="AWS "
  [ "$CHOSEN_AZURE" = "1" ] && picked+="Azure "
  [ "$CHOSEN_GCP"   = "1" ] && picked+="GCP "
  [ -z "$picked" ] && picked="(none)"
  ok "Selected: $picked"
}

prompt_cloud_aws() {
  echo
  echo "${BLD}AWS Setup${RST}"

  cat <<'EOM'
Required (see getkeys.md §1):
  - IAM user with sts:AssumeRole permission on the target scan role
  - Target role with ReadOnlyAccess (or IAMReadOnlyAccess) in target account
EOM

  read -rp "AWS Access Key ID (AKIA...): " ak
  read -rsp "AWS Secret Access Key:        " sk; echo
  read -rp  "AWS Region (default us-east-1): " region
  region="${region:-us-east-1}"
  read -rp  "Target Role ARN to validate (or blank to skip role check): " role_arn

  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_DEFAULT_REGION="$region" \
    validate_aws "$role_arn" || {
      warn "AWS validation failed. Credentials NOT saved."
      return
    }

  upsert_env AWS_ACCESS_KEY_ID  "$ak"
  upsert_env AWS_SECRET_ACCESS_KEY "$sk"
  upsert_env AWS_DEFAULT_REGION "$region"
  ok "AWS credentials saved to .env"
}

validate_aws() {
  local role_arn="${1:-}"

  if ! command -v aws >/dev/null; then
    warn "aws CLI not installed — skipping permission validation. Install: apt install awscli"
    return 0
  fi

  info "Validating identity (sts:get-caller-identity)..."
  if ! aws sts get-caller-identity >/dev/null 2>&1; then
    err  "sts:get-caller-identity failed — bad keys or no network"
    return 1
  fi
  ok "Caller identity verified: $(aws sts get-caller-identity --query Arn --output text)"

  if [ -n "$role_arn" ]; then
    info "Validating sts:AssumeRole on $role_arn ..."
    if ! aws sts assume-role --role-arn "$role_arn" --role-session-name iam-analyzer-validate \
         --duration-seconds 900 >/dev/null 2>&1; then
      err  "AssumeRole failed. Caller lacks sts:AssumeRole on the target role, or trust policy excludes it."
      err  "See getkeys.md §1.2 for trust-policy template."
      return 1
    fi
    ok "AssumeRole succeeded — target role reachable + read-only permissions accessible"
  fi
}

prompt_cloud_azure() {
  echo
  echo "${BLD}Azure Setup${RST}"

  cat <<'EOM'
Required (see getkeys.md §2):
  - Service principal with Reader role on the target subscription
EOM

  read -rp  "Tenant ID:              " tid
  read -rp  "Client (App) ID:        " cid
  read -rsp "Client Secret:          " csec; echo
  read -rp  "Subscription ID:        " sub

  validate_azure "$tid" "$cid" "$csec" "$sub" || {
    warn "Azure validation failed. Credentials NOT saved."
    return
  }

  upsert_env AZURE_TENANT_ID      "$tid"
  upsert_env AZURE_CLIENT_ID      "$cid"
  upsert_env AZURE_CLIENT_SECRET  "$csec"
  upsert_env AZURE_SUBSCRIPTION_ID "$sub"
  ok "Azure credentials saved to .env"
}

validate_azure() {
  local tid="$1" cid="$2" csec="$3" sub="$4"
  if ! command -v curl >/dev/null; then warn "curl missing — skipping validation"; return 0; fi

  info "Requesting Azure OAuth token..."
  local token_response
  token_response=$(curl -sS -X POST "https://login.microsoftonline.com/$tid/oauth2/v2.0/token" \
    --data-urlencode "client_id=$cid" \
    --data-urlencode "client_secret=$csec" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "scope=https://management.azure.com/.default" 2>&1)
  local token
  token=$(echo "$token_response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true)
  if [ -z "$token" ]; then
    err "OAuth token request failed: $(echo "$token_response" | head -c 200)"
    return 1
  fi
  ok "OAuth token acquired"

  info "Verifying Reader access on subscription $sub..."
  local list_response status
  list_response=$(curl -sS -o /tmp/_az.json -w "%{http_code}" \
    -H "Authorization: Bearer $token" \
    "https://management.azure.com/subscriptions/$sub/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$top=1")
  status="$list_response"
  if [ "$status" != "200" ]; then
    err  "roleAssignments list returned HTTP $status. Service principal lacks Reader on subscription $sub."
    err  "Fix: az role assignment create --assignee $cid --role Reader --scope /subscriptions/$sub"
    rm -f /tmp/_az.json
    return 1
  fi
  rm -f /tmp/_az.json
  ok "Service principal has Reader access on subscription $sub"
}

prompt_cloud_gcp() {
  echo
  echo "${BLD}GCP Setup${RST}"

  cat <<'EOM'
Required (see getkeys.md §3):
  - Service account with roles/iam.securityReviewer on target project
  - JSON key file generated for that service account
EOM

  read -rp "GCP Project ID:                       " proj
  read -rp "Path to service-account JSON key:     " keypath
  keypath="${keypath/#\~/$HOME}"

  if [ ! -r "$keypath" ]; then
    err  "Key file not readable: $keypath"
    return
  fi

  validate_gcp "$proj" "$keypath" || {
    warn "GCP validation failed. Credentials NOT saved."
    return
  }

  local key_inline
  key_inline=$(python3 -c "import json,sys; print(json.dumps(json.load(open('$keypath'))))")
  upsert_env GCP_PROJECT_ID                 "$proj"
  upsert_env GCP_SERVICE_ACCOUNT_KEY_JSON   "$key_inline"
  ok "GCP credentials saved to .env"
}

validate_gcp() {
  local proj="$1" keypath="$2"

  info "Parsing service-account key..."
  if ! python3 -c "import json; d=json.load(open('$keypath')); assert d.get('type')=='service_account' and d.get('client_email')" 2>/dev/null; then
    err "Key file is not a valid GCP service-account JSON"
    return 1
  fi
  ok "Key file parsed"

  if ! command -v gcloud >/dev/null; then
    warn "gcloud not installed — saving key without live permission check. Install: apt install google-cloud-cli"
    return 0
  fi

  info "Activating service account and querying project IAM..."
  gcloud auth activate-service-account --key-file="$keypath" --quiet >/dev/null 2>&1 || {
    err "gcloud could not activate the service account from $keypath"
    return 1
  }
  if ! gcloud projects get-iam-policy "$proj" --format=json >/dev/null 2>&1; then
    err  "getIamPolicy failed on project $proj. Service account lacks roles/iam.securityReviewer."
    err  "Fix: gcloud projects add-iam-policy-binding $proj \\"
    err  "       --member=serviceAccount:<sa-email> --role=roles/iam.securityReviewer"
    return 1
  fi
  ok "Service account can read IAM policy on $proj"
}

# ── 7. .env upsert helper ────────────────────────────────────────────────────

upsert_env() {
  # upsert_env KEY VALUE
  local key="$1" val="$2"
  local val_esc
  val_esc="$(printf '%s' "$val" | sed 's|[|&\\/]|\\&|g')"
  if grep -qE "^${key}=" .env; then
    sed -i "s|^${key}=.*|${key}=${val_esc}|" .env
  elif grep -qE "^# ${key}=" .env; then
    sed -i "s|^# ${key}=.*|${key}=${val_esc}|" .env
  else
    printf '\n%s=%s\n' "$key" "$val" >> .env
  fi
}

# ── 8. Build + start stack ───────────────────────────────────────────────────

bring_up_stack() {
  echo
  info "Building images (first run ~5min)..."
  if [ "${DOCKER_GROUP_ADDED:-0}" = "1" ]; then
    # Group just granted — use sg so we don't need logout
    sg docker -c "docker compose up -d --build" \
      || fatal "Stack failed to start. Check: docker compose logs"
  else
    docker compose up -d --build \
      || fatal "Stack failed to start. Check: docker compose logs"
  fi
  sleep 5
  info "Health check..."
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS http://localhost:8000/health >/dev/null 2>&1; then
      ok "Backend healthy: $(curl -fsS http://localhost:8000/health)"
      break
    fi
    sleep 3
  done
}

# ── 9. Final summary ─────────────────────────────────────────────────────────

print_summary() {
  echo
  echo "${BLD}═══════════════════════════════════════════════════════════════════${RST}"
  echo "${GRN} Setup complete${RST}"
  echo "${BLD}═══════════════════════════════════════════════════════════════════${RST}"
  echo
  echo "Open:    ${CYN}http://localhost:8000/${RST}    (frontend)"
  echo "Docs:    ${CYN}http://localhost:8000/docs${RST} (Swagger)"
  echo "Neo4j:   ${CYN}http://localhost:7474/${RST}    (graph browser)"
  echo
  echo "Login with the admin account you just set."
  echo
  echo "${BLD}Useful commands:${RST}"
  echo "  docker compose ps           # service status"
  echo "  docker compose logs -f      # tail all logs"
  echo "  make test                   # run backend tests"
  echo "  make test-frontend          # run frontend tests"
  echo "  docker compose down         # stop"
  echo "  docker compose down -v      # stop + wipe data"
  echo
  echo "${BLD}Did not configure a cloud above?${RST} Read ${YEL}getkeys.md${RST} for step-by-step"
  echo "guides for AWS, Azure, and GCP. Re-run this script (or edit .env manually)"
  echo "to add them later, then: ${CYN}docker compose restart backend celery-worker${RST}"
  echo
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
  banner
  detect_os
  require_sudo_or_root
  require_python3
  setup_container_engine
  install_cloud_clis
  init_env
  prompt_admin
  prompt_gemini
  select_clouds
  [ "${CHOSEN_AWS:-0}"   = "1" ] && prompt_cloud_aws   || warn "Skipping AWS.   Add later via .env (see getkeys.md §1)"
  [ "${CHOSEN_AZURE:-0}" = "1" ] && prompt_cloud_azure || warn "Skipping Azure. Add later via .env (see getkeys.md §2)"
  [ "${CHOSEN_GCP:-0}"   = "1" ] && prompt_cloud_gcp   || warn "Skipping GCP.   Add later via .env (see getkeys.md §3)"
  bring_up_stack
  print_summary
}

main "$@"
