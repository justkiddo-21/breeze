#!/usr/bin/env bash
#
# Deploy Breeze on rootless Podman (the "simple self-host" path: docker-compose.yml
# + docker-compose.override.yml.ghcr + docker-compose.override.yml.podman).
#
# Encodes every fix from docs/operations/PODMAN_ROOTLESS_DEPLOY.md so a fresh
# server doesn't have to rediscover them by hand. Read that doc for the WHY
# behind each step below; this script is the WHAT.
#
# Usage:
#   scripts/deploy-podman-rootless.sh [--behind-cloudflare-tunnel-http-origin] [ENV_FILE]
#
#   --behind-cloudflare-tunnel-http-origin
#       Only pass this if cloudflared's origin service for Caddy is http://
#       (not https://) — i.e. Cloudflare Tunnel terminates public TLS and the
#       cloudflared<->Caddy hop is plain HTTP. This sets FORCE_HTTPS=false and
#       TRUST_CF_CONNECTING_IP=true in .env, because Caddy stamps
#       X-Forwarded-Proto from its OWN (plain-HTTP) listener, not from
#       Cloudflare's original scheme — the API's HTTPS-redirect middleware
#       would otherwise infinite-loop on every /api/* request (see doc §8).
#       Omit this flag for any other topology (Caddy terminating real TLS,
#       a tunnel with an https:// origin, no tunnel at all).
#
#   ENV_FILE defaults to <repo>/.env; override via arg or BREEZE_ENV_FILE.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BEHIND_CF_TUNNEL_HTTP_ORIGIN=false
ENV_FILE="${BREEZE_ENV_FILE:-${REPO_ROOT}/.env}"
for arg in "$@"; do
  case "${arg}" in
    --behind-cloudflare-tunnel-http-origin) BEHIND_CF_TUNNEL_HTTP_ORIGIN=true ;;
    *) ENV_FILE="${arg}" ;;
  esac
done

SECRETS_DIR="${REPO_ROOT}/podman-secrets"
CADDY_HOST_PORT="${CADDY_HOST_PORT:-8080}"
COMPOSE_FILES=(
  -f "${REPO_ROOT}/docker-compose.yml"
  -f "${REPO_ROOT}/docker-compose.override.yml.ghcr"
  -f "${REPO_ROOT}/docker-compose.override.yml.podman"
)
IMAGES=(api web portal binaries)
HEALTH_SERVICES=(breeze-postgres breeze-redis breeze-api breeze-web breeze-portal breeze-caddy)
HEALTH_TIMEOUT_SECONDS=180
PLACEHOLDER="generate-a-random-hex-string-for-production"

log() { echo "[deploy-podman] $*"; }
die() { echo "[deploy-podman] ERROR: $*" >&2; exit 1; }

# Reads KEY=value from ENV_FILE without sourcing it as shell — sourcing an
# arbitrary secrets file would let a value containing $(...) or a backtick
# execute as a command. grep+cut only ever reads.
env_get() {
  local key="$1"
  grep -m1 "^${key}=" "${ENV_FILE}" 2>/dev/null | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//'
}

# Idempotent set-or-append of KEY=value. Uses awk (not sed -i) so arbitrary
# secret values with /, &, etc. can't corrupt the substitution pattern.
# Caveat: awk -v does its own backslash-escape processing, so this is only
# safe for values with no backslashes — true for every value this script
# writes (openssl rand base64/hex output, or literal true/false).
env_set() {
  local key="$1" value="$2" tmp
  if grep -q "^${key}=" "${ENV_FILE}"; then
    tmp="$(mktemp)"
    awk -v k="${key}" -v v="${value}" -F'=' 'BEGIN{OFS="="} $1==k{print k"="v; next} {print}' "${ENV_FILE}" > "${tmp}"
    mv "${tmp}" "${ENV_FILE}"
  else
    printf '%s=%s\n' "${key}" "${value}" >> "${ENV_FILE}"
  fi
}

[[ -f "${ENV_FILE}" ]] || die "Environment file not found: ${ENV_FILE} — copy .env.example to .env and fill in real values first."

log "== Preflight =="

command -v podman >/dev/null 2>&1 || die "podman not found on PATH."
podman compose version >/dev/null 2>&1 || die "'podman compose' doesn't work — need the docker-compose CLI plugin installed (podman shells out to it)."

if ! grep -q "^$(whoami):" /etc/subuid 2>/dev/null || ! grep -q "^$(whoami):" /etc/subgid 2>/dev/null; then
  log "WARNING: no /etc/subuid or /etc/subgid entry for $(whoami) — rootless container UID remapping may not work. See PODMAN_ROOTLESS_DEPLOY.md prerequisites."
fi

[[ -f "${REPO_ROOT}/docker-compose.override.yml.podman" ]] || die "docker-compose.override.yml.podman is missing — expected it to ship with the repo (see docs/operations/PODMAN_ROOTLESS_DEPLOY.md)."

log "== .env secret sanity check =="

fixed_any=false
for key in ENROLLMENT_KEY_PEPPER MFA_RECOVERY_CODE_PEPPER; do
  if [[ "$(env_get "${key}")" == "${PLACEHOLDER}" ]]; then
    log "Fixing ${key}: still the .env.example placeholder — generating a real secret."
    env_set "${key}" "$(openssl rand -base64 32)"
    fixed_any=true
  fi
done

if [[ "$(env_get MFA_ENCRYPTION_KEY)" == "${PLACEHOLDER}" ]]; then
  log "Fixing MFA_ENCRYPTION_KEY: still the .env.example placeholder — generating a real key."
  env_set MFA_ENCRYPTION_KEY "$(openssl rand -hex 32)"
  fixed_any=true
fi

if [[ "$(env_get METRICS_SCRAPE_TOKEN)" == "${PLACEHOLDER}" ]]; then
  log "Fixing METRICS_SCRAPE_TOKEN: still the .env.example placeholder — generating a real token."
  env_set METRICS_SCRAPE_TOKEN "$(openssl rand -hex 32)"
  fixed_any=true
fi

if [[ "$(env_get ENROLLMENT_KEY_PEPPER)" == "$(env_get MFA_RECOVERY_CODE_PEPPER)" ]]; then
  die "ENROLLMENT_KEY_PEPPER and MFA_RECOVERY_CODE_PEPPER are identical — the API refuses to boot with shared secret material across key domains. Set two independent values."
fi

db_url_app="$(env_get DATABASE_URL_APP)"
if [[ -n "${db_url_app}" ]] && [[ "${db_url_app}" == *localhost* || "${db_url_app}" == *127.0.0.1* ]]; then
  die "DATABASE_URL_APP points at localhost/127.0.0.1 (${db_url_app}). Inside the compose network the Postgres host is 'postgres', not localhost — DATABASE_URL_APP is passed through verbatim and does NOT get corrected like DATABASE_URL does. Fix it in ${ENV_FILE} and re-run."
fi

keyring="$(env_get JWT_SIGNING_KEYRING)"
active_kid="$(env_get JWT_ACTIVE_KID)"
if [[ -n "${keyring}" ]]; then
  if ! node -e '
    const keyring = JSON.parse(process.argv[1]);
    const kid = process.argv[2];
    process.exit(Object.prototype.hasOwnProperty.call(keyring, kid) ? 0 : 1);
  ' "${keyring}" "${active_kid}" 2>/dev/null; then
    valid_kids="$(node -e 'console.log(Object.keys(JSON.parse(process.argv[1])).join(", "))' "${keyring}" 2>/dev/null || echo "<unparsable JSON>")"
    die "JWT_ACTIVE_KID='${active_kid}' is not a key in JWT_SIGNING_KEYRING. Valid kids: ${valid_kids}. Set JWT_ACTIVE_KID to one of those (not a full JWT, not a guessed value)."
  fi
fi

${fixed_any} && log "Wrote regenerated secrets to ${ENV_FILE}." || log "No placeholder secrets found."

if ${BEHIND_CF_TUNNEL_HTTP_ORIGIN}; then
  log "== Cloudflare Tunnel (plain-HTTP origin) adjustments =="
  env_set FORCE_HTTPS false
  env_set TRUST_CF_CONNECTING_IP true
  log "Set FORCE_HTTPS=false, TRUST_CF_CONNECTING_IP=true (see doc §8 for why)."
fi

log "== GHCR auth =="
podman login --get-login ghcr.io >/dev/null 2>&1 || die "Not logged into ghcr.io. Run: podman login ghcr.io -u x-access-token --password-stdin"

log "== Verifying BREEZE_VERSION images actually exist on GHCR =="
version="$(env_get BREEZE_VERSION)"
[[ -n "${version}" ]] || die "BREEZE_VERSION is not set in ${ENV_FILE}."
for image in "${IMAGES[@]}"; do
  log "Pulling ghcr.io/lanternops/breeze/${image}:${version} ..."
  podman pull --quiet "ghcr.io/lanternops/breeze/${image}:${version}" >/dev/null \
    || die "ghcr.io/lanternops/breeze/${image}:${version} has no published image. A git tag existing is not proof an image was published — check https://github.com/orgs/lanternops/packages for the newest tag that actually has all four images (api/web/portal/binaries)."
done

log "== Redis secret file (podman doesn't materialize Compose's environment-sourced secrets) =="
redis_password="$(env_get REDIS_PASSWORD)"
[[ -n "${redis_password}" && "${redis_password}" != "__GENERATE_ME__" ]] || die "REDIS_PASSWORD is empty or the __GENERATE_ME__ placeholder in ${ENV_FILE}."
mkdir -p "${SECRETS_DIR}"
chmod 700 "${SECRETS_DIR}"
printf '%s\n' "${redis_password}" > "${SECRETS_DIR}/redis_password"
chmod 644 "${SECRETS_DIR}/redis_password"   # 600 is unreadable to the container's remapped UID — see doc §5

log "== Checking for unescaped '\$' in .env values (breaks Compose interpolation) =="
# A bare $WORD or ${WORD} inside a .env VALUE gets re-interpolated by Compose
# itself when it substitutes that value into the YAML — if WORD isn't an
# actual variable, Compose silently blanks it (`config` prints a "variable is
# not set" warning), silently truncating whatever secret held it. This is
# exactly how BREEZE_BOOTSTRAP_ADMIN_PASSWORD=$$$Fk21102003$$$ broke a real
# deploy: the intended literal `$` needed `$$` escaping and wasn't given it.
# Catch it here instead of as a mystifying container-exited-1 later.
config_warnings="$(cd "${REPO_ROOT}" && podman compose "${COMPOSE_FILES[@]}" config 2>&1 >/dev/null || true)"
if grep -q 'variable is not set' <<<"${config_warnings}"; then
  log "Compose reported unset-variable warnings while resolving ${ENV_FILE}:"
  echo "${config_warnings}" | grep 'variable is not set' >&2
  die "One of your .env values contains a literal '\$' that needs to be escaped as '\$\$' for Compose (e.g. a password like \$Foo123 must be written \$\$Foo123). Find it, fix the escaping, and re-run."
fi

log "== podman compose up -d =="
if ! (cd "${REPO_ROOT}" && podman compose "${COMPOSE_FILES[@]}" up -d); then
  log "'up -d' failed — dumping the last 40 log lines from any non-running core service:"
  for name in "${HEALTH_SERVICES[@]}"; do
    state="$(podman inspect "${name}" --format '{{.State.Status}}' 2>/dev/null || echo "missing")"
    if [[ "${state}" != "running" ]]; then
      log "--- ${name} (state: ${state}) ---"
      podman logs --tail 40 "${name}" 2>&1 || true
    fi
  done
  die "podman compose up -d failed — see logs above for the actual cause."
fi

log "== Waiting for containers to report healthy (timeout ${HEALTH_TIMEOUT_SECONDS}s) =="
deadline=$((SECONDS + HEALTH_TIMEOUT_SECONDS))
for name in "${HEALTH_SERVICES[@]}"; do
  while true; do
    status="$(podman inspect "${name}" --format '{{.State.Health.Status}}' 2>/dev/null || echo "missing")"
    [[ "${status}" == "healthy" ]] && { log "${name}: healthy"; break; }
    if (( SECONDS >= deadline )); then
      log "${name} did not become healthy in time (last status: ${status}). Recent logs:"
      podman logs --tail 30 "${name}" 2>&1 || true
      die "${name} failed to become healthy."
    fi
    sleep 3
  done
done

log "== Smoke test =="
health_code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${CADDY_HOST_PORT}/health" || echo "000")"
config_code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${CADDY_HOST_PORT}/api/v1/config" || echo "000")"
[[ "${health_code}" == "200" ]] || die "GET /health returned ${health_code}, expected 200."
[[ "${config_code}" == "200" ]] || die "GET /api/v1/config returned ${config_code}, expected 200 (a redirect loop here usually means the Cloudflare-Tunnel-http-origin fix is needed — see --behind-cloudflare-tunnel-http-origin above)."

log "== Done. Stack is up and healthy on http://127.0.0.1:${CADDY_HOST_PORT} =="
${BEHIND_CF_TUNNEL_HTTP_ORIGIN} || log "If this deploy sits behind a Cloudflare Tunnel with a plain-HTTP origin, re-run with --behind-cloudflare-tunnel-http-origin."
