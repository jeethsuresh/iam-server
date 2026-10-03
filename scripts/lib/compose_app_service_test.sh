#!/usr/bin/env bash
# Regression: Forge release tagging hardcodes services.app.image / `compose images -q app`.
# Renaming the compose service (e.g. to web) makes Forge report image=(unknown).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE="$ROOT_DIR/docker-compose.yml"

if [[ ! -f "$COMPOSE" ]]; then
  echo "FAIL: missing $COMPOSE" >&2
  exit 1
fi

# Top-level service key must be exactly "app" (not web/iam/lakehouse).
# Note: awk END runs even after exit, so stash the code and exit once from END.
if ! awk '
  /^[[:space:]]*services:[[:space:]]*$/ { in_services=1; next }
  in_services && /^[^[:space:]#]/ { in_services=0 }
  in_services && /^  [a-zA-Z0-9_-]+:[[:space:]]*$/ {
    svc=$1; sub(/:.*/,"",svc)
    if (svc=="app") found=1
  }
  END { exit(found ? 0 : 1) }
' "$COMPOSE"; then
  echo "FAIL: docker-compose.yml must define a top-level service named app (Forge release tagging)" >&2
  exit 1
fi

if ! grep -E '^[[:space:]]+image:[[:space:]]+iam-server:latest[[:space:]]*$' "$COMPOSE" >/dev/null; then
  echo "FAIL: app service must set image: iam-server:latest for Forge tagging" >&2
  exit 1
fi

# Guard against a reintroduced web app service that would orphan Forge lookups.
if awk '
  /^[[:space:]]*services:[[:space:]]*$/ { in_services=1; next }
  in_services && /^[^[:space:]#]/ { in_services=0 }
  in_services && /^  web:[[:space:]]*$/ { found_web=1 }
  END { exit(found_web ? 0 : 1) }
' "$COMPOSE"; then
  echo "FAIL: docker-compose.yml must not define a top-level web service (use app)" >&2
  exit 1
fi

# Forge staging health-checks HTTP with compose defaults. Defaulting MIX_ENV to prod
# loads runtime.exs fail-closed secret checks against the docker-dev placeholders and
# the app never listens (staging health check → fetch failed).
if ! grep -E '^[[:space:]]+MIX_ENV:[[:space:]]+\$\{APP_MIX_ENV:-dev\}[[:space:]]*$' "$COMPOSE" >/dev/null; then
  echo "FAIL: app MIX_ENV must default to APP_MIX_ENV:-dev so Forge staging boots with compose secrets" >&2
  exit 1
fi

echo "compose_app_service_test.sh: OK"
