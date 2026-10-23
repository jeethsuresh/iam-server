#!/usr/bin/env bash
# Contract: diagnose_forge_image must restart the app after ensure_forge_app_image,
# which only creates the container (Forge tagging needs create, not start).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIAGNOSE="$SCRIPT_DIR/../diagnose_forge_image.sh"

if [[ ! -f "$DIAGNOSE" ]]; then
  echo "FAIL: missing $DIAGNOSE" >&2
  exit 1
fi

if ! grep -q 'ensure_forge_app_image' "$DIAGNOSE"; then
  echo "FAIL: diagnose script must call ensure_forge_app_image" >&2
  exit 1
fi

# After ensure, the live stack must be brought back up (create-only leaves app stopped).
if ! awk '
  /ensure_forge_app_image/ { seen_ensure=1; next }
  seen_ensure && /compose_cmd up -d app/ { found=1 }
  END { exit(found ? 0 : 1) }
' "$DIAGNOSE"; then
  echo "FAIL: diagnose_forge_image.sh must run 'compose_cmd up -d app' after ensure_forge_app_image" >&2
  exit 1
fi

echo "diagnose_forge_image_test.sh: OK"
