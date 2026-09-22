#!/usr/bin/env bash
# Probe what Forge release tagging likely sees for the compose app image.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-iam-server}"
export COMPOSE_PROJECT_NAME PROJECT_NAME="$COMPOSE_PROJECT_NAME"

echo "=== docker image inspect iam-server:latest ==="
docker image inspect iam-server:latest --format 'Id={{.Id}} RepoTags={{json .RepoTags}}' 2>&1 || echo "(missing)"
echo "=== docker image inspect localhost/iam-server:latest ==="
docker image inspect localhost/iam-server:latest --format 'Id={{.Id}} RepoTags={{json .RepoTags}}' 2>&1 || echo "(missing)"
echo "=== docker images (filtered) ==="
docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>&1 | grep -E 'iam-server|REPOSITORY' || true
echo "=== compose images (table) ==="
compose_cmd images 2>&1 || true
echo "=== compose images --format json ==="
compose_cmd images --format json 2>&1 || true
echo "=== compose ps -a ==="
compose_cmd ps -a 2>&1 || true
echo "=== container inspect Image / Config.Image / ImageName ==="
for c in iam-server-app-1; do
  echo "-- $c --"
  docker inspect -f 'Image={{.Image}} Config.Image={{.Config.Image}}' "$c" 2>&1 || echo "(no container)"
done
echo "=== ensure_forge_app_image ==="
ensure_forge_app_image
# ensure_forge_app_image only creates the app container (Forge tagging needs that).
# Restore a running stack so diagnose does not leave production Created/stopped.
echo "=== restore running app (compose up -d app) ==="
compose_cmd up -d app
echo "=== post-ensure compose images ==="
compose_cmd images 2>&1 || true
echo "diagnose_forge_image.sh: OK"
