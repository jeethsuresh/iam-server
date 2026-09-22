#!/usr/bin/env bash
# Shared helpers for root pipeline scripts.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-lakehouse}"
PROJECT_NAME="${PROJECT_NAME:-$COMPOSE_PROJECT_NAME}"
HOST_PORT="${HOST_PORT:-4000}"

# Host publish of Postgres is only for local tooling; compose services use
# postgres:5432 on the internal network. Avoid default 5432 so Forge hosts that
# already bind system Postgres do not fail `compose up`.
if [[ -n "${POSTGRES_HOST_PORT:-}" ]]; then
  POSTGRES_HOST_PORT_EXPLICIT=1
else
  POSTGRES_HOST_PORT=$((HOST_PORT + 11432))
  POSTGRES_HOST_PORT_EXPLICIT=0
fi

export COMPOSE_PROJECT_NAME PROJECT_NAME HOST_PORT POSTGRES_HOST_PORT POSTGRES_HOST_PORT_EXPLICIT COMPOSE_FILE ROOT_DIR

# Forge hosts often lack buildx; Bake then produces no local app image for release tagging.
export COMPOSE_BAKE="${COMPOSE_BAKE:-false}"

# Compose v2 requires com.docker.compose.network=default on the project network.
# Podman (Forge) often recreates that network with an empty label, so we remove
# stale networks and pre-create a correctly labeled one before any compose call.
# Run at most once per process so we never tear down a healthy network mid-script.
COMPOSE_NETWORK_ENSURED=0

ensure_compose_network() {
  local net="${COMPOSE_PROJECT_NAME}_default"
  local label=""

  if docker network inspect "$net" >/dev/null 2>&1; then
    # Existence check must not rely on label templates alone (nil Labels can error).
    label="$(docker network inspect -f '{{index .Labels "com.docker.compose.network"}}' "$net" 2>/dev/null || true)"
    if [[ "$label" == "default" ]]; then
      return 0
    fi
    echo "common.sh: removing stale compose network $net (label='$label', expected 'default')" >&2

    # Prefer container IDs attached to this network only (never sweep by project name
    # prefix — that can kill a healthy postgres mid-test when labels are misread).
    local ids=""
    ids="$(docker network inspect -f '{{range $id, $c := .Containers}}{{println $id}}{{end}}' "$net" 2>/dev/null || true)"
    ids+=$'\n'
    ids+="$(docker ps -aq --filter "network=$net" 2>/dev/null || true)"
    if [[ -n "$ids" ]]; then
      while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        docker network disconnect -f "$net" "$id" >/dev/null 2>&1 || true
        docker rm -f "$id" >/dev/null 2>&1 || true
      done <<<"$ids"
    fi

    if ! docker network rm "$net" >/dev/null 2>&1; then
      # Last resort: still attached endpoints
      ids="$(docker network inspect -f '{{range $id, $c := .Containers}}{{println $id}}{{end}}' "$net" 2>/dev/null || true)"
      ids+=$'\n'
      ids+="$(docker ps -aq --filter "network=$net" 2>/dev/null || true)"
      while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        docker network disconnect -f "$net" "$id" >/dev/null 2>&1 || true
        docker rm -f "$id" >/dev/null 2>&1 || true
      done <<<"$ids"
      docker network rm "$net" >/dev/null 2>&1 || true
    fi

    if docker network inspect "$net" >/dev/null 2>&1; then
      echo "common.sh: failed to remove stale network $net; refuse to continue" >&2
      return 1
    fi
  fi

  # Pre-create so Compose/Podman reuse a correctly labeled network instead of
  # recreating one with an empty com.docker.compose.network label.
  echo "common.sh: creating compose network $net with compose labels" >&2
  if ! docker network create \
    --label "com.docker.compose.network=default" \
    --label "com.docker.compose.project=${COMPOSE_PROJECT_NAME}" \
    "$net" >/dev/null; then
    echo "common.sh: failed to create compose network $net" >&2
    return 1
  fi
}

compose_cmd() {
  if [[ "${COMPOSE_NETWORK_ENSURED}" -eq 0 ]]; then
    ensure_compose_network
    COMPOSE_NETWORK_ENSURED=1
  fi
  docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" "$@"
}

# Forge release tagging resolves the compose app image via `compose images`
# (needs a created web container) and/or build-log lines "Successfully tagged ...".
# Call after build (and again after test, which may destroy the web container).
ensure_forge_app_image() {
  local image_id=""
  local primary="iam-server:latest"
  local images_out=""
  local short_id=""

  if ! docker image inspect "$primary" >/dev/null 2>&1; then
    if docker image inspect "localhost/iam-server:latest" >/dev/null 2>&1; then
      docker tag "localhost/iam-server:latest" "$primary"
    else
      echo "ensure_forge_app_image: iam-server:latest missing after compose build" >&2
      docker images >&2 || true
      return 1
    fi
  fi

  image_id="$(docker image inspect -f '{{.Id}}' "$primary")"
  short_id="${image_id#sha256:}"
  short_id="${short_id:0:12}"
  # Podman-compatible aliases used by this Forge host.
  docker tag "$primary" localhost/iam-server:latest 2>/dev/null || true
  docker tag "$primary" localhost/iam-server_web:latest 2>/dev/null || true
  docker tag "$primary" iam-server_web:latest 2>/dev/null || true
  # compose images only lists images for created containers.
  # Re-check network labels: Podman may recreate the network mid-script.
  # Note: Podman compose create does not support --no-deps (unlike `run`).
  ensure_compose_network
  COMPOSE_NETWORK_ENSURED=1
  compose_cmd create web >/dev/null
  echo "Successfully tagged iam-server:latest"
  echo "Successfully tagged localhost/iam-server:latest"
  echo "Successfully built ${short_id}"
  echo "ensure_forge_app_image: app image iam-server:latest (${image_id}) ready" >&2
  images_out="$(compose_cmd images 2>/dev/null || true)"
  printf '%s\n' "$images_out" >&2
  # Forge looks up the web service row; refuse to continue if it is missing.
  if ! grep -E 'iam-server-web-1|[[:space:]]web[[:space:]]' <<<"$images_out" >/dev/null 2>&1; then
    # Prefer matching repository name if container name format differs.
    if ! grep -E 'iam-server(_web)?[[:space:]]+latest|localhost/iam-server' <<<"$images_out" >/dev/null 2>&1; then
      echo "ensure_forge_app_image: compose images has no resolvable iam-server app image" >&2
      return 1
    fi
  fi
  if grep -E 'iam-server.*[[:space:]](\(unknown\)|<none>|unknown)[[:space:]]' <<<"$images_out" >/dev/null 2>&1; then
    echo "ensure_forge_app_image: compose images still reports unknown/<none> for app image" >&2
    return 1
  fi
}

have_mix() {
  command -v mix >/dev/null 2>&1
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required when mix is not installed on PATH" >&2
    exit 127
  fi
}

print_common_help() {
  cat <<EOF
Common flags:
  --project-name NAME   Compose project name (default: lakehouse)
  --host-port PORT      Host port for the app (default: 4000)
  --compose-file PATH   Compose file (default: docker-compose.yml)
  -h, --help            Show help
EOF
}

parse_common_args() {
  REMAINING_ARGS=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --project-name)
        COMPOSE_PROJECT_NAME="$2"
        PROJECT_NAME="$2"
        export COMPOSE_PROJECT_NAME PROJECT_NAME
        shift 2
        ;;
      --host-port|--port)
        HOST_PORT="$2"
        # Refresh derived publish port when caller did not set POSTGRES_HOST_PORT.
        if [[ -z "${POSTGRES_HOST_PORT_EXPLICIT:-}" ]]; then
          POSTGRES_HOST_PORT=$((HOST_PORT + 11432))
        fi
        export HOST_PORT POSTGRES_HOST_PORT
        shift 2
        ;;
      --compose-file)
        COMPOSE_FILE="$2"
        export COMPOSE_FILE
        shift 2
        ;;
      -h|--help)
        return 2
        ;;
      *)
        REMAINING_ARGS+=("$1")
        shift
        ;;
    esac
  done
  return 0
}
