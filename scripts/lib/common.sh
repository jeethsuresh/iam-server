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

# Remove stale Compose default networks left by older compose/docker that lack
# com.docker.compose.network=default (Compose v2 refuses to reuse them).
ensure_compose_network() {
  local net="${COMPOSE_PROJECT_NAME}_default"
  # Existence check must not rely on label templates (nil Labels can error).
  if ! docker network inspect "$net" >/dev/null 2>&1; then
    return 0
  fi
  local label=""
  label="$(docker network inspect -f '{{index .Labels "com.docker.compose.network"}}' "$net" 2>/dev/null || true)"
  if [[ "$label" == "default" ]]; then
    return 0
  fi
  echo "common.sh: removing stale compose network $net (label='$label', expected 'default')" >&2

  # Prefer container IDs (map keys); Names alone can be empty on some engines.
  # Also sweep legacy project containers (e.g. compose v1 name_service_N) that
  # may still hold endpoints on the stale network.
  local ids=""
  ids="$(docker network inspect -f '{{range $id, $c := .Containers}}{{println $id}}{{end}}' "$net" 2>/dev/null || true)"
  ids+=$'\n'
  ids+="$(docker ps -aq --filter "network=$net" 2>/dev/null || true)"
  ids+=$'\n'
  ids+="$(docker ps -aq --filter "name=^${COMPOSE_PROJECT_NAME}_" 2>/dev/null || true)"
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
}

compose_cmd() {
  ensure_compose_network
  docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" "$@"
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
