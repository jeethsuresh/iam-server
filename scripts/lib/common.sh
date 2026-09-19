#!/usr/bin/env bash
# Shared helpers for root pipeline scripts.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-lakehouse}"
PROJECT_NAME="${PROJECT_NAME:-$COMPOSE_PROJECT_NAME}"
HOST_PORT="${HOST_PORT:-4000}"

export COMPOSE_PROJECT_NAME PROJECT_NAME HOST_PORT COMPOSE_FILE ROOT_DIR

# Remove stale Compose default networks left by older compose/docker that lack
# com.docker.compose.network=default (Compose v2 refuses to reuse them).
ensure_compose_network() {
  local net="${COMPOSE_PROJECT_NAME}_default"
  local label=""
  if ! label="$(docker network inspect -f '{{index .Labels "com.docker.compose.network"}}' "$net" 2>/dev/null)"; then
    return 0
  fi
  if [[ "$label" == "default" ]]; then
    return 0
  fi
  echo "common.sh: removing stale compose network $net (label='$label', expected 'default')" >&2
  local containers=""
  containers="$(docker network inspect -f '{{range .Containers}}{{.Name}}{{println}}{{end}}' "$net" 2>/dev/null || true)"
  if [[ -n "$containers" ]]; then
    while IFS= read -r c; do
      [[ -z "$c" ]] && continue
      docker rm -f "$c" >/dev/null 2>&1 || true
    done <<<"$containers"
  fi
  docker network rm "$net" >/dev/null 2>&1 || true
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
        export HOST_PORT
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
