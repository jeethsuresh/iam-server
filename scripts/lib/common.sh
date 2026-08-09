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

compose_cmd() {
  docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" "$@"
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
