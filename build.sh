#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/scripts/lib/common.sh"

SKIP_INSTALL=0
REMAINING_ARGS=()

usage() {
  cat <<EOF
Usage: ./build.sh [options]

Compile the Lakehouse umbrella (mix deps + compile).
When mix is not on PATH, builds the compose image instead (Dockerfile compiles).

EOF
  print_common_help
  cat <<EOF
Build flags:
  --skip-install   Skip mix deps.get (host mix only)
EOF
}

if ! parse_common_args "$@"; then
  usage
  exit 0
fi
if ((${#REMAINING_ARGS[@]})); then
  set -- "${REMAINING_ARGS[@]}"
else
  set --
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-install) SKIP_INSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    "") shift ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

export MIX_ENV="${MIX_ENV:-dev}"

if have_mix; then
  if [[ "$SKIP_INSTALL" -eq 0 ]]; then
    mix deps.get
  fi
  mix compile
else
  require_docker
  echo "build.sh: mix not found; building via docker compose (project=$COMPOSE_PROJECT_NAME)"
  compose_cmd build
  echo "build.sh: compose images:" >&2
  compose_cmd images >&2 || true
  echo "build.sh: docker images (iam-server*):" >&2
  docker images 'iam-server*' --format 'table {{.Repository}}:{{.Tag}}	{{.ID}}	{{.CreatedSince}}' >&2 || true
  # Tag common aliases Forge may look up
  if docker image inspect iam-server:latest >/dev/null 2>&1; then
    docker tag iam-server:latest "${COMPOSE_PROJECT_NAME}:latest" || true
    docker tag iam-server:latest "${COMPOSE_PROJECT_NAME}-web:latest" || true
    docker tag iam-server:latest "${COMPOSE_PROJECT_NAME}-app:latest" || true
    echo "build.sh: app image iam-server:latest ready (+ aliases)" >&2
  else
    echo "build.sh: iam-server:latest missing after compose build" >&2
    docker images >&2 || true
    exit 1
  fi
fi

echo "build.sh: OK (project=$COMPOSE_PROJECT_NAME host_port=$HOST_PORT)"
