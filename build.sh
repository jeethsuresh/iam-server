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
  # Classic builder emits "Successfully tagged" which Forge release tagging parses.
  export DOCKER_BUILDKIT=0
  export COMPOSE_DOCKER_CLI_BUILD=0
  compose_cmd build
  compose_cmd create web >/dev/null
  if ! docker image inspect iam-server:latest >/dev/null 2>&1; then
    echo "build.sh: iam-server:latest missing after compose build" >&2
    docker images >&2 || true
    exit 1
  fi
  image_id="$(docker image inspect -f '{{.Id}}' iam-server:latest)"
  echo "Successfully tagged iam-server:latest"
  echo "build.sh: app image iam-server:latest (${image_id}) ready" >&2
fi

echo "build.sh: OK (project=$COMPOSE_PROJECT_NAME host_port=$HOST_PORT)"
