#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/scripts/lib/common.sh"

DETACH=1
REMAINING_ARGS=()

usage() {
  cat <<EOF
Usage: ./deploy.sh [options]

Deploy via docker compose up.

EOF
  print_common_help
  cat <<EOF
Deploy flags:
  --detach / --no-detach   Run detached (default) or foreground
EOF
}

if ! parse_common_args "$@"; then
  usage
  exit 0
fi
set -- "${REMAINING_ARGS[@]:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --detach) DETACH=1; shift ;;
    --no-detach) DETACH=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

export PORT="$HOST_PORT"
UP_ARGS=(up --build)
if [[ "$DETACH" -eq 1 ]]; then
  UP_ARGS+=(-d)
fi

compose_cmd "${UP_ARGS[@]}"
echo "deploy.sh: OK → http://localhost:${HOST_PORT} (project=$COMPOSE_PROJECT_NAME)"
