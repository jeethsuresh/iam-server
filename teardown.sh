#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/scripts/lib/common.sh"

REMOVE_VOLUMES=0
REMOVE_ORPHANS=1
REMAINING_ARGS=()

usage() {
  cat <<EOF
Usage: ./teardown.sh [options]

Stop compose stack for this project.

EOF
  print_common_help
  cat <<EOF
Teardown flags:
  --volumes              Also remove named volumes
  --no-remove-orphans    Keep orphan containers
EOF
}

if ! parse_common_args "$@"; then
  usage
  exit 0
fi
set -- "${REMAINING_ARGS[@]:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --volumes) REMOVE_VOLUMES=1; shift ;;
    --no-remove-orphans) REMOVE_ORPHANS=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

DOWN_ARGS=(down)
if [[ "$REMOVE_ORPHANS" -eq 1 ]]; then
  DOWN_ARGS+=(--remove-orphans)
fi
if [[ "$REMOVE_VOLUMES" -eq 1 ]]; then
  DOWN_ARGS+=(-v)
fi

compose_cmd "${DOWN_ARGS[@]}"
echo "teardown.sh: OK (project=$COMPOSE_PROJECT_NAME)"
