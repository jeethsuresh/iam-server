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

EOF
  print_common_help
  cat <<EOF
Build flags:
  --skip-install   Skip mix deps.get
EOF
}

if ! parse_common_args "$@"; then
  usage
  exit 0
fi
set -- "${REMAINING_ARGS[@]:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-install) SKIP_INSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

export MIX_ENV="${MIX_ENV:-dev}"

if [[ "$SKIP_INSTALL" -eq 0 ]]; then
  mix deps.get
fi

mix compile
echo "build.sh: OK (project=$COMPOSE_PROJECT_NAME host_port=$HOST_PORT)"
