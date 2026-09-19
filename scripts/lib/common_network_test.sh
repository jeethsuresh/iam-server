#!/usr/bin/env bash
# Unit test for ensure_compose_network (mock docker on PATH).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

MOCK_BIN="$TMP/bin"
mkdir -p "$MOCK_BIN"
STATE="$TMP/state"
mkdir -p "$STATE"

# Mock docker: network with empty compose label (legacy v1), one attached container.
cat >"$MOCK_BIN/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${MOCK_DOCKER_STATE:?}"
cmd="${1:-}"
shift || true
case "$cmd" in
  network)
    sub="${1:-}"; shift || true
    case "$sub" in
      inspect)
        # support: docker network inspect NET
        # support: docker network inspect -f TEMPLATE NET
        fmt=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            -f|--format) fmt="$2"; shift 2 ;;
            *) net="$1"; shift ;;
          esac
        done
        [[ -f "$STATE_DIR/networks/$net" ]] || exit 1
        label="$(cat "$STATE_DIR/networks/$net")"
        if [[ -n "$fmt" ]]; then
          if [[ "$fmt" == *'Containers'* ]]; then
            if [[ -f "$STATE_DIR/network_containers/$net" ]]; then
              cat "$STATE_DIR/network_containers/$net"
            fi
            exit 0
          fi
          # {{index .Labels "com.docker.compose.network"}}
          printf '%s' "$label"
          exit 0
        fi
        echo "{}"
        ;;
      rm)
        net="$1"
        rm -f "$STATE_DIR/networks/$net"
        echo "removed $net"
        ;;
      *) exit 1 ;;
    esac
    ;;
  rm)
    # docker rm -f NAME
    shift || true  # -f
    name="${1:-}"
    rm -f "$STATE_DIR/containers/$name"
    echo "removed container $name"
    ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$MOCK_BIN/docker"

export PATH="$MOCK_BIN:$PATH"
export MOCK_DOCKER_STATE="$STATE"
export COMPOSE_PROJECT_NAME="iam-server"

mkdir -p "$STATE/networks" "$STATE/network_containers" "$STATE/containers"
# Stale legacy network (empty label)
printf '' >"$STATE/networks/iam-server_default"
printf 'old_postgres\n' >"$STATE/network_containers/iam-server_default"
touch "$STATE/containers/old_postgres"

# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/common.sh"

ensure_compose_network

if [[ -f "$STATE/networks/iam-server_default" ]]; then
  echo "FAIL: stale network was not removed" >&2
  exit 1
fi
if [[ -f "$STATE/containers/old_postgres" ]]; then
  echo "FAIL: attached container was not removed" >&2
  exit 1
fi

# Healthy modern network must be left alone
printf 'default' >"$STATE/networks/iam-server_default"
ensure_compose_network
label="$(cat "$STATE/networks/iam-server_default")"
if [[ "$label" != "default" ]]; then
  echo "FAIL: modern network was incorrectly removed" >&2
  exit 1
fi

echo "common_network_test.sh: OK"
