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

# Mock docker: network with empty compose label (legacy), endpoint keyed by ID.
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
              # IDs one per line (map keys)
              cat "$STATE_DIR/network_containers/$net"
            fi
            exit 0
          fi
          printf '%s' "$label"
          exit 0
        fi
        echo "{}"
        ;;
      disconnect)
        # docker network disconnect -f NET ID
        shift || true # -f
        net="${1:-}"; id="${2:-}"
        if [[ -f "$STATE_DIR/network_containers/$net" ]]; then
          grep -vx "$id" "$STATE_DIR/network_containers/$net" >"$STATE_DIR/network_containers/$net.tmp" || true
          mv "$STATE_DIR/network_containers/$net.tmp" "$STATE_DIR/network_containers/$net"
        fi
        ;;
      rm)
        net="$1"
        if [[ -f "$STATE_DIR/network_containers/$net" ]] && [[ -s "$STATE_DIR/network_containers/$net" ]]; then
          echo "network has active endpoints" >&2
          exit 1
        fi
        rm -f "$STATE_DIR/networks/$net"
        echo "removed $net"
        ;;
      *) exit 1 ;;
    esac
    ;;
  ps)
    # docker ps -aq --filter network=NET | --filter name=PREFIX
    net=""
    name_filt=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --filter)
          filt="$2"; shift 2
          case "$filt" in
            network=*) net="${filt#network=}" ;;
            name=*) name_filt="${filt#name=}" ;;
          esac
          ;;
        -aq|-q|-a) shift ;;
        *) shift ;;
      esac
    done
    if [[ -n "$net" && -f "$STATE_DIR/network_containers/$net" ]]; then
      cat "$STATE_DIR/network_containers/$net"
    fi
    if [[ -n "$name_filt" ]]; then
      # Strip leading ^ used by ensure_compose_network.
      prefix="${name_filt#^}"
      safe="$(printf '%s' "$prefix" | tr -c 'A-Za-z0-9._-' '_')"
      if [[ -f "$STATE_DIR/name_filters/$safe" ]]; then
        cat "$STATE_DIR/name_filters/$safe"
      fi
    fi
    ;;
  rm)
    # docker rm -f ID
    shift || true  # -f
    id="${1:-}"
    rm -f "$STATE_DIR/containers/$id"
    for f in "$STATE_DIR"/network_containers/*; do
      [[ -f "$f" ]] || continue
      grep -vx "$id" "$f" >"$f.tmp" || true
      mv "$f.tmp" "$f"
    done
    echo "removed container $id"
    ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$MOCK_BIN/docker"

export PATH="$MOCK_BIN:$PATH"
export MOCK_DOCKER_STATE="$STATE"
export COMPOSE_PROJECT_NAME="iam-server"

mkdir -p "$STATE/networks" "$STATE/network_containers" "$STATE/containers" "$STATE/name_filters"
# Stale legacy network (empty label); endpoint only has an ID (no usable name).
printf '' >"$STATE/networks/iam-server_default"
printf 'abc123def\n' >"$STATE/network_containers/iam-server_default"
touch "$STATE/containers/abc123def"

# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/common.sh"

ensure_compose_network

if [[ -f "$STATE/networks/iam-server_default" ]]; then
  echo "FAIL: stale network was not removed" >&2
  exit 1
fi
if [[ -f "$STATE/containers/abc123def" ]]; then
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

# Missing network is a no-op
rm -f "$STATE/networks/iam-server_default"
ensure_compose_network

echo "common_network_test.sh: OK"
