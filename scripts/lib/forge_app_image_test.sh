#!/usr/bin/env bash
# Unit test for ensure_forge_app_image (mock docker on PATH).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

MOCK_BIN="$TMP/bin"
STATE="$TMP/state"
mkdir -p "$MOCK_BIN" "$STATE/images" "$STATE/tags" "$STATE/compose_calls"

# Mock docker: image inspect/tag + compose create/rm/images.
cat >"$MOCK_BIN/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${MOCK_DOCKER_STATE:?}"
cmd="${1:-}"
shift || true
case "$cmd" in
  image)
    sub="${1:-}"; shift || true
    case "$sub" in
      inspect)
        fmt=""
        ref=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            -f|--format) fmt="$2"; shift 2 ;;
            *) ref="$1"; shift ;;
          esac
        done
        safe="$(printf '%s' "$ref" | tr '/:' '__')"
        [[ -f "$STATE_DIR/images/$safe" ]] || exit 1
        if [[ -n "$fmt" ]]; then
          cat "$STATE_DIR/images/$safe"
        else
          echo "{}"
        fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  tag)
    src="${1:-}"; dst="${2:-}"
    echo "$src->$dst" >>"$STATE_DIR/tags/log"
    safe="$(printf '%s' "$dst" | tr '/:' '__')"
    if [[ "$src" == sha256:* ]]; then
      printf '%s\n' "$src" >"$STATE_DIR/images/$safe"
    else
      src_safe="$(printf '%s' "$src" | tr '/:' '__')"
      cp "$STATE_DIR/images/$src_safe" "$STATE_DIR/images/$safe"
    fi
    ;;
  compose)
    echo "$*" >>"$STATE_DIR/compose_calls/log"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -f|-p) shift 2 ;;
        *) break ;;
      esac
    done
    sub="${1:-}"; shift || true
    case "$sub" in
      create)
        echo "created $*" >>"$STATE_DIR/compose_calls/create"
        ;;
      rm)
        echo "rm $*" >>"$STATE_DIR/compose_calls/rm"
        ;;
      images)
        if [[ -f "$STATE_DIR/compose_calls/images_override" ]]; then
          cat "$STATE_DIR/compose_calls/images_override"
        else
          echo "CONTAINER REPOSITORY TAG IMAGE_ID"
          echo "proj-web-1 localhost/iam-server latest sha256:deadbeef"
        fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  images)
    # ensure_forge_app_image may dump filtered image list to stderr.
    exit 0
    ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$MOCK_BIN/docker"

export PATH="$MOCK_BIN:$PATH"
export MOCK_DOCKER_STATE="$STATE"
export COMPOSE_PROJECT_NAME="iam-server"
export COMPOSE_FILE="docker-compose.yml"

# Seed Podman-style localhost tag (what compose build leaves).
printf 'sha256:deadbeef\n' >"$STATE/images/localhost_iam-server_latest"
# Stale short name on a different id — ensure must overwrite via digest tag.
printf 'sha256:stalebeef\n' >"$STATE/images/iam-server_latest"

# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/common.sh"

ensure_compose_network() { return 0; }
COMPOSE_NETWORK_ENSURED=1

if ! declare -F ensure_forge_app_image >/dev/null; then
  echo "FAIL: ensure_forge_app_image is not defined (expected in common.sh)" >&2
  exit 1
fi

out="$(ensure_forge_app_image 2>"$TMP/err")"

if ! grep -q 'Successfully tagged iam-server:latest' <<<"$out"; then
  echo "FAIL: stdout missing Successfully tagged iam-server:latest" >&2
  echo "stdout=$out" >&2
  exit 1
fi
if ! grep -q 'Successfully tagged localhost/iam-server:latest' <<<"$out"; then
  echo "FAIL: stdout missing Successfully tagged localhost/iam-server:latest" >&2
  echo "stdout=$out" >&2
  exit 1
fi
if ! grep -q 'Successfully built deadbeef' <<<"$out"; then
  echo "FAIL: stdout missing Successfully built short image id" >&2
  echo "stdout=$out" >&2
  exit 1
fi
if ! grep -q 'sha256:deadbeef->iam-server:latest' "$STATE/tags/log"; then
  echo "FAIL: did not digest-tag iam-server:latest onto current image" >&2
  cat "$STATE/tags/log" >&2 || true
  exit 1
fi
if ! grep -q 'localhost/iam-server_web:latest' "$STATE/tags/log"; then
  echo "FAIL: did not docker tag localhost/iam-server_web:latest" >&2
  cat "$STATE/tags/log" >&2 || true
  exit 1
fi
if [[ ! -f "$STATE/compose_calls/rm" ]] || ! grep -q 'web' "$STATE/compose_calls/rm"; then
  echo "FAIL: did not compose rm web before recreate" >&2
  cat "$STATE/compose_calls/log" >&2 || true
  exit 1
fi
if [[ ! -f "$STATE/compose_calls/create" ]] || ! grep -q 'web' "$STATE/compose_calls/create"; then
  echo "FAIL: did not compose create web" >&2
  cat "$STATE/compose_calls/log" >&2 || true
  exit 1
fi
if ! grep -q 'app image iam-server:latest' "$TMP/err"; then
  echo "FAIL: stderr missing app image ready line" >&2
  cat "$TMP/err" >&2
  exit 1
fi
# Short name must now resolve to the current digest, not the stale one.
if [[ "$(cat "$STATE/images/iam-server_latest")" != $'sha256:deadbeef' ]]; then
  echo "FAIL: iam-server:latest was not moved onto sha256:deadbeef" >&2
  cat "$STATE/images/iam-server_latest" >&2
  exit 1
fi

# Missing image must fail clearly.
rm -f "$STATE/images/"*
if ensure_forge_app_image >/dev/null 2>"$TMP/err2"; then
  echo "FAIL: ensure_forge_app_image should fail when image missing" >&2
  exit 1
fi
if ! grep -qi 'missing\|not found\|iam-server:latest' "$TMP/err2"; then
  echo "FAIL: missing-image error unclear" >&2
  cat "$TMP/err2" >&2
  exit 1
fi

# compose images without app row must fail.
printf 'sha256:deadbeef\n' >"$STATE/images/localhost_iam-server_latest"
printf 'sha256:deadbeef\n' >"$STATE/images/iam-server_latest"
cat >"$STATE/compose_calls/images_override" <<'EOF'
CONTAINER REPOSITORY TAG IMAGE_ID
proj-postgres-1 postgres 16-alpine sha256:pg
EOF
if ensure_forge_app_image >/dev/null 2>"$TMP/err3"; then
  echo "FAIL: ensure_forge_app_image should fail when compose images lacks app row" >&2
  exit 1
fi
if ! grep -qi 'no resolvable\|unknown' "$TMP/err3"; then
  echo "FAIL: expected no-resolvable error when compose images lacks app" >&2
  cat "$TMP/err3" >&2
  exit 1
fi

echo "forge_app_image_test.sh: OK"
