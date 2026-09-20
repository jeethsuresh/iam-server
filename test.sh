#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/scripts/lib/common.sh"

RUN_UNIT=1
RUN_API=1
RUN_BROWSER=1
EXCLUDE_BROWSER=0
WATCH=0
COVERAGE=0
STARTED_PG=0
REMAINING_ARGS=()

usage() {
  cat <<EOF
Usage: ./test.sh [options]

Run Lakehouse tests (ExUnit + Cucumber API/BDD + Wallaby browser).

EOF
  print_common_help
  cat <<EOF
Test flags:
  --unit             Only domain ExUnit (iam + matrix apps)
  --api              Only @api BDD (via lakehouse_web)
  --browser          Only @browser BDD
  --exclude-browser  Skip browser tests (unit + api)
  --watch            mix test --listen-on-stdin
  --coverage         mix test --cover
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
    --unit) RUN_UNIT=1; RUN_API=0; RUN_BROWSER=0; shift ;;
    --api) RUN_UNIT=0; RUN_API=1; RUN_BROWSER=0; shift ;;
    --browser) RUN_UNIT=0; RUN_API=0; RUN_BROWSER=1; shift ;;
    --exclude-browser) EXCLUDE_BROWSER=1; RUN_BROWSER=0; shift ;;
    --watch) WATCH=1; shift ;;
    --coverage) COVERAGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    "") shift ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

export MIX_ENV=test
export PORT="${PORT:-4002}"

# Forge deploy hosts often lack host Elixir; run the suite inside compose instead.
run_tests_via_compose() {
  require_docker
  # Fast mocked check for stale-network recovery used by compose_cmd.
  bash "$SCRIPT_DIR/scripts/lib/common_network_test.sh"
  echo "test.sh: mix not found; running tests via docker compose (project=$COMPOSE_PROJECT_NAME)" >&2

  compose_cmd build lakehouse

  # Drop leftover test pgdata so each Forge run gets a clean POSTGRES_USER role.
  docker volume rm "${COMPOSE_PROJECT_NAME}_pgdata_v2" >/dev/null 2>&1 || true

  echo "test.sh: starting postgres..." >&2
  compose_cmd up -d postgres

  local i
  for ((i = 1; i <= 60; i++)); do
    if compose_cmd exec -T postgres pg_isready -U postgres -d postgres >/dev/null 2>&1 \
      && compose_cmd exec -T postgres psql -U postgres -d postgres -c 'SELECT 1' >/dev/null 2>&1; then
      echo "test.sh: postgres ready (attempt $i)" >&2
      break
    fi
    if [[ "$i" -eq 60 ]]; then
      echo "test.sh: Postgres did not become ready" >&2
      compose_cmd logs postgres >&2 || true
      exit 1
    fi
    sleep 1
  done

  # Create the test DB via psql. mix ecto.create under MIX_ENV=test can be OOM-killed
  # while compiling the test env inside constrained Forge agents.
  echo "test.sh: ensuring lakehouse_test database..." >&2
  if ! compose_cmd exec -T postgres \
    psql -U postgres -d postgres -v ON_ERROR_STOP=1 -tc "SELECT 1 FROM pg_database WHERE datname = 'lakehouse_test'" \
    | grep -q 1; then
    compose_cmd exec -T postgres \
      psql -U postgres -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE lakehouse_test;"
  fi

  local mix_cmd=(mix test --exclude browser)
  if [[ "$RUN_UNIT" -eq 1 && "$RUN_API" -eq 0 && "$RUN_BROWSER" -eq 0 ]]; then
    mix_cmd=(mix test apps/lakehouse_iam/test apps/lakehouse_matrix/test)
  elif [[ "$RUN_API" -eq 1 && "$RUN_UNIT" -eq 0 && "$RUN_BROWSER" -eq 0 ]]; then
    mix_cmd=(mix test --only api apps/lakehouse_web/test)
  elif [[ "$RUN_BROWSER" -eq 1 && "$RUN_UNIT" -eq 0 && "$RUN_API" -eq 0 ]]; then
    echo "test.sh: browser-only suite requires host mix + Chrome; use --exclude-browser on Forge" >&2
    exit 1
  fi

  echo "test.sh: running ${mix_cmd[*]} via compose..." >&2
  compose_cmd run -T --rm --no-deps --entrypoint /bin/sh \
    -e MIX_ENV=test \
    -e POSTGRES_HOST=postgres \
    -e POSTGRES_PORT=5432 \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=postgres \
    -e WALLABY_SKIP=1 \
    -e PORT=4002 \
    lakehouse \
    -c "set -e
mix ecto.migrate -r LakehouseIam.Repo > /tmp/migrate.out 2>&1 || { cat /tmp/migrate.out; exit 1; }
cat /tmp/migrate.out
$(printf '%q ' "${mix_cmd[@]}") > /tmp/test.out 2>&1 || { echo 'mix test failed:'; cat /tmp/test.out; exit 1; }
cat /tmp/test.out
echo test.sh: mix OK"

  echo "test.sh: OK"
}

cleanup() {
  if [[ "$STARTED_PG" -eq 1 ]]; then
    compose_cmd stop postgres >/dev/null 2>&1 || true
    compose_cmd rm -f postgres >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if ! have_mix; then
  run_tests_via_compose
  exit 0
fi

port_open() {
  local port="$1"
  (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1
}

pick_free_port() {
  local p
  for p in $(seq 35432 35500); do
    if ! port_open "$p"; then
      echo "$p"
      return 0
    fi
  done
  echo "No free Postgres host port in 35432-35500" >&2
  exit 1
}

ensure_postgres() {
  if [[ -n "${POSTGRES_HOST:-}" && -n "${POSTGRES_PORT:-}" ]]; then
    return 0
  fi

  if port_open 5432; then
    export POSTGRES_HOST=localhost
    export POSTGRES_PORT=5432
    return 0
  fi

  local pg_port
  pg_port="$(pick_free_port)"
  if [[ "$COMPOSE_PROJECT_NAME" == "lakehouse" ]]; then
    COMPOSE_PROJECT_NAME="lakehouse-test-$$"
    PROJECT_NAME="$COMPOSE_PROJECT_NAME"
    export COMPOSE_PROJECT_NAME PROJECT_NAME
  fi
  export POSTGRES_HOST_PORT="$pg_port"
  export POSTGRES_HOST=localhost
  export POSTGRES_PORT="$pg_port"
  export POSTGRES_USER=postgres
  export POSTGRES_PASSWORD=postgres

  echo "test.sh: starting Postgres via compose (project=$COMPOSE_PROJECT_NAME port=$pg_port)"
  compose_cmd up -d postgres
  STARTED_PG=1

  local i
  for ((i = 1; i <= 60; i++)); do
    if compose_cmd exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "test.sh: Postgres did not become ready" >&2
  exit 1
}

ensure_chrome() {
  if command -v chromedriver >/dev/null 2>&1 && {
    command -v chromium-browser >/dev/null 2>&1 ||
      command -v chromium >/dev/null 2>&1 ||
      command -v google-chrome >/dev/null 2>&1
  }; then
    return 0
  fi

  local tools="$ROOT_DIR/.tools/chrome"
  local marker="$tools/.ready"
  if [[ -f "$marker" ]]; then
    # shellcheck disable=SC1090
    source "$marker"
    export CHROME_PATH CHROMEDRIVER_PATH
    return 0
  fi

  echo "test.sh: downloading Chrome for Testing into .tools/chrome ..."
  mkdir -p "$tools"
  local json version url_chrome url_driver
  json="$(curl -fsSL "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json")"
  version="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["channels"]["Stable"]["version"])')"
  url_chrome="$(printf '%s' "$json" | python3 -c 'import json,sys; d=json.load(sys.stdin)["channels"]["Stable"]["downloads"]["chrome"]; print(next(x["url"] for x in d if x["platform"]=="linux64"))')"
  url_driver="$(printf '%s' "$json" | python3 -c 'import json,sys; d=json.load(sys.stdin)["channels"]["Stable"]["downloads"]["chromedriver"]; print(next(x["url"] for x in d if x["platform"]=="linux64"))')"

  curl -fsSL "$url_chrome" -o "$tools/chrome.zip"
  curl -fsSL "$url_driver" -o "$tools/chromedriver.zip"
  rm -rf "$tools/chrome-linux64" "$tools/chromedriver-linux64"
  unzip -q -o "$tools/chrome.zip" -d "$tools"
  unzip -q -o "$tools/chromedriver.zip" -d "$tools"
  chmod +x "$tools/chrome-linux64/chrome" "$tools/chromedriver-linux64/chromedriver"
  cat >"$marker" <<EOF
export CHROME_PATH="$tools/chrome-linux64/chrome"
export CHROMEDRIVER_PATH="$tools/chromedriver-linux64/chromedriver"
export WALLABY_CHROME_VERSION="$version"
EOF
  # shellcheck disable=SC1090
  source "$marker"
  echo "test.sh: Chrome $version ready"
}

MIX_ARGS=(test)
if [[ "$COVERAGE" -eq 1 ]]; then
  MIX_ARGS+=(--cover)
fi

ensure_postgres

mix ecto.create -r LakehouseIam.Repo --quiet || true
mix ecto.migrate -r LakehouseIam.Repo --quiet

EXCLUDE_ARGS=()
ONLY_ARGS=()

if [[ "$EXCLUDE_BROWSER" -eq 1 || ( "$RUN_BROWSER" -eq 0 && "$RUN_API" -eq 1 ) || ( "$RUN_BROWSER" -eq 0 && "$RUN_UNIT" -eq 1 && "$RUN_API" -eq 0 ) ]]; then
  export WALLABY_SKIP=1
  EXCLUDE_ARGS+=(--exclude browser)
fi

if [[ "$RUN_BROWSER" -eq 1 ]]; then
  unset WALLABY_SKIP || true
  ensure_chrome
fi

# Full gate without browser flag pair
if [[ "$EXCLUDE_BROWSER" -eq 1 ]]; then
  export WALLABY_SKIP=1
fi

if [[ "$RUN_UNIT" -eq 1 && "$RUN_API" -eq 0 && "$RUN_BROWSER" -eq 0 ]]; then
  export WALLABY_SKIP=1
  mix "${MIX_ARGS[@]}" apps/lakehouse_iam/test apps/lakehouse_matrix/test
  echo "test.sh: OK"
  exit 0
fi

if [[ "$RUN_API" -eq 1 && "$RUN_UNIT" -eq 0 && "$RUN_BROWSER" -eq 0 ]]; then
  export WALLABY_SKIP=1
  mix "${MIX_ARGS[@]}" --only api apps/lakehouse_web/test
  echo "test.sh: OK"
  exit 0
fi

if [[ "$RUN_BROWSER" -eq 1 && "$RUN_UNIT" -eq 0 && "$RUN_API" -eq 0 ]]; then
  mix "${MIX_ARGS[@]}" --only browser apps/lakehouse_web/test
  echo "test.sh: OK"
  exit 0
fi

if [[ "$WATCH" -eq 1 ]]; then
  mix "${MIX_ARGS[@]}" "${EXCLUDE_ARGS[@]:-}" --listen-on-stdin
else
  mix "${MIX_ARGS[@]}" "${EXCLUDE_ARGS[@]:-}"
fi

echo "test.sh: OK"
