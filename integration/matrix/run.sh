#!/usr/bin/env bash
set -Eeuo pipefail
# Run against independent Synapse and Rust-backed clients on a private Docker network.
# Usage: bash integration/matrix/run.sh <image-built-from-Dockerfile.tests>
image=${1:?Pass the image built from Dockerfile.tests}
mode=${2:-modern}
case "$mode" in
  modern) reference_image=ghcr.io/element-hq/synapse@sha256:b497dc97929056f25401ad3f4e8c7e82cb374cfaba07d7348a3c4ea3d1ae950f; serve_only=0; client_script=crypto.mjs ;;
  legacy) reference_image=docker.io/matrixdotorg/synapse@sha256:70fdddfcba9058d2471ae7764f887b6db781d7527debcb75a1b8083217c342f1; serve_only=1; client_script=legacy.mjs ;;
  *) echo 'Expected modern or legacy interoperability mode' >&2; exit 1 ;;
esac
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
fixture_dir=$(mktemp -d)
name="gravitas-matrix-interop-$$"
containers=()
cleanup() {
  status=$?
  if (( status != 0 )); then
    for container in "${containers[@]}"; do docker logs --tail 100 "$container" 2>&1 || true; done
  fi
  for container in "${containers[@]}"; do docker rm -fv "$container" >/dev/null 2>&1 || true; done
  docker network rm "$name" >/dev/null 2>&1 || true
  docker image rm "$name-client" >/dev/null 2>&1 || true
  rm -rf "$fixture_dir"
  exit "$status"
}
trap cleanup EXIT
cp "$root/integration/matrix/homeserver.yaml" "$root/integration/matrix/log.config" "$fixture_dir/"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$fixture_dir/ca.key" -out "$fixture_dir/ca.pem" -days 2 \
  -subj '/CN=Gravitas isolated interoperability test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$fixture_dir/peer.key" -out "$fixture_dir/peer.csr" \
  -subj '/CN=native.test' >/dev/null 2>&1
cat > "$fixture_dir/extensions.cnf" <<'EXT'
subjectAltName=DNS:native.test,DNS:reference.test
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in "$fixture_dir/peer.csr" -CA "$fixture_dir/ca.pem" -CAkey "$fixture_dir/ca.key" \
  -CAcreateserial -out "$fixture_dir/peer.pem" -days 2 -extfile "$fixture_dir/extensions.cnf" >/dev/null 2>&1
chmod 600 "$fixture_dir/ca.key" "$fixture_dir/peer.key"
docker network create --internal "$name" >/dev/null
containers+=("$name-pg")
docker run -d --name "$name-pg" --network "$name" --network-alias postgres \
  -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=matrix_interop_native \
  postgres@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea >/dev/null
for attempt in $(seq 1 60); do
  if docker exec "$name-pg" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
  if (( attempt == 60 )); then exit 1; fi
  sleep 1
done
containers+=("$name-reset")
docker run --name "$name-reset" --network "$name" --init \
  -e POSTGRES_HOST=postgres -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e WALLABY_SKIP=1 --entrypoint mix "$image" run --no-start integration/matrix/reset.exs \
  > "$fixture_dir/reset.log" 2>&1 || { cat "$fixture_dir/reset.log"; exit 1; }
grep 'RESET PASS' "$fixture_dir/reset.log"
synapse_start='exec python -m synapse.app.homeserver --config-path /fixtures/homeserver.yaml'
if [[ "$mode" == legacy ]]; then
  synapse_start="python -m synapse.app.homeserver --config-path /fixtures/homeserver.yaml --generate-keys; $synapse_start"
fi
containers+=("$name-synapse")
docker run -d --name "$name-synapse" --network "$name" --network-alias reference.test \
  --user 0 --security-opt label=disable --read-only --tmpfs /data:rw --tmpfs /tmp:rw \
  -v "$fixture_dir:/fixtures:ro" --entrypoint sh \
  "$reference_image" -ec "$synapse_start" >/dev/null
for attempt in $(seq 1 90); do
  if docker exec "$name-synapse" python -c 'import ssl, urllib.request; urllib.request.urlopen("https://reference.test:8448/_matrix/client/versions", context=ssl.create_default_context(cafile="/fixtures/ca.pem"), timeout=2).close()' >/dev/null 2>&1; then break; fi
  if [[ $(docker inspect -f '{{.State.Running}}' "$name-synapse") != true ]] || (( attempt == 90 )); then exit 1; fi
  sleep 1
done
containers+=("$name-native")
docker run -d --name "$name-native" --network "$name" --network-alias native.test --init \
  --security-opt label=disable -v "$fixture_dir:/fixtures:ro" \
  -e POSTGRES_HOST=postgres -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e WALLABY_SKIP=1 -e INTEROP_HOLD=1 -e INTEROP_SERVE_ONLY="$serve_only" \
  --entrypoint mix "$image" run --no-start integration/matrix/native.exs >/dev/null
for attempt in $(seq 1 90); do
  if docker logs "$name-native" 2>&1 | grep -q 'INTEROP CRYPTO SERVER READY'; then break; fi
  if [[ $(docker inspect -f '{{.State.Running}}' "$name-native") != true ]] || (( attempt == 90 )); then exit 1; fi
  sleep 1
done
docker logs "$name-native" 2>&1 | grep 'INTEROP '
docker build -f "$root/integration/matrix/Dockerfile.client" -t "$name-client" "$root"
containers+=("$name-client")
docker run --name "$name-client" --network "$name" --security-opt label=disable \
  -v "$fixture_dir:/fixtures:ro" "$name-client" node "$client_script" > "$fixture_dir/client.log" 2>&1 || {
    tail -100 "$fixture_dir/client.log"
    exit 1
  }
grep -E 'CRYPTO |LEGACY ' "$fixture_dir/client.log"
