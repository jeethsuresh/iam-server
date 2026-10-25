#!/usr/bin/env bash
# Exercise release ordering and the migration failure gate without a cluster.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export IAM_TEST_KUBECTL
IAM_TEST_KUBECTL="$(command -v kubectl)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export IAM_TEST_LOG="$work/calls"
cat > "$work/kubectl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == kustomize ]]; then exec "$IAM_TEST_KUBECTL" "$@"; fi
printf '%s\n' "$*" >> "$IAM_TEST_LOG"
if [[ "$*" == *'get deployment iam -o jsonpath='* ]]; then printf '1'; fi
if [[ "$*" == *'config view --minify'* ]]; then printf '%s' "${IAM_TEST_SERVER:-https://02fe9a55-8048-421e-a03f-eae9a4a60472.k8s.ondigitalocean.com}"; fi
if [[ "$*" == *'exec iam-db-0'* && "${IAM_TEST_FAIL_BACKUP:-0}" == 1 ]]; then exit 1; fi
if [[ "$*" == *'create job '* && "$*" == *'--dry-run=client -o json'* ]]; then
  printf '{"spec":{"template":{"spec":{"containers":[{"name":"iam","image":"%s"}]}}}}' "$IAM_TEST_IMAGE"
fi
if [[ "$*" == *'create -f '* && "${IAM_TEST_RESET_JOB:-}" != '' ]]; then
  cp "${@: -1}" "$IAM_TEST_RESET_JOB"
fi
if [[ "$*" == *'wait --for=condition=complete'* && "${IAM_TEST_FAIL_MIGRATION:-0}" == 1 ]]; then exit 1; fi
MOCK
chmod +x "$work/kubectl"
export PATH="$work:$PATH" KUBE_CONTEXT=disposable-mock-context
image=registry.example.com/iam:commit-test
"$root/scripts/kubernetes/deploy.sh" --render "$image" > "$work/rendered"
[[ ! -e "$IAM_TEST_LOG" ]] || { echo 'Render attempted a cluster mutation'; exit 1; }
[[ $(grep -c "image: $image" "$work/rendered") == 2 ]]
"$root/scripts/kubernetes/deploy.sh" "$image"
python3 - "$IAM_TEST_LOG" <<'PY'
from pathlib import Path
import sys
calls=Path(sys.argv[1]).read_text().splitlines()
migrate=next(i for i,x in enumerate(calls) if 'create job ' in x)
wait=next(i for i,x in enumerate(calls) if 'wait --for=condition=complete' in x)
app=next(i for i,x in enumerate(calls) if 'app.kubernetes.io/component=server' in x)
assert migrate < wait < app
assert any('rollout status deployment/iam' in x for x in calls[app+1:])
PY
: > "$IAM_TEST_LOG"
if IAM_TEST_FAIL_MIGRATION=1 "$root/scripts/kubernetes/deploy.sh" "$image" 2> "$work/error"; then echo 'Expected failed migration'; exit 1; fi
if grep -q 'app.kubernetes.io/component=server\|rollout status' "$IAM_TEST_LOG"; then echo 'Failed migration updated app'; exit 1; fi
if "$root/scripts/kubernetes/deploy.sh" --render registry.example.com/iam:latest > /dev/null 2>&1; then echo 'Mutable latest tag accepted'; exit 1; fi
: > "$IAM_TEST_LOG"
IAM_MAINTENANCE_RELEASE=1 "$root/scripts/kubernetes/deploy.sh" "$image"
python3 - "$IAM_TEST_LOG" <<'PY'
from pathlib import Path
import sys
calls=Path(sys.argv[1]).read_text().splitlines()
pause=next(i for i,x in enumerate(calls) if 'scale deployment/iam --replicas=0' in x)
deleted=next(i for i,x in enumerate(calls) if 'wait --for=delete pod' in x)
migrate=next(i for i,x in enumerate(calls) if 'create job ' in x)
app=next(i for i,x in enumerate(calls) if 'app.kubernetes.io/component=server' in x and 'apply ' in x)
assert pause < deleted < migrate < app
PY
: > "$IAM_TEST_LOG"
if IAM_MAINTENANCE_RELEASE=1 IAM_TEST_FAIL_MIGRATION=1 "$root/scripts/kubernetes/deploy.sh" "$image" 2> "$work/error"; then echo 'Expected failed maintenance migration'; exit 1; fi
grep -q 'scale deployment/iam --replicas=1' "$IAM_TEST_LOG" || { echo 'Failed maintenance release did not restore old pod'; exit 1; }
if grep -q 'apply .*app.kubernetes.io/component=server' "$IAM_TEST_LOG"; then echo 'Failed maintenance migration updated app'; exit 1; fi
echo 'kubernetes/deploy_test.sh: OK (render, migration ordering, failure gate)'

: > "$IAM_TEST_LOG"
if IAM_KUSTOMIZE_OVERLAY=gravitas IAM_TEST_SERVER=https://wrong.example "$root/scripts/kubernetes/deploy.sh" "$image" 2> "$work/error"; then echo 'Unexpected cluster accepted'; exit 1; fi
if grep -q 'apply \|scale \|create job' "$IAM_TEST_LOG"; then echo 'Unexpected cluster was mutated'; exit 1; fi
IAM_KUSTOMIZE_OVERLAY=gravitas IAM_MAINTENANCE_RELEASE=1 "$root/scripts/kubernetes/deploy.sh" "$image"
if grep -q 'get secret' "$IAM_TEST_LOG"; then echo 'Release tried to read application Secrets'; exit 1; fi
echo 'Gravitas cluster guard and Secret isolation: OK'
IAM_KUSTOMIZE_OVERLAY=gravitas "$root/scripts/kubernetes/deploy.sh" --render "$image" > "$work/gravitas-rendered"
python3 - "$work/gravitas-rendered" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
assert text.count('name: iam-matrix-signing') == 2
assert text.count('name: MATRIX_NATIVE_EVENT_GRAPH') == 2
assert text.count('name: MATRIX_FEDERATION_ENABLED') == 2
# The shared ConfigMap is applied before backup/reset. Native activation belongs
# to the new pod templates so a failed release can still restart the old writer.
assert 'MATRIX_NATIVE_EVENT_GRAPH: "false"' in text
assert 'MATRIX_FEDERATION_ENABLED: "false"' in text
assert 'kind: Secret' not in text
PY
python3 "$root/scripts/kubernetes/test_matrix_signing_key.py"

# Destructive room resets require a fresh validated archive and a one-use job.
export IAM_TEST_IMAGE="registry.example.com/iam@sha256:$(printf 'a%.0s' {1..64})"
export IAM_TEST_RESET_JOB="$work/reset-job.json"
: > "$IAM_TEST_LOG"
IAM_KUSTOMIZE_OVERLAY=gravitas IAM_MAINTENANCE_RELEASE=1 IAM_ROOM_RESET_SERVER=gravitas.cool "$root/scripts/kubernetes/deploy.sh" "$IAM_TEST_IMAGE"
python3 - "$IAM_TEST_LOG" "$IAM_TEST_RESET_JOB" <<'PYTEST'
import json,sys
from pathlib import Path
calls=Path(sys.argv[1]).read_text().splitlines()
pause=next(i for i,x in enumerate(calls) if 'scale deployment/iam --replicas=0' in x)
backup=next(i for i,x in enumerate(calls) if 'exec iam-db-0' in x)
dry=next(i for i,x in enumerate(calls) if 'create job ' in x)
create=next(i for i,x in enumerate(calls) if 'create -f ' in x)
wait=next(i for i,x in enumerate(calls) if 'wait --for=condition=complete' in x)
app=next(i for i,x in enumerate(calls) if 'apply ' in x and 'component=server' in x)
assert pause < backup < dry < create < wait < app
text=Path(sys.argv[1]).read_text()
assert 'pg_restore --list' in text and 'pg_restore --file=/dev/null' in text and 'sha256sum' in text
job=json.loads(Path(sys.argv[2]).read_text())
container=job['spec']['template']['spec']['containers'][0]
assert 'Release.reset_rooms' in container['command'][-1]
assert job['spec']['backoffLimit'] == 0
assert container['env'][-1] == {'name': 'MATRIX_ROOM_RESET_SERVER', 'value': 'gravitas.cool'}
PYTEST
: > "$IAM_TEST_LOG"
if IAM_KUSTOMIZE_OVERLAY=gravitas IAM_MAINTENANCE_RELEASE=1 IAM_ROOM_RESET_SERVER=gravitas.cool IAM_TEST_FAIL_BACKUP=1 "$root/scripts/kubernetes/deploy.sh" "$IAM_TEST_IMAGE" 2> "$work/error"; then echo 'Expected backup failure'; exit 1; fi
if grep -q 'create job\|create -f' "$IAM_TEST_LOG"; then echo 'Backup failure submitted a reset'; exit 1; fi
grep -q 'scale deployment/iam --replicas=1' "$IAM_TEST_LOG" || { echo 'Backup failure did not restore old writers'; exit 1; }
: > "$IAM_TEST_LOG"
if IAM_KUSTOMIZE_OVERLAY=gravitas IAM_MAINTENANCE_RELEASE=1 IAM_ROOM_RESET_SERVER=gravitas.cool IAM_TEST_FAIL_MIGRATION=1 "$root/scripts/kubernetes/deploy.sh" "$IAM_TEST_IMAGE" 2> "$work/error"; then echo 'Expected uncertain reset failure'; exit 1; fi
if grep -q 'scale deployment/iam --replicas=1\|apply .*component=server' "$IAM_TEST_LOG"; then echo 'Uncertain reset restarted writers'; exit 1; fi
grep -q 'Writers remain stopped' "$work/error"
if IAM_ROOM_RESET_SERVER=gravitas.cool "$root/scripts/kubernetes/deploy.sh" "$IAM_TEST_IMAGE" 2>/dev/null; then echo 'Non-maintenance reset accepted'; exit 1; fi
echo 'Matrix reset backup, one-use job and stopped-writer failure gate: OK'
