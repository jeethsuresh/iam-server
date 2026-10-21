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
