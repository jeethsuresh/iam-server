#!/usr/bin/env bash
# Explicit first-install task; re-running may reset the administrator password.
set -euo pipefail
: "${KUBE_CONTEXT:?Set KUBE_CONTEXT explicitly to your DOKS kubectl context}"
kube=(kubectl --context "$KUBE_CONTEXT" --namespace iam)
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
job="iam-bootstrap-$(date +%s)-$RANDOM"
"${kube[@]}" create job "$job" --from=cronjob/iam-migrate --dry-run=client -o json > "$work/job.json"
python3 - "$work/job.json" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
job = json.loads(path.read_text())
job['spec']['template']['spec']['containers'][0]['command'] = ['/app/bin/lakehouse', 'eval', 'LakehouseIam.Release.bootstrap()']
path.write_text(json.dumps(job))
PY
"${kube[@]}" create -f "$work/job.json"
if ! "${kube[@]}" wait --for=condition=complete "job/$job" --timeout=330s; then
  "${kube[@]}" logs "job/$job" --all-containers >&2 || true
  exit 1
fi
