#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
overlay="${IAM_KUSTOMIZE_OVERLAY:-digitalocean}"
case "$overlay" in
  digitalocean|gravitas) ;;
  *) echo 'IAM_KUSTOMIZE_OVERLAY must be digitalocean or gravitas' >&2; exit 1 ;;
esac
render_only=0
if [[ "${1:-}" == --render ]]; then render_only=1; shift; fi
image="${1:?Usage: KUBE_CONTEXT=... deploy.sh [--render] registry/iam:commit-tag}"
if [[ ! "$image" =~ ^[a-zA-Z0-9./:_@-]+$ || "$image" == *:latest || ( "$image" != *:* && "$image" != *@* ) ]]; then
  echo 'Use a registry image with an immutable commit tag or sha256 digest.' >&2
  exit 1
fi
work="$(mktemp -d)"
maintenance="${IAM_MAINTENANCE_RELEASE:-0}"
[[ "$maintenance" == 0 || "$maintenance" == 1 ]] || { echo 'IAM_MAINTENANCE_RELEASE must be 0 or 1' >&2; exit 1; }
reset_server="${IAM_ROOM_RESET_SERVER:-}"
if [[ -n "$reset_server" ]]; then
  [[ "$overlay" == gravitas && "$maintenance" == 1 && "$reset_server" == gravitas.cool && "$image" =~ ^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$ ]] || {
    echo 'Room reset requires the Gravitas maintenance release, gravitas.cool and an image digest.' >&2; exit 1;
  }
fi
reset_started=0
paused=0
previous_replicas=1
maintenance_ready=0
cleanup() {
  result=$?
  if [[ "$paused" == 1 ]]; then
    if [[ "$reset_started" == 1 ]]; then
      "${kube[@]}" scale deployment/iam --replicas=0 >&2 || true
      echo 'Room reset may have run. Writers remain stopped; inspect the reset job and verified backup before recovery.' >&2
    else
      "${kube[@]}" scale deployment/iam --replicas="$previous_replicas" >&2 || true
    fi
  fi
  rm -rf "$work"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cp -R "$root/deploy/kubernetes/base" "$root/deploy/kubernetes/$overlay" "$work/"
if [[ "$image" == *@sha256:* ]]; then
  printf '\nimages:\n  - name: iam\n    newName: %s\n    digest: %s\n' "${image%@*}" "${image#*@}" >> "$work/$overlay/kustomization.yaml"
else
  printf '\nimages:\n  - name: iam\n    newName: %s\n    newTag: %s\n' "${image%:*}" "${image##*:}" >> "$work/$overlay/kustomization.yaml"
fi
kubectl kustomize "$work/$overlay" > "$work/release.yaml"
if [[ "$render_only" == 1 ]]; then cat "$work/release.yaml"; exit 0; fi
: "${KUBE_CONTEXT:?Set KUBE_CONTEXT explicitly to your DOKS kubectl context}"
kube=(kubectl --context "$KUBE_CONTEXT" --namespace iam)
# Prerequisites are managed separately; release credentials cannot read Secrets.
if [[ "$overlay" == gravitas ]]; then
  server="$("${kube[@]}" config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
  [[ "$server" == 'https://02fe9a55-8048-421e-a03f-eae9a4a60472.k8s.ondigitalocean.com' ]] || { echo 'Refusing an unexpected Gravitas cluster' >&2; exit 1; }
fi
"${kube[@]}" apply -f "$work/release.yaml" --selector 'app.kubernetes.io/component!=server'
if [[ "$overlay" == gravitas ]]; then
  "${kube[@]}" rollout status statefulset/iam-db --timeout=180s
fi
if [[ "$maintenance" == 1 ]] && previous_replicas=$("${kube[@]}" get deployment iam -o 'jsonpath={.spec.replicas}' 2>/dev/null); then
  [[ "$previous_replicas" =~ ^[0-9]+$ ]] || { echo 'Could not read existing IAM replica count' >&2; exit 1; }
  maintenance_ready=1
  if [[ "$previous_replicas" != 0 ]]; then
    "${kube[@]}" scale deployment/iam --replicas=0
    paused=1
  fi
  if [[ "$previous_replicas" != 0 || -n "$reset_server" ]]; then
    "${kube[@]}" wait --for=delete pod --selector 'app.kubernetes.io/component=server' --timeout=90s
  fi
fi
if [[ -n "$reset_server" ]]; then
  [[ "$maintenance_ready" == 1 ]] || { echo 'Room reset could not establish maintenance state' >&2; exit 1; }
  paused=1
  # Keep the dump on the retained database volume. The local socket uses the
  # existing database identity; no credentials or database contents are printed.
  "${kube[@]}" exec iam-db-0 -- sh -c '
    set -eu
    umask 077
    backup=$(mktemp /var/lib/postgresql/data/iam-pre-matrix-reset-XXXXXXXX.dump)
    pg_dump --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --format=custom --file "$backup"
    test -s "$backup"
    pg_restore --list "$backup" >/dev/null
    pg_restore --file=/dev/null "$backup"
    sha256sum "$backup"
  '
fi
job="iam-migrate-$(date +%s)-$RANDOM"
if [[ -n "$reset_server" ]]; then
  "${kube[@]}" create job "$job" --from=cronjob/iam-migrate --dry-run=client -o json > "$work/reset-job.json"
  python3 "$root/scripts/kubernetes/matrix_reset_job.py" "$work/reset-job.json" "$reset_server" "$image"
  # The reset command exists only in this job, never in the persistent CronJob.
  reset_started=1
  "${kube[@]}" create -f "$work/reset-job.json"
else
  "${kube[@]}" create job "$job" --from=cronjob/iam-migrate
fi
if ! "${kube[@]}" wait --for=condition=complete "job/$job" --timeout=330s; then
  "${kube[@]}" logs "job/$job" --all-containers >&2 || true
  echo "Migration failed; application image has not been updated." >&2
  exit 1
fi
"${kube[@]}" apply -f "$work/release.yaml" --selector 'app.kubernetes.io/component=server'
"${kube[@]}" rollout status deployment/iam --timeout=240s
paused=0
