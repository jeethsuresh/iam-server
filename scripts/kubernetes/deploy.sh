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
trap 'rm -rf "$work"' EXIT
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
# Prerequisites are intentionally managed separately from application releases.
"${kube[@]}" get secret iam-secrets iam-db-app iam-db-ca >/dev/null
"${kube[@]}" apply -f "$work/release.yaml" --selector 'app.kubernetes.io/component!=server'
job="iam-migrate-$(date +%s)-$RANDOM"
"${kube[@]}" create job "$job" --from=cronjob/iam-migrate
if ! "${kube[@]}" wait --for=condition=complete "job/$job" --timeout=330s; then
  "${kube[@]}" logs "job/$job" --all-containers >&2 || true
  echo "Migration failed; application image has not been updated." >&2
  exit 1
fi
"${kube[@]}" apply -f "$work/release.yaml" --selector 'app.kubernetes.io/component=server'
"${kube[@]}" rollout status deployment/iam --timeout=240s
