# Automatic Gravitas IAM release

Main runs migration-ordering/failure tests, unit/API/browser tests and image publication, then deploys the exact digest with the existing gravitas overlay. Pull requests test and build without publishing or deploying.

An administrator applies ci-access.json once and installs the dedicated IAM-only kubeconfig as the gravitas GitHub environment secret GRAVITAS_KUBECONFIG. Restrict that environment to main and set repository variable GRAVITAS_DEPLOY_ENABLED=true. This credential has no application Secret reads, RBAC administration or cross-namespace access. Signing keys, database credentials and existing PostgreSQL/media PVCs remain separate prerequisites; never reset/bootstrap them during a release.

The small cluster uses IAM_MAINTENANCE_RELEASE=1: scale the single app down, wait for its pod to stop, run the 100m/256Mi migration job, then deploy and verify the app at the same resources. PostgreSQL stays running. A failed migration does not apply the new app image and restores the old replica count. Requests and limits remain equal. Releases are serialized; avoid manual releases during an automatic one. Schema changes must remain compatible with the old app for migration-failure recovery. Downgrades are never automatic.

The job verifies the actual image digest, public health/readiness and IAM discovery with normal TLS verification. A failed check fails the workflow. Pause with GRAVITAS_DEPLOY_ENABLED=false. Rotate the dedicated credential through the same secure provisioning process without printing or committing it.
