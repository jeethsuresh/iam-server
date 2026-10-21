# Live Gravitas deployment

The deployed overlay is `deploy/kubernetes/gravitas`: the existing shared Traefik ingress, an IAM-only Postgres StatefulSet, verified database TLS, retained database storage and a separate retained media volume. It does not install a cluster-wide database operator or another load balancer. The optional CloudNativePG/Cilium templates below are alternatives and are not used by this installation.

IAM is at **https://gravitas.cool**. Traefik owns the shared apex/wildcard certificate in its own namespace; the IAM Ingress references the apex host without a certificate secret. Keep Namecheap credentials out of IAM and Kubernetes. Shared certificate and DNS management is maintained with the RSS/Office infrastructure.

The first installation starts fresh; Forge's accounts, groups and media are left untouched. Runtime credentials, the database CA and the first-install administrator login are kept locally under `.local/gravitas/` with owner-only permissions, excluded from Git and Docker contexts. `admin-login.env` contains the administrator login. Runtime secrets also exist in namespace `iam`; the app uses a non-superuser Postgres role. Database connections require TLS and verify a private CA; plaintext database connections are rejected.

All application, database and migration-job CPU/memory requests equal their limits: **100m CPU / 256Mi memory**. The database uses a retained 10Gi volume, and private media uses a retained 1Gi volume. A replacement pod can reattach these volumes; there is a recovery interruption. Back up and test restoring these volumes and a logical database export; automated off-cluster backups are not yet configured. The database leaf certificate needs renewal before its one-year expiry using the retained CA; replace `iam-db-server-tls` and restart Postgres after renewal.

GitHub Actions publishes an AMD64 image from `Dockerfile.release` on the deployment branch and main, with immutable commit tags and an image digest. Deploy the selected digest explicitly:

The release also copies Phoenix and LiveView browser assets from the locked dependencies, keeping the browser and server protocols at the same version.

```sh
IAM_KUSTOMIZE_OVERLAY=gravitas KUBE_CONTEXT=do-tor1-gravitas-k8s-services ./scripts/kubernetes/deploy.sh ghcr.io/jeethsuresh/iam-server@sha256:YOUR_DIGEST
```

The first-install bootstrap uses `scripts/kubernetes/bootstrap.sh`; do not repeat it during upgrades because it can reset the administrator password. Registration requires the configured invitation key and administrator approval. Service catalog entries should be added only after their app supports the Gravitas PKCE sign-in entry point.

# Gravitas on DigitalOcean Kubernetes

This keeps Phoenix, Postgres, Matrix groups and the existing PKCE protocol. The signed-in home is `/dashboard`; public identity and discovery live at `https://gravitas.cool`. There is no Worker or Cloudflare Container in this deployment.

## Release image

Build `Dockerfile.release` for the architecture of your DOKS nodes, push to a registry that the cluster can pull from, and use a unique commit tag (or image digest). For example:

```sh
docker buildx build --platform linux/amd64 -f Dockerfile.release -t registry.digitalocean.com/YOUR_REGISTRY/iam:YOUR_COMMIT --push .
```

Connect DigitalOcean Container Registry to DOKS, or configure an image pull secret. Do not deploy a local Mac ARM image to AMD64 nodes. The release runs as UID 1000 with a read-only root filesystem and writable `/tmp`. IAM sessions, service catalog, grants and PKCE state are persisted in Postgres. No credentials are baked into the image.

## Platform setup (once per cluster)

Use VPC-native networking, Kubernetes 1.33 or later, and an accepted `cilium` GatewayClass. Install a supported CloudNativePG operator with support for `postgresql.synchronous` before applying `platform/postgres.yaml`. Pin and maintain the operator version in your cluster infrastructure repository. See [DOKS Gateway API](https://docs.digitalocean.com/products/kubernetes/how-to/use-gateway-api/) and [CNPG replication](https://cloudnative-pg.io/docs/current/replication/).

```sh
kubectl --context YOUR_DOKS_CONTEXT apply -f deploy/kubernetes/platform/namespaces.yaml
kubectl --context YOUR_DOKS_CONTEXT apply -f deploy/kubernetes/platform/postgres.yaml
kubectl --context YOUR_DOKS_CONTEXT -n iam wait --for=condition=Ready cluster/iam-db --timeout=600s
```

The default database template creates **one Postgres pod with one persistent DigitalOcean block volume**. This is sufficient to run the application. Kubernetes can restart it or reschedule it after worker failure, but the database is unavailable during recovery and disk reattachment. This is not automatic database failover.

For automatic database failover later, use at least three workers and apply `platform/postgres-ha.patch.yaml` as a merge patch to `cluster/iam-db`. It raises the database to three instances on separate workers and disks, with commits waiting for one synchronous standby. Losing two database instances stops writes until a standby returns. The operator generates `iam-db-app` (including the connection URI) and `iam-db-ca`; the release verifies the database certificate with that CA. These are private cluster services, with no public database load balancer.

Before importing real accounts, configure off-cluster WAL archiving and scheduled base backups using the current [CNPG Barman Cloud plugin](https://cloudnative-pg.io/plugin-barman-cloud/docs/). Use a separate private Spaces backup bucket and credentials, set retention, and prove restoration into a separate cluster. Backup configuration is site-specific and is **not enabled by the supplied template**. Replica failover is not a backup. Keep database volumes when replacing app releases.

## Low-use resource defaults

Phoenix and Postgres each request and limit **100m CPU and 256Mi memory**. Requests and limits are always identical for both resources. The migration job uses the same budget and runs only during releases. Combined steady-state application allocations are 200m CPU and 512Mi memory, excluding the database operator, gateway, Kubernetes system workloads, and other apps. These reservations do not reduce the fixed price of an already provisioned DOKS node.

The release uses one BEAM scheduler, one dirty CPU/IO scheduler each, two async threads and a three-connection Ecto pool. Its container entrypoint caps the inherited open-file limit at 65,536: the DOKS runtime supplied a limit above one billion, which exhausted memory before BEAM could start. With the cap, the native AMD64 release's minimal startup peaked at about 50Mi. Migration and bootstrap commands also use this entrypoint. Postgres uses 32MB shared buffers, 2MB work memory, 16MB maintenance memory and at most 30 connections. These are starting values for low traffic. Monitor actual working sets, OOM restarts, query latency and pool waits; increase memory for large media transformations or heavier traffic. Do not lower the limits further without measurements. Each database replica in the optional HA setup receives its own resource allocation.

## Secrets and media

Copy `deploy/kubernetes/iam-secrets.env.example` to a private file outside Git and fill it in. Generate strong signing secrets and the administrator password; set `IAM_REGISTRATION_KEY` to the registration key agreed for this installation. The key is required by browser and API registration; accounts still require administrator approval. Existing accounts are unaffected. Import without putting values on command lines:

```sh
kubectl --context YOUR_DOKS_CONTEXT -n iam create secret generic iam-secrets --from-env-file=/PRIVATE/PATH/iam-secrets.env
```

For durable uploads, add `S3_ENDPOINT=https://nyc3.digitaloceanspaces.com`, `S3_REGION=nyc3`, and `S3_BUCKET=YOUR_PRIVATE_MEDIA_BUCKET` to `base/config.yaml`, plus `S3_ACCESS_KEY_ID` and `S3_SECRET_ACCESS_KEY` in the secret. Change the region to match your Space. The bucket must be private; files are served through authenticated IAM media routes. Without these values uploads return storage unavailable rather than writing to disposable pod disk. Existing R2 variables remain compatible.

## DNS and certificate through Namecheap

At the authoritative DNS provider, point the apex `gravitas.cool` and wildcard `*.gravitas.cool` A records to the shared Gateway address. Avoid stale AAAA records if IPv6 is not configured. The registrar may remain Namecheap. Obtain a certificate whose SANs include **both** `gravitas.cool` and `*.gravitas.cool`; a wildcard alone does not cover the apex. Import the full chain and key as a Kubernetes TLS secret:

```sh
kubectl --context YOUR_DOKS_CONTEXT -n gravitas-system create secret tls gravitas-tls --cert=/PRIVATE/PATH/fullchain.pem --key=/PRIVATE/PATH/privkey.pem
kubectl --context YOUR_DOKS_CONTEXT apply -f deploy/kubernetes/platform/gateway.yaml
kubectl --context YOUR_DOKS_CONTEXT -n gravitas-system get gateway gravitas
```

Applying the Gateway provisions a **billable shared load balancer**. Renew and replace the TLS secret before expiry (or configure a maintained DNS-01 issuer for your authoritative DNS provider). DNS-01 is required for ACME wildcard certificates; a Namecheap registrar account alone does not configure automatic renewal. The manifest terminates TLS at Cilium and redirects HTTP to HTTPS. Future apps attach HTTPRoutes to the `apps-https` listener; allow their namespaces with the `gravitas.cool/gateway-access: "true"` label. IAM attaches to `apex-https` and receives `X-Forwarded-Proto: https`, including for discovery and LiveView WebSockets.

## Migrate, bootstrap and deploy

First render and inspect the deployment; rendering has no cluster side effects:

```sh
./scripts/kubernetes/deploy.sh --render registry.digitalocean.com/YOUR_REGISTRY/iam:YOUR_COMMIT > /tmp/iam-release.yaml
KUBE_CONTEXT=YOUR_DOKS_CONTEXT ./scripts/kubernetes/deploy.sh registry.digitalocean.com/YOUR_REGISTRY/iam:YOUR_COMMIT
```

The deploy script checks required secrets, updates the suspended migration job template and configuration, runs a one-off migration job, and waits for success before updating the app image. Serialize deployments in CI/Forge; do not deploy concurrently. Only backward-compatible migrations may be deployed this way because the previous app continues running during migration. On a migration failure the app image stays unchanged, but shared configuration may already have updated. Use reviewed config changes and restore the previous ConfigMap if needed.

On the **first installation only**, bootstrap roles and the administrator after migrations:

```sh
KUBE_CONTEXT=YOUR_DOKS_CONTEXT ./scripts/kubernetes/bootstrap.sh
```

Bootstrap uses a separate one-off job with the same resource budget, avoiding a second BEAM process inside the running web pod. It is explicit because it can update administrator credentials. Do not run it on every restart or release. When moving Forge's database, take a backup, restore to the new Postgres cluster, preserve `MATRIX_DOMAIN` if existing IDs embed a different domain, and run migrations. Changing IAM_DOMAIN changes the visible identifier domain; coordinate client discovery and app configuration.

`/healthz` checks the process and `/readyz` also checks Postgres. Probes use `Host: localhost` to bypass HTTPS redirection over the private pod network. A readiness failure removes the pod from routing without restarting it for a transient database outage. Verify the public HTTPS discovery endpoints, registration protection, dashboard, app consent/relaunch, groups and uploads after deployment. Exercise worker loss and restore drills to measure recovery time; test promotion separately if you enable the optional HA configuration.

The application currently runs **one active pod**, with `Recreate` deployments. Kubernetes reschedules it after node loss, using the shared database and media store. This produces a brief interruption; in-flight WebSockets reconnect. It is not uninterrupted active-active Phoenix: room actors and local PubSub need distributed ownership before raising replicas. Do not add an HPA yet. The default single Postgres instance also recovers by restart/rescheduling, with downtime. The optional three-instance database configuration provides database failover independently of app replica count. Node loss detection, scheduling and volume reattachment can take minutes; measure this on your cluster.

For rollback, redeploy a previous immutable image only if it is compatible with the current schema; do not automatically reverse migrations or delete volumes. Delete failed migration jobs only after saving diagnostics.

## Dashboard and service integration

Administrators add services at `/services/manage` or via authenticated `POST /api/v1/services` with a `service` object (`name`, optional `description`, `home_url`, `login_url`). `GET /api/v1/services` lists the shared directory; DELETE removes an entry. Removal does not revoke existing user consent; each user can revoke connections in Settings.

A service's `login_url` is its **app-side** sign-in initiation endpoint, for example `https://notes.gravitas.cool/auth/gravitas/start`. Home and login URLs must be HTTPS on the same origin. Loopback HTTP is allowed only with the development callback flag. Only one entry per origin is supported, matching the current origin-based consent model. To change an entry, remove it and add the replacement; grants remain associated with its origin.

Launch appends the public `login_hint=@user:gravitas.cool`, preserving the app's existing query parameters. It never sends an IAM cookie, password, JWT or app access token in a link. The app resolves the hint's domain via WebFinger and IAM discovery, creates PKCE verifier/state in its own session, registers the request at `/backend/register`, and redirects to `/oauth/authorize`. After consent the app verifies state and exchanges the one-use code at `/oauth/token`, then creates its own session. The demo app implements `/auth/gravitas/start` as a reference.

The first connection asks permission. Subsequent launches skip password and consent while the Gravitas session and existing grant cover the requested access. A new scope or expired session can legitimately prompt again. Arbitrary third-party sites must implement this protocol; a dashboard link cannot sign into an unintegrated site. This is the existing custom PKCE protocol, not OIDC. Older connected origins outside the catalog are shown with ordinary Visit links; an administrator must add their actual login entry points for session reuse from the dashboard.

Identity discovery uses the standard hyphenated `/.well-known/` prefix. If identities later use another domain from the IAM hostname, serve that domain's WebFinger/metadata with the existing validated HTTPS delegation; discovery continues to support `@user:domain`.
