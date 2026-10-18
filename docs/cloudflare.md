# Cloudflare deployment and federated login

The production path is a Cloudflare Worker launching **one Cloudflare Container**
containing the existing Phoenix/Elixir app. Postgres remains external. This keeps
login, consent, room actors, LiveView, and WebSockets in their existing runtime.
The Worker always selects `iam-primary`; do not load-balance OTP state between
random container IDs. Pending PKCE logins and single-use codes now live in Postgres
and survive a restart. Active WebSockets reconnect after a container restart.

## Identity and discovery

An identity is `@user:example.com`. `user` is the local username stored in Postgres;
`example.com` is `IAM_DOMAIN`, separate from `IAM_PUBLIC_URL=https://iam.example.com`.
Bare local usernames still work on the IAM server. Email-style input is no longer
accepted by the demo client. Foreign qualified identities cannot log in as local
accounts with the same username. Existing local accounts and principal UUIDs remain.
Keep IAM_DOMAIN stable: changing it changes the namespace of user and Matrix IDs.

The discovery flow is:

1. Parse `@user:example.com` into username `user` and domain `example.com`.
2. GET `https://example.com/.well-known/webfinger?resource=acct%3Auser%40example.com&rel=https%3A%2F%2Fgithub.com%2Fjeethsuresh%2Fiam-server%23issuer`.
3. Follow HTTPS redirects (at most five requests), preserving the query. The
   identity domain can redirect this path to `https://iam.example.com`.
4. Read the WebFinger link with relation
   `https://github.com/jeethsuresh/iam-server#issuer`.
5. GET `<issuer>/.well-known/iam-configuration`, and verify the issuer and identity
   domain match. Use its backend registration, authorization, token and profile URLs.

The WebFinger wire resource is an RFC 7033 `acct:` URI. The user-facing identifier
remains `@user:domain`. **This is the existing Lakehouse PKCE protocol, not OpenID
Connect**: the custom issuer relation and `iam-configuration` document deliberately
do not advertise OIDC compatibility or claim an `openid-configuration` endpoint.
`/.well-known` uses a hyphen. `/.well_known` is not a standard alias.

For Matrix clients, `https://example.com/.well-known/matrix/client` returns
`{"m.homeserver":{"base_url":"https://iam.example.com"}}` through the same delegation.
These discovery endpoints support public CORS. Callback and discovered endpoint
URLs require HTTPS; discovery rejects credentials, private addresses and HTTPS to
HTTP downgrades. HTTP loopback discovery is available only in relaxed development.

## Sign into another app

1. Generate a random PKCE verifier (43–128 unreserved characters), its SHA-256
   base64url challenge, and a random state. Keep the verifier/state in the app's
   own browser session. The demo app implements this flow.
2. Discover IAM, then POST its `backend_registration_endpoint`:
   `username`, `callerURL`, `redirectURL`, `codeChallenge`,
   `codeChallengeMethod: "S256"`, `scope: "profile.name"`, and `state`.
   Caller and callback must share the same HTTPS origin.
3. Navigate to the discovered authorization endpoint with `sessionID` from the
   response. IAM reuses its existing secure browser session, asks for consent
   when required, and redirects to the app with `code` and `state`.
4. Verify state; POST `grant_type=authorization_code`, `code`, `code_verifier`, and
   the exact `redirect_uri` to the discovered token endpoint. Codes are single-use.
5. Call `userinfo_endpoint` with the returned bearer access token. The response
   includes stable `sub`, local `username`, `domain`, and qualified `user_id`.
   Use `(issuer, sub)` as the app's durable account key. Keep tokens in the app's
   own session; IAM cookies stay on the IAM hostname.

Apps need no client secret or advance registration. Grants are scoped to the app
origin and can be revoked in IAM settings. No token or password goes in a callback
URL. The public PKCE/bearer APIs support CORS without cookie credentials.

## Prepare infrastructure

Cloudflare Containers requires a compatible Cloudflare plan and a Docker-compatible
builder. Provide an external Postgres database reachable from the container. Use
verified TLS; its CA must be in the container's CA bundle (or mount a custom bundle
and set DATABASE_CA_FILE when running the image elsewhere).

Copy `cloudflare/wrangler.jsonc` and set `IAM_DOMAIN`, `IAM_PUBLIC_URL`, the Worker
name, and your routes. No example routes are enabled by default. For `example.com`,
add routes for `iam.example.com/*` and **only** these apex paths:

- `example.com/.well-known/webfinger`
- `example.com/.well-known/iam-configuration`
- `example.com/.well-known/matrix/client`

The apex routes delegate discovery with a 307; ordinary apex traffic stays with
its existing application. Alternatively, configure those redirects on the current
apex web server. A DNS record alone cannot delegate a well-known path. IAM itself
returns the discovery JSON on its canonical hostname. Workers.dev and preview URLs
are disabled so there is one canonical login origin.

Install dependencies with `cd cloudflare && npm ci`. Set Worker secrets using
`npx wrangler secret put NAME` for each of:

- `DATABASE_URL`
- `JWT_SECRET` (at least 32 bytes, fresh random material)
- `SECRET_KEY_BASE` (at least 64 bytes, fresh random material)
- `IAM_ADMIN_PASSWORD` (at least 12 bytes)

Secrets are injected into the container at runtime, never as image build arguments.
Before the first launch, run the release tasks against the same database using a
secure env file (`--env-file`, kept outside git) and the built image:

```sh
docker build -f Dockerfile.cloudflare -t iam-server:release .
docker run --rm --env-file /secure/iam.env iam-server:release \
  /app/bin/lakehouse eval 'LakehouseIam.Release.migrate()'
docker run --rm --env-file /secure/iam.env iam-server:release \
  /app/bin/lakehouse eval 'LakehouseIam.Release.bootstrap()'
```

The env file needs IAM_DOMAIN, IAM_PUBLIC_URL and the four secrets listed above.
Migrations and bootstrap are explicit operations, not startup hooks. Back up the
existing database before migration. Import an existing Forge database with standard
Postgres dump/restore if moving to another database. The migration adds a new auth
state table without rewriting users, passwords, grants or room data. Previously
in-memory pending logins must be restarted once during the initial upgrade.

When retaining Matrix room history, set the optional Worker variable `MATRIX_DOMAIN`
to the existing homeserver domain (older installs often used `localhost`). Matrix
events embed that domain; changing it requires a separate namespace migration.
New installations default MATRIX_DOMAIN to IAM_DOMAIN. Moving the database does
not rename existing event IDs or media URIs.

For persistent media, configure a private R2 bucket and set `R2_ENDPOINT`,
`R2_BUCKET`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` as Worker secrets. The app
signs private S3 requests and enforces its existing download authorization. Copy
existing local blobs to that bucket before cutover. Without R2, the Cloudflare
runtime refuses media operations rather than saving uploads on ephemeral disk.
IAM login itself does not require R2.

Run `./scripts/cloudflare-check.sh`, the Elixir test gate, then deploy with
`cd cloudflare && npm run deploy`. Check `/healthz` and `/readyz` through the public
IAM hostname, then complete the demo PKCE flow from another app origin.

## Forge

The existing `web` target stays available. The new `cloudflare` Forgefile target
uses `kind: cloudflare-workers`, `cloudflare/wrangler.jsonc`, and the global
credential profile named `cloudflare-iam` (API token + account ID). Create that
profile in Forge before launching this target; keep application secrets in Worker
secrets. Push the prepared branch to Forge, pin the tested commit as a release,
and deploy that release to the Cloudflare target when infrastructure is configured.
No live DNS changes or deployments are performed by the prep scripts.

References: https://www.rfc-editor.org/rfc/rfc7033.html,
https://developers.cloudflare.com/containers/get-started/,
https://developers.cloudflare.com/containers/api/container-class/.
