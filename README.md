## Gravitas dashboard and Kubernetes

The signed-in home now lists connected and available services. Administrators maintain the shared service catalog; Groups keeps the existing room experience. See [DigitalOcean Kubernetes deployment and service integration](docs/kubernetes.md) for release images, database storage, optional failover, wildcard TLS, secret configuration and the app-side PKCE login contract.

# Lakehouse — IAM + Matrix-style rooms + WebRTC orchestration (Elixir umbrella)

This repository implements the architecture described in `original-plan.md`:

Cloudflare launch preparation is documented in [docs/cloudflare.md](docs/cloudflare.md):
Workers launch the production Phoenix release in a Container, and `@user:domain`
identities discover their IAM host through `/.well-known/webfinger`. The demo app
uses discovery before starting the existing PKCE login flow. The Forgefile includes
a separate `cloudflare` deployment target; the local `web` target stays available.

- **OTP-first**: federated IAM sessions, supervised room actors, Registry-backed routing.
- **iam-server compatible HTTP surface** for integrations that already speak that protocol.
- **Bounded contexts**: `lakehouse_iam` (identity + RBAC), `lakehouse_matrix` (rooms + `RoomServer`), `lakehouse_web` (HTTP + Channels + Presence).

## Umbrella applications

| App | Responsibility |
|-----|----------------|
| `lakehouse_iam` | `LakehouseIam.Repo`, principals/credentials/RBAC, HS256 JWT, persistent PKCE sessions and single-use codes |
| `lakehouse_matrix` | Room persistence (shared Postgres schema), `LakehouseMatrix.RoomServer`, `DynamicSupervisor` |
| `lakehouse_web` | Phoenix endpoint, iam-server routes, `/api/v1` REST, sockets |

## Prerequisites

- Elixir ~> 1.14 and Erlang/OTP compatible with Phoenix 1.7
- PostgreSQL 14+ (or Docker — see below)

## Local setup (without Docker)

```bash
cd /home/jeeth/elixir/iam-matrix
mix deps.get
mix ecto.create -r LakehouseIam.Repo
mix ecto.migrate -r LakehouseIam.Repo
mix run apps/lakehouse_iam/priv/repo/seeds.exs
mix phx.server
```

Configure Postgres in `config/dev.exs` via environment variables:

| Variable | Default |
|----------|---------|
| `POSTGRES_HOST` | `localhost` |
| `POSTGRES_USER` | `postgres` |
| `POSTGRES_PASSWORD` | `postgres` |
| `POSTGRES_DB` | `lakehouse_dev` |

Listen address / port:

| Variable | Default |
|----------|---------|
| `PHX_LISTEN_ADDRESS` | `127.0.0.1` — use `0.0.0.0` to bind all interfaces (e.g. containers) |
| `PORT` | `4000` |

### Environment (iam-server parity)

| Variable | Purpose |
|----------|---------|
| `JWT_SECRET` | HS256 signing material (hashed to a 256-bit oct key internally) |
| `IAM_ADMIN_USERNAME` | Bootstrap admin username (default `admin`) |
| `IAM_ADMIN_PASSWORD` | When set, bootstrap creates/resets that admin and accepts this password at login |
| `IAM_RELAXED_CALLBACK_URLS` | Non-empty allows loopback/private callback URLs for federated login (still blocks `169.254.0.0/16`) |
| `SECRET_KEY_BASE` | Phoenix endpoint (optional in dev; required in prod via `config/runtime.exs`) |
| `DATABASE_URL` | Production database |

## Docker Compose (PostgreSQL + app)

From the repo root:

```bash
docker compose build
docker compose up
```

This starts:

- **postgres** — `postgres:16-alpine`, database `lakehouse_dev`, port **5432** on the host.
- **lakehouse** — umbrella app on port **4000**, waits for Postgres with `pg_isready`, runs `ecto.create`, `ecto.migrate`, seeds, then `mix phx.server`.

Environment overrides (optional): `JWT_SECRET`, `SECRET_KEY_BASE`, `IAM_ADMIN_USERNAME`, `IAM_ADMIN_PASSWORD`, `IAM_RELAXED_CALLBACK_URLS`.

To rebuild after code changes:

```bash
docker compose build --no-cache lakehouse && docker compose up
```

## Web UI (HTML)

- `GET /` — sign-in form (supports federated return query params `username`, `sessionID`, same idea as iam-server `GET /?username&sessionID`)
- `GET /register` — registration form
- `POST /web/login` — browser login (CSRF-protected); sets host-only session/refresh cookies and redirects to `/dashboard`
- `POST /web/register` — browser registration (CSRF-protected)
- `GET /profile` — HTML when opened in a browser if you are logged in via session, or JSON with `Accept: application/json` / API clients using Bearer token
- `GET /profile/password` — change password form (session or Bearer)
- `POST /web/profile/password` — submit password change (`current_password`, `new_password`, `new_password_confirm`). Bootstrap admin cannot use this when `IAM_ADMIN_PASSWORD` is set (same as iam-server); change the env and restart instead.
- `GET /admin` — **admin only** (bootstrap account or an active user with a global `admin` role): redirects to settings with pending users and approve buttons
- `POST /web/admin/approve` — **admin only**, form field `username` to activate an account
- `POST /web/logout` — CSRF-protected browser logout; revokes this Gravitas login and connected service sessions, keeping saved consent. `GET /logout` shows a confirmation form.

JSON **iam-server**-compatible endpoints retain their existing fields (no CSRF). `POST /login` also returns a rotating refresh token; use body-only `POST /refresh` and `POST /revoke`. Browser refresh sessions last at most 30 days. Integrated subdomains use the shared non-credential sign-in cookie to start silent PKCE login; see [session and service integration](docs/kubernetes.md#dashboard-and-service-integration).

Additional JSON (Bearer required):

- `POST /profile/password` — body/urlencoded `current_password`, `new_password`, `new_password_confirm` → `{"message":"Password updated."}` or error JSON with `message` (403 for env-backed admin password)
- `POST /admin/approve` — **admin** Bearer only; JSON body `{"username":"..."}` to approve a pending user

Additional administrators keep their existing passwords and may change them normally. A trusted database operator can grant an existing active account the global `admin` role with `scripts/kubernetes/grant-admin.sql`; see [the Kubernetes operator procedure](docs/kubernetes.md#additional-administrators). Resource-scoped `admin` grants do not grant IAM administration, and revoking the global grant takes effect on the next request.

## IAM routes (compatible with `iam-server`)

- `POST /backend/register` JSON `{username, callerURL, redirectURL, codeChallenge, codeChallengeMethod, scope}` → `{sessionID, username}` (PKCE; no client secret / publicKey)
- `GET /oauth/authorize?sessionID=` → login + consent → redirect with `code`
- `POST /oauth/token` → opaque access/refresh tokens
- `GET/POST /app/v1/*` → third-party profile, chats, events
- `POST /login` JSON or urlencoded `username`, `password`, optional `sessionID` for federated completion
- `POST /register` signup (pending activation unless registering as configured admin username)
- `GET /logout` (with session + `Accept: application/json` for API-style response, or use browser for redirect)
- `GET /profile` with `Authorization: Bearer <HS256 JWT>` or browser session after `/web/login`

## API + realtime

- `GET|POST /api/v1/rooms` … — bearer JWT required (`LakehouseWeb.Plugs.BearerAuth`).
- Phoenix Channel `room:<uuid>` on `/socket` — pass `token` (HS256) in socket params.

## Tests

Callback URL policy tests are DB-free:

```bash
mix test apps/lakehouse_iam/test/lakehouse_iam/auth/callback_url_test.exs --no-start
```

Full `mix test` (and any tests that hit `LakehouseIam.Repo`) require PostgreSQL matching `config/test.exs`, then start apps as usual (omit `--no-start`).
