# Federated PKCE + App Resource API

> **Last updated:** 2026-08-13  
> **Status:** Approved for implementation

## Goal

Evolve Lakehouse federated login into **Authorization Code + PKCE** so arbitrary app origins can sign users in without `client_id` / `client_secret` or sysadmin pre-registration. Apps get a dedicated `/app/v1` API (profile, chat list, read/write **events**). A test-only `lakehouse_app_demo` umbrella app exercises the full flow.

## Non-goals

- Enforcing verified-domain DNS/HTTPS signatures (scaffold only)
- Using Matrix Client-Server API as the third-party surface
- Shipping the demo app in production `deploy.sh` / default compose
- Keeping iam-server `tokenURL` + `publicKey` response parity

## Trust model

1. **App identity** = HTTPS **origin** of `callerURL` and `redirectURL` (must be the same origin).
2. That origin is the grant and opaque-token **namespace**.
3. **PKCE S256** binds the code exchange to the party that started login.
4. Grants persist per `(principal, app_origin)` until revoked in Settings.
5. Future: `LakehouseIam.Apps.VerifiedDomain` may require DNS/HTTPS pubkey + signed request (stubbed, not enforced).

## Scopes

| Scope | Meaning |
|-------|---------|
| `profile.name` | Display name / username |
| `chats.list` | List all chats the user is in |
| `chats.read` | Read events (selected rooms or explicit “all”) |
| `chats.write` | Write message events (selected rooms or explicit “all”) |

## Protocol

### `POST /backend/register`

JSON: `username`, `callerURL`, `redirectURL`, `codeChallenge`, `codeChallengeMethod` (`S256`), `scope` (space-delimited), optional `state`.

Validates URLs (existing `CallbackURL` policy), same-origin of caller/redirect, stores in-memory PKCE session.

Response: `{sessionID, username}` (no `publicKey`).

### Authorize / consent

`GET /oauth/authorize?sessionID=…` → login if needed → consent UI showing caller URL, callback URL, scopes, room picker for read/write (or “all”) → on approve, upsert `AppGrant`, mint one-time `code`, redirect `redirectURL?code&state`.

Skip consent when existing grant subsumes requested scopes/rooms.

### `POST /oauth/token`

- `authorization_code`: `code`, `code_verifier`, `redirect_uri` → opaque access + refresh tokens
- `refresh_token`: rotate/issue new access token

### `/app/v1/*`

Bearer opaque token; enforce scopes and room mode.

| Method | Path | Scope |
|--------|------|--------|
| GET | `/app/v1/me` | `profile.name` |
| GET | `/app/v1/chats` | `chats.list` |
| GET | `/app/v1/chats/:id/events` | `chats.read` |
| POST | `/app/v1/chats/:id/events` | `chats.write` |

## Data model

- `app_grants`: principal, app_origin, scopes[], room_mode (`all`\|`selected`), room_ids[]
- `app_tokens`: grant_id, token_hash, kind (`access`\|`refresh`), expires_at, revoked_at
- In-memory: PKCE sessions + auth codes

## Demo app

`apps/lakehouse_app_demo`: separate Phoenix port, PKCE client UI, test/compose profile only.

## Testing

Unit ExUnit + Cucumber `@api` / `@browser`; gate with `./build.sh` and `./test.sh`.
