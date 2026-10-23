# Native Gravitas login through Private Store

The Android Private Store is an optional account broker. Spacetime is the first
client. Apps retain system-browser PKCE login when the store is absent, has no
eligible account, needs reauthentication, or the requested service needs consent.
Local/offline content remains available under the app's existing rules.

## IAM contract, version 1

The deployment explicitly configures `IAM_NATIVE_BROKER_ORIGIN` as
`https://apps.gravitas.cool`. Delegation is disabled without this configuration.
Only that origin with **exact** redirect
`https://apps.gravitas.cool/auth/android/callback` may request `native.broker`.
Native store login requests `profile.name native.broker`; browser-only store login
continues to request `profile.name`. The consent screen explains the additional
permission. Old store tokens/refreshes/pending requests cannot gain this capability
because access/refresh tokens snapshot the authorized request's scopes.

The store's existing native backend PKCE exchange may return its own origin-scoped
IAM bundle to the Android store's encrypted vault. Never return that bundle from a
web session endpoint, to a child app, in URLs, or in logs. First-party browser
refresh credentials are never involved. `/oauth/token` refresh is serialized by
the Android broker and preserves scope and the fixed original family expiry.
`session_id` and `/oauth/session` proof `exp` bind the account and absolute lifetime.

The store's explicit `broker:true` native start/exchange adds a `broker` object to
its existing device response: `issuer`, `appOrigin`, `subject`, `account`,
`accessToken`, `refreshToken`, `scope`, `accessExpiresAt`, `sessionId`,
`sessionCheckToken`, `sessionExpiresAt`. Expiries are integer Unix seconds; the
absolute family expiry is verified against the live proof's `exp`. Legacy native
clients omit that flag and receive only the usual store device credential.

Discovery advertises `native_broker_authorization_endpoint`, whose value is
`https://gravitas.cool/oauth/broker/authorize`.

The store sends a JSON POST with its appstore-origin IAM **access** bearer:

```json
{
  "app_origin": "https://spacetime.gravitas.cool",
  "redirect_uri": "https://spacetime.gravitas.cool/auth/gravitas/callback",
  "code_challenge": "<child-owned S256 challenge>",
  "code_challenge_method": "S256",
  "scope": "profile.name",
  "state": "<child-owned random state>"
}
```

The exact Spacetime binding is its **existing** `/auth/gravitas/callback` URI.
Broker codes are not navigated to that URI. Its ordinary browser flow is unchanged.

Successful no-store JSON contains `code`, `state`, `issuer`, `app_origin`,
`redirect_uri`, `session_id`, `sub`, and `expires_in` (at most 60 seconds).
The code is single-use, S256-bound, target-specific, and belongs to the broker's
existing IAM login family. Existing target `profile.name` consent is required;
this endpoint cannot create/expand grants, delegate `native.broker`, or request
chat scopes. Exchange uses the existing `/oauth/token` authorization-code grant
with the exact redirect URI and child verifier. Resulting tokens/proof remain
bound to the original family. The backend validates issuer, origin, subject,
family and proof before issuing its normal local native session.

Errors are no-store JSON: `401 invalid_token` for missing/invalid/revoked/expired
access; `403 insufficient_scope` for an unauthorized or unbound broker;
`403 consent_required` if target consent is missing; `400 invalid_request` for
bad target/state/challenge/scope; `503 temporarily_unavailable` for transient IAM
storage failures. An expired access credential may be refreshed once if eligible.
Revocation/failed refresh requires explicit sign-in. Network/503 errors retain
local encrypted credentials and edits and never imply authenticated access.

## Android contract

- Account type: `dev.jeeth.privatestore.gravitas`.
- Store package: `dev.jeeth.privatestore`; release SHA-256 certificate:
  `e70b5b54a0d174f4ad8867889f6481a2b193dc9c130630f321563e12f3293793`.
- Spacetime package: `com.jeethsuresh.spacetime`; release SHA-256 certificate:
  `f5714ad3d2b3d82b283efd61b2d99f5eaad5ec9efe67b644a62efc79fec94582`.
- `authTokenType`: `gravitas_code:spacetime:v1:<challenge>:<state>`. The challenge
  and state are independently random-request-bound 43-character base64url values;
  the challenge is SHA-256 of a verifier retained only by Spacetime.
- Options: `protocolVersion=1`, `codeChallenge`, `state`, all matching the type.
- Result: `KEY_AUTHTOKEN` is the one-use code, with `protocolVersion`, `state`,
  `codeChallenge`, `issuer`, `appOrigin`, `redirectUri`, `sessionId`, `subject`.

The authenticator verifies AccountManager's original caller UID, resolves its
single exact package, and compares the installed release certificate against the
approved service mapping. It never accepts caller-supplied URLs or scopes. The
child independently pins the store package/certificate and authenticator before
requesting an account. Custom-token cache expiry is zero; request-specific token
types prevent platform caching across different challenges/states, and the child
immediately invalidates each received code. State/version/challenge/account and
returned issuer/origin/redirect/family/subject are checked before exchange.

For installation after account setup, the child first pins and calls the
`dev.jeeth.privatestore.gravitas` ContentProvider's `prepare` method. This narrow
handshake verifies the actual Binder caller's sole package and release signer,
then reconciles AccountManager visibility immediately. It returns only
`protocolVersion:1` and `available`, never an account name or credential. Query,
CRUD, unknown methods and unapproved callers are rejected. It does not add an
account or initiate consent; absent accounts still use browser fallback.

Spacetime posts `{code, code_verifier, session_id, sub}` to its own
`/api/auth/gravitas/broker`. Only its existing local bearer/user response reaches
the child. The child's verifier never goes through the store.

Refresh runs on demand and opportunistically during update checks. Periodic
Android jobs are inexact and cannot guarantee access-token expiry timing. No
background job extends the fixed 30-day IAM family maximum.

Central Gravitas logout revokes the family: broker access/refresh, unfinished
codes, native app proofs/sessions, and protected streaming mutations all fail.
No client positively caches revocation status for protected requests. Existing
store-only logout clears the store account/broker credentials and device session;
it does not silently broaden to unrelated browser/device sign-out. A later
reauthentication cannot revive a previously revoked family.
