# Protocol capability registry (PCR), version 1

Gravitas stores a user's protocol subscriptions separately from the service catalog. Discovery returns protocol names, exact semver versions, permitted capabilities, required permission arrays and their input/output objects. It never returns provider origins, application identities, registration IDs, installed packages, device lists, callback URLs or provider counts. Multiple providers of an exact protocol version are multicast targets; the sender receives the same asynchronous receipt regardless of their number or delivery outcome.

This is a general JSON transport. `appstore` is its first protocol, with `push.send` for a particular opaque device handle and `push.broadcast` for all that app's enabled devices. Neither protocol registration nor the core relay contains push-specific routing logic. The appstore repository owns `protocols/appstore/1.0.0.json`; consumers retain an exact copy under their root `protocols/` folder. The IAM copy under `test/fixtures/` is solely a test fixture.

## Credentials and permission layers

User-facing app tokens register a PCR with the existing `profile.name` login grant. The authenticated principal and app origin determine its ownership. A service must be an operator-configured backend to receive deliveries. Only the configured namespace owner can introduce a new protocol/version. Another provider can register an identical existing version. Changing a published spec returns 409; publish a new semver version instead. PUT replaces that app's complete registry atomically; an empty `protocols` array unsubscribes it. Revoking the app grant deletes registrations and queued deliveries. Subscriptions persist across individual session sign-outs until the app grant or registration is removed; delivery devices independently enforce session revocation.

Each capability has a required `permissions` array. Capabilities can be peers with additive permissions: `push.send` requires `appstore.push`; `push.broadcast` requires both `appstore.push` and `appstore.push.broadcast`. Discovery filters capabilities by the caller's effective permissions. Old tokens without a scope snapshot cannot inherit these new permissions when a grant is upgraded. App tokens can request the registered `protocols.read`, `appstore.push` and `appstore.push.broadcast` scopes through normal consent. Server-initiated notifications use separate, permission-limited backend credentials.

Set the secret `PROTOCOL_SERVICES` to a JSON map keyed by canonical HTTPS backend origin:

```json
{
  "https://apps.example": {"key": "REPLACE_WITH_RANDOM_PROVIDER_CREDENTIAL", "permissions": ["protocols.read"]},
  "https://calendar.example": {"key": "REPLACE_WITH_DISTINCT_RANDOM_SENDER_CREDENTIAL", "permissions": ["protocols.read", "appstore.push"]}
}
```

Keys must be distinct, at least 32 bytes, and kept server-side. `PROTOCOL_OWNERS` maps protocol names to their owner origin, e.g. `{"appstore":"https://apps.example"}`. The hosted overlay sets the appstore owner and routes HTTPS connections through `PROTOCOL_GATEWAY_ADDR`; Host, SNI and TLS verification still use the configured provider hostname. Independent deployments may omit that gateway. Destinations are derived exclusively from operator configuration, always `/api/protocols/invoke`; PCR JSON cannot select a URL or credential. Redirects and automatic HTTP retries are disabled.

## API

All endpoints require bearer authentication and return no-store responses. JSON examples below contain placeholders.

* `PUT /app/v1/protocols/registry` with the user's app access token: `{"schema_version":1,"protocols":[SPEC]}`.
* `PUT /protocols/v1/registry` with a trusted backend credential: `{"session_proof":"STATUS_CREDENTIAL","registry":{"schema_version":1,"protocols":[SPEC]}}`. This supports existing-device reconciliation. IAM requires a live status proof bound to that same backend origin, then derives the principal and grant itself. A status credential alone cannot register.
* `GET /protocols/v1/specifications` lists catalogued versions and structures available to a caller with `protocols.read`.
* `GET /protocols/v1/users/PRINCIPAL_UUID` lists that user's subscribed versions and structures, with the same read permission. Unknown users return an empty protocol list.
* `POST /protocols/v1/users/PRINCIPAL_UUID/invoke` validates the exact version, capability, permissions and input before enqueueing:

```json
{
  "id": "unique-idempotency-key",
  "protocol": "appstore",
  "version": "1.0.0",
  "capability": "push.send",
  "input": {"app":"spacetime","device":"OPAQUE_64_HEX_DEVICE_HANDLE","payload":{"kind":"event.invited","title":"Dinner"}}
}
```

The response is always `202 {"id":"unique-idempotency-key","status":"accepted"}` for an authorized valid request, including a user with no matching providers. It confirms durable acceptance, not OS display. Reusing an ID with different content or recipient returns 409. IDs are scoped to the sender origin. Discovery and invocation never disclose delivery counts, upstream errors or per-provider results.

The receiver gets the invocation plus `sender`, `subject` and `issuer`, all supplied by Gravitas, authenticated with its own backend credential. The sender's credential is never forwarded. Providers implement the declared capability and return a success HTTP status. The first version supports asynchronous capabilities; output objects describe the capability receipt and are discoverable, while provider-specific response bodies stay private. Synchronous result aggregation is future work.

## JSON contract and delivery bounds

PCR v1 supports a bounded JSON Schema subset: `type`, `properties`, `required`, `additionalProperties` (boolean), `items`, `enum`, string lengths/patterns, numeric bounds, array lengths and `description`. External references, remote loading, combinators and unsupported keywords are rejected. Inputs and outputs must be objects. Specs are at most 32 KiB with at most 32 capabilities; registries contain at most 32 specs; invocation input is at most 8 KiB. Exact semver versions include prerelease/build identifiers; no implicit version selection or fallback occurs.

An invocation and its fan-out deliveries are inserted in one Postgres transaction. Each destination is leased with `FOR UPDATE SKIP LOCKED`, retried independently with bounded exponential backoff, and removed only after success, provider removal or seven-day expiry. No outbound HTTP runs inside a database transaction. A slow worker cannot delete another worker's lease. The service rate limit is 1,000 new IDs per minute; idempotent retries do not consume another slot. Delivery is at least once, so receivers deduplicate by sender and request ID. Revoking a provider grant cancels pending work. Key rotation/removal takes effect on the next delivery attempt.

## Validation and rollout

Domain tests cover a second unrelated protocol, semver immutability, ownership, schema/permission checks, private multicast, receipts, deduplication, retry and grant removal. HTTP tests cover app tokens, backend credentials and origin-bound status proofs. `ProtocolInteropTest` runs the real Spacetime event API/outbox, Gravitas HTTP registry/relay and appstore stream/ack using standalone test binaries. Set `PROTOCOL_INTEROP_APPSTORE_BINARY` and `PROTOCOL_INTEROP_SPACETIME_BINARY` to enable it; normal CI explicitly skips that cross-repository fixture when those binaries are absent.

Prepare backend secrets first. Deploy IAM and its migration, then appstore with `PROTOCOL_RELAY_KEY`. Verify existing-device registry reconciliation before deploying Spacetime with `NOTIFICATION_PROTOCOL=appstore/1.0.0`. Existing active store devices reconcile server-side without phone polling. Failed sends remain queued during rollout. Verify the public IAM discovery advertises the new endpoints, both deployments are ready, signed Android releases are public and Private Store ingests their version-matched changelogs.
