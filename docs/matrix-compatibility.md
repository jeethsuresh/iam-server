# Native Matrix compatibility

This is the first stage of bringing Gravitas's native Elixir implementation to
the Matrix 1.19 specification. It is **not a complete Matrix 1.19 homeserver**.
Federated room joins, signed room event graphs, state resolution, cross-signing,
key backups, and a real Matrix client interoperability gate remain unfinished.
Do not describe this release as fully federating or fully E2EE compatible.

## River interoperability

River and standard Matrix clients use the same rooms, memberships, state, and
event records. Existing room and event IDs are preserved. Standard clients can
read River spaces and their parent/child links, receive invitations, accept at
the parent space, send messages and reactions to its channels, paginate history,
and receive subsequent changes with ordinary or sliding sync. Matrix APIs retain
River's owner, block, publication, parent membership, and call membership rules.
They cannot bypass those rules by writing custom Gravitas state or changing a
River room's power levels. Encryption cannot be enabled on an existing River
room because River does not yet implement client-side encryption.

New River DMs also write each participant's private `m.direct` account data.
The migration backfills existing DMs. Users' later account-data edits remain
authoritative; sync does not silently reconstruct deleted `m.direct` entries.

## Client API implemented in this stage

- Password login discovery, local/full Matrix user IDs, persistent per-device
  opaque access tokens, whoami, logout, logout-all, device listing and names.
- Standard room creation presets, invitation-only defaults, initial state,
  encryption state on new native rooms, room state/event/member reads, messages,
  room join aliases, and transaction-safe sends and timeline redactions.
- Commit-ordered ordinary sync, bounded history pagination, and signed cursors
  scoped to user/device/room. Sender timestamps no longer determine delivery.
- Private global and room account data, saved sync filters, read markers and
  public/private receipts.
- Local device-key upload/query, atomic one-time-key claims, fallback keys, and
  durable device messages. These are E2EE transport primitives, not complete
  device verification, cross-signing, or key recovery support.
- Browser CORS, authenticated client media downloads, and Matrix-shaped errors
  for unsupported routes.

`/_matrix/client/versions` now returns specification versions, rather than the
incorrect API path name `v3`. It advertises the conservative `v1.1` baseline and
the `org.matrix.msc4186` extension, not full `v1.19` support.

## Sliding sync

`POST /_matrix/client/unstable/org.matrix.msc4186/sync` supports the deployed
MSC4186 request shape: `ranges`, tuple `required_state`, subscriptions, filters,
and account-data, receipts, to-device, and E2EE extensions. Request positions
are scoped to user, device, and connection ID. Connection state is persisted in
Postgres, expires after 30 minutes, and supports retrying the last requested
position. Invalid positions return `M_UNKNOWN_POS`.

The experimental `POST /_matrix/client/v4/sync` also accepts the current proposal
shape: `range`, include/exclude/lazy membership state requests, non-sticky lists,
`membership`, `stripped_state`, and `expanded_timeline`. This route follows a
proposal; its name is not a claim that it has entered the stable specification.

Limits: 100 list/subscription entries, 100 events per timeline, 100 state
selectors, and windows of at most 1,000 rooms. Explicit subscriptions never grant
room access. Invited users receive stripped state, not message history. Changes
to timeline limits or required state expand the response when necessary. Remote
key lookup, presence and typing extensions are still pending.

## Server API implemented in this stage

The native implementation provides canonical JSON, Ed25519 server-key
publication/query, HTTPS server delegation and SRV discovery, signed outbound
request headers, inbound `X-Matrix` signature verification, and authenticated
local profile queries. Discovery connections pin a public resolved IP while
preserving the original TLS identity and HTTP Host. Private, loopback,
link-local, metadata, mapped-private and non-routable targets are rejected.
Redirects are not followed. Discovery responses have a bounded body size.

Set `MATRIX_SIGNING_KEY` to a persistent base64-encoded 32-byte Ed25519 seed and
optionally `MATRIX_SIGNING_KEY_ID` to an `ed25519:` key ID. Store the seed in the
deployment's secret store and back it up. Do not use the IAM JWT secret. Changing
the seed under the same key ID is invalid key rotation. Old signing-key
retention and trusted key-notary caching must be added before room federation.
Without a key, key publication returns 503 and server well-known discovery
returns 404. This change does not create or rotate production secrets.

Federation authentication never accepts an IAM/Matrix client bearer token as a
server credential. A signature covers the exact HTTP method, encoded URI with
its query string, destination, and parsed JSON body. Server-key documents must
be unexpired, name the requested origin, and verify their own signature.

Federated room transactions return an explicit 501 response. They are **not**
acknowledged or appended to River's policy tables. New native rooms currently
have `m.federate: false`. Existing events lack the signed graph, hashes, and
authorization snapshots required to safely accept remote events.

## Persistence and rollout

Apply migration `20261024120000_matrix_client_state` before starting this code.
It backfills a stream position for every existing event without rewriting IDs,
content, or timestamps, and introduces device, account-data, delivery, filter,
receipt, transaction, and sliding-connection tables. Back up the database first.
The migration takes a write lock on the event table while backfilling it; budget
a maintenance window for a large existing event history.

Pause room mutations until migration and replacement of every old application
pod are complete. Old and new writers use different lock orders; do not leave
both versions serving room writes during a rolling deployment.

The stream clock row remains locked until each writer commits. A cursor cannot
advance past an uncommitted event. Matrix and River write transactions acquire
this lock before room, principal, or grant locks to maintain a consistent lock
order. This deliberately favors correctness; the global clock, per-room sync
queries, and 200ms idle polling need load testing and optimization before large
deployments.

Existing JWT-based first-party sessions remain accepted. Old timestamp sync
tokens on those sessions trigger a complete resync. New device sessions use
hashed opaque tokens and signed cursors. No production deployment is performed
as part of this source change.

## Work remaining for the requested complete implementation

1. Add a persisted signed PDU graph, event hashes, authorization state and
   rejection/soft-failure records. Implement room versions 11 and 12, including
   version 12's hashed room IDs, creator powers, and state resolution.
2. Design and test the River room upgrade path. Preserve old client references
   through aliases/tombstones and explicit old-to-new event mappings; do not
   invent signatures for existing random event IDs or silently rewrite history.
3. Implement inbound/outbound room federation: transactions and retry queues,
   invites, make/send join/leave/knock, auth chains, state, missing events,
   backfill, visibility, server ACLs, device-list EDUs and federated media.
4. Complete device deletion/revocation semantics, cross-signing, key-signature
   distribution, key backups, notifications/push rules, relations/aggregation,
   space hierarchy and the remaining required client endpoints.
5. Add cross-server conformance tests (including forks, failures, replay and
   restart), run against a maintained independent homeserver, and verify a
   current real Matrix client against River's rooms. Only then raise the
   advertised specification version and enable federated room creation.

References checked on 2026-10-24:
[Matrix 1.19](https://spec.matrix.org/v1.19/),
[client API](https://spec.matrix.org/v1.19/client-server-api/),
[server API](https://spec.matrix.org/v1.19/server-server-api/),
[room version 12](https://spec.matrix.org/v1.19/rooms/v12/), and
[MSC4186](https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md).
