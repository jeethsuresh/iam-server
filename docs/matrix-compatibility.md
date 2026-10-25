# Native Matrix compatibility

Gravitas implements Matrix in Elixir. This branch adds native room versions 11
and 12, signed event graphs, state resolution, room federation, and homeserver
E2EE services. The native backend targets Matrix 1.19 and advertises it when
`MATRIX_NATIVE_EVENT_GRAPH=true`. The older local backend retains its v1.1
advertisement. The native release must pass the API/browser and independent
version-negotiated federation/crypto gates before production rollout.

## Verified interoperability

`integration/matrix/run.sh` starts disposable, isolated instances of Gravitas,
Synapse 1.163.2 and real Matrix JavaScript SDK 44 clients backed by Rust crypto.
Images, dependencies and test peers are pinned. The suite verifies signed joins
in both directions, two-way message delivery and leave, knocks in both directions,
private invitation decline, room upgrades through tombstones and moved aliases,
federated thread relations and aggregates, federated encrypted-room
invites, Olm key sharing, Megolm decryption in both directions, cross-signing,
encrypted secret storage, client-encrypted key backups and fresh-device recovery.
The suite also transfers and decrypts client-encrypted attachments in both
directions. It also verifies refresh credentials, encrypted notifications and
private read receipts. The native event API exposes ciphertext only. Synapse is a test peer
and is not part of the production deployment.

CI runs this suite after the existing unit, API and real-browser test gate.
The state-resolution fixtures also compare eight version-11/12 fork scenarios
with the unmodified Synapse implementation. Focused tests cover malformed event
signatures, historical key retention, auth/state rejection, soft failures,
missing dependencies, replay, delivery leases, redaction authorization, private
invitations, device revocation, backup merging and policy-server signatures.

## Shared River rooms

New River spaces and channels use the same signed PDU graph and resolved state
as standard Matrix rooms. River's internal room UUID maps to the wire room ID;
version-12 room IDs and event IDs derive from the signed create/event hashes.
River requests retain idempotency through a request-to-event ledger. Channel
join rules use the parent space as a restricted-join eligibility room.

The rollout may reset room state and history, as authorized for this transition.
Do not synthesize federation signatures for old random event IDs. Accounts,
identity credentials and global account secrets must survive a room reset.
River itself still needs a maintained client crypto integration before it can
read and send encrypted room content. Its delegated plaintext API rejects new
messages, edits, reactions and attachment manifests after a room enables
encryption; the older browser chat sender applies the same safeguard. Standard
Matrix clients can send ciphertext through the Matrix API.
Server support verified by the reference clients does not mean River client
E2EE is complete.

## Protocol services

- Canonical JSON, Ed25519 PDU hashes/signatures, room-version authorization,
  persisted state-before/state-after snapshots, state resolution 2 and 2.1,
  DAG extremities, authenticated redaction and timeline/state projections.
- Signed server discovery and requests, historical signing-key cache with
  immutable key-ID bindings, public-address validation, DNS-pinned verified TLS,
  bounded responses and no implicit redirects.
- Inbound replay-protected transactions, durable dependency recovery and leased
  outbound delivery, ACLs, room-state/auth-chain retrieval, make/send join, leave
  and knock, restricted-join co-signing and verified remote room snapshots.
- Local and remote device keys, atomic one-time/fallback-key claims, durable
  local and federated to-device messages, device/signing-key changes,
  cross-signing signatures and password-based user-interactive authorization.
- Opaque encrypted room-key backups and secret storage. Private signing,
  recovery and room keys are generated and held by clients.
- Renewable device sessions, one-use two-minute login tokens with fresh UIA,
  and browser-bound SSO with explicit full-account consent. Refresh credentials
  retain their identity until device revocation, so lost responses can be retried.
  Neither login flow changes existing delegated application grants.
- Reversible account locks and suspensions through the standard administrator
  endpoints. Locks retain credentials and return `M_USER_LOCKED` with soft
  logout, while permitting explicit logout. Suspensions retain reading, new
  sessions, device verification, key backup, own-event redaction and room leave;
  they prevent room, profile and directory writes. Local graph and River writes
  recheck moderation under the stream lock. Existing River sockets and app tokens
  also respect these restrictions, and locked accounts receive no HTTP pushes.
  Whois is private to the account and administrators; connection metadata which
  the server does not retain is omitted.
- Password-reauthenticated account deactivation permanently closes the shared
  Gravitas identity, revokes IAM, app and Matrix credentials, and removes private
  client state and encrypted backups. IAM approval and bootstrap configuration
  cannot reopen it. Leased room departures continue after the response, retry
  failures and rotate through rooms so one unavailable peer cannot block others.
  Erasure prunes room content for later members and servers while retaining
  original copies for prior members. It preserves canonical authorization and
  ACL state, filters search and relation data, and covers River read models,
  invitations, late history and federation retrieval/delivery. A real redaction
  removes the preserved original. Erasure is not broadcast to other servers,
  which may retain their existing copies, as specified by Matrix.
- `m.invite_permission_config` blocks local, raw-state and incoming federation
  invitations with `M_INVITE_BLOCKED`. Existing invitations are suppressed in
  classic, sliding and legacy sync; removing the setting restores them. Public
  device/master/self-signing keys can be discovered before users share a room;
  user-signing keys remain owner-only. Device IDs cannot collide with any of the
  account's cross-signing key IDs, and a new login replaces that device's old
  access and refresh credentials.
- State events expose `unsigned.replaces_state`; `prev_content` is included only
  when the prior event is visible, with erasure and redaction applied. Managed
  `m.push_rules` and `m.fully_read` account data reject direct writes with HTTP
  405. The dedicated read-marker API updates receipts and account data atomically.
- Image-pack state, global pack references, recent emoji, key-backup metadata,
  moderation lists, stickers and VoIP signalling use the common state/event and
  private account-data APIs. Typed image-pack media references preserve River's
  private-media authorization and redaction boundaries.
- Atomic v11/v12 room upgrades, tombstones, predecessor links and moved local
  aliases. Replacement rooms transfer standard settings and invite members
  without impersonating joins; tags, direct-room links and room push rules are
  copied when the user joins. Additional creators are explicitly selected.
- Matrix 1.19 default push rules and ordered user rules, typed conditions,
  escaped paths, bounded glob matching, notification pagination and unread counts
  in ordinary and sliding sync. Receipt history preserves counts at delivery
  boundaries; public/private and thread receipts cannot move backwards.
  Device-bound HTTP pushers use leased retries, verified HTTPS and public-address
  DNS pinning. Event-ID-only payloads and read/device revocation are enforced.
- Ordinary sync with state-after support and native MSC4186 sliding sync,
  scoped cursors, device/account data, resolved-state updates and receipts.
  Native history uses DAG order and verified backfill, retaining eligible history
  after leaving without exposing later private events.
- Legacy initial snapshots, event lookup and event streams remain available for
  older clients and room previews. Peeking requires world-readable history;
  private invitations expose stripped state, and archived snapshots stop at
  the user's leave. Streams merge timeline and resolved-state changes and page
  bursts without dropping events. Tokens remain bound to the user and device,
  and every polling iteration rechecks access and account locks.
- Relations with three-level recursive pagination, edit/reference/thread
  aggregates, thread lists and participation filters, duplicate reaction
  prevention, ignored-user filtering and redactions through the send endpoint.
  Aggregates exclude hidden history, ignored senders and redacted relations.
  Sliding positions work in history/relations; current proposal requests use
  non-sticky parameters and include knocks, departures and removed-state stubs.
- Permission-filtered room summaries and space hierarchy across federation,
  ordered depth-first pagination, restricted-room eligibility and cycle handling.
  Remote previews stay in a bounded-lifetime metadata cache, never in verified
  room state. Timestamp lookup applies visibility rules and can import a closer
  event only after checking its signature, state and auth chain.
- Local aliases, explicitly published room directories with filtering and
  pagination, native membership moderation, profile updates, a shared-room user
  directory, typing and presence with expiry. Declining a remote invitation
  queues a stable signed leave without promoting stripped state. Forgetting
  hides a departed room for that user and rejoining restores it.
  Profile changes also produce presence updates without resetting activity;
  inactive ages advance and local expiry reaches joined federation peers.
  Profiles support namespaced JSON fields, `m.tz`, deletion and the 64 KiB limit;
  only display name/avatar enter room memberships and presence. Private room
  tags preserve fractional ordering and mutual-room pages bind user/device and
  recheck current membership without including new joins in an older page.
- Short-lived OpenID identity attestations use separate hashed credentials;
  they cannot authenticate Matrix clients. Room, event and user reports are
  retained privately with bounded reasons and per-user limits. Event reports
  require current membership; unknown targets can be concealed without accepting
  inaccessible event evidence.
- Authenticated local/remote media and multipart federation downloads, with
  separate visibility for private River uploads and standard Matrix media.
  Raw JSON files retain their bytes and MIME type through client upload and
  federation. Owner-bound asynchronous MXC reservations expire after 24 hours,
  enforce pending-upload quotas, and serialize writes without holding the global
  stream lock. Downloads can wait for pending uploads and return
  `M_NOT_YET_UPLOADED`; completed media cannot be overwritten.
  Private legacy media uses authorized typed attachment references, including
  history visibility and redaction checks. UUID text cannot grant access.
  Explicit sharing of readable attachments into federating rooms publishes the
  required media, while local-only rooms retain private access.
  Matrix requests accept JSON without a mandatory Content-Type and
  return JSON-object/parse errors with CORS; browser SSO and legacy uploads retain
  their existing request handling.
- Indexed plaintext search supports body/name/topic keys, including the plain
  text representation in `m.topic`, ranking and recent ordering, filters,
  per-event context and historical profiles, state and room/sender groups.
  Encrypted rooms, redactions, forgotten rooms and inaccessible history are
  excluded. Results are bounded to 100 with approximate counts; search does not
  issue pagination tokens, as permitted by the search specification.
- Raster previews use one supervised converter per VM, with bounded memory,
  disk and execution time and a raster-only ImageMagick policy. Disconnecting
  the requesting client retains the converter slot until the process exits.
  Unsupported vectors/documents remain downloadable as original uploads;
  their bytes never enter preview conversion. See the
  [ImageMagick policy documentation](https://imagemagick.org/security-policy/).
- Authenticated URL previews fetch only public HTTPS endpoints with verified,
  DNS-pinned TLS, no redirects, a 1 MiB response limit, a ten-second deadline,
  four concurrent fetches and per-account request limits. Summaries cache for
  at most five minutes and honor private/no-store responses. Only bounded text
  metadata is returned; remote images and active content are omitted. No room
  messages or encrypted URLs are automatically inspected or fetched.
- Matrix 1.19 policy-server requests and signature validation. Local operations
  retry outside database transactions; unapproved inbound events soft-fail.

Account registration, password changes and recovery remain in IAM with account
approval; Matrix registration is closed. The corresponding Matrix endpoints
return explicit policy errors. `m.change_password` and `m.3pid_changes` stay
false, and the Matrix 3PID list does not expose unrelated IAM contact data.
No third-party network bridges are configured, so discovery returns an empty
protocol inventory and unknown lookups return `M_NOT_FOUND`.

Optional Matrix TURN credentials use the
[coturn REST credential format](https://github.com/coturn/coturn/blob/master/README.turnserver#turn-rest-api).
Set `MATRIX_TURN_URIS` (comma-separated `turn:`/`turns:` URIs),
`MATRIX_TURN_SHARED_SECRET` (at least 32 bytes) and optionally `MATRIX_TURN_TTL`
(60–86400 seconds, default 3600). Configure the same secret on the TURN service.
Credentials bind the Matrix user and expiry; the shared secret is never returned.
This API does not provision a TURN service or reuse LiveKit credentials.

Native creation is controlled by `MATRIX_NATIVE_EVENT_GRAPH`; background
federation workers by `MATRIX_FEDERATION_ENABLED`. Both accept only `true` or
`false` and default to false. Enabling either requires a signing key, and
federation also requires native creation.
`MATRIX_SIGNING_KEY` must contain a persistent dedicated Ed25519 seed. Do not
reuse the IAM JWT key or rotate a seed under an existing key ID.

## Authorized room reset

The reset is an explicit maintenance release, never a startup or migration hook.
It revokes Matrix access/refresh sessions so clients sign in again, advances the
protocol epoch to invalidate all old cursors, and clears room graphs, room data,
room-specific roles, selected application room IDs, cached sync/discovery state
and pending room delivery. Selected grants retain their selected mode.
Accounts, IAM sessions and app tokens, owned uploads, device/cross-signing keys,
client-encrypted backups, global secret storage and non-room preferences survive.
Room history and River room publications are part of the room reset.

`LakehouseMatrix.Release.room_reset_plan()` returns a read-only summary.
For the authorized Gravitas rollout, set `IAM_KUSTOMIZE_OVERLAY=gravitas`,
`IAM_MAINTENANCE_RELEASE=1`, `IAM_ROOM_RESET_SERVER=gravitas.cool` and the explicit
`KUBE_CONTEXT`, then run `scripts/kubernetes/deploy.sh` with the verified image
digest. The release stops writers, creates a fresh custom-format PostgreSQL dump
on the retained database volume, checks its archive and data stream and prints
its checksum, then submits one job which migrates and resets. The persistent
migration CronJob never contains the reset command. A failed backup restores the
old writers; once a reset job may have run, a failure leaves writers stopped for
inspection and recovery. Normal maintenance releases retain their existing
failure recovery.

Signing-key provisioning, final conformance and production deployment are still
pending. These release tasks have been tested against disposable databases and
mocked Kubernetes calls; the production reset has not run.

## Deployment policies and remaining release work

- Matrix registration and recovery remain governed by IAM approval and password
  management. Guest registration and identity-service invitations/bindings are
  disabled. There are no registered application services: service-only client
  operations reject ordinary tokens. Matrix authentication uses the legacy
  password/token/SSO API; OAuth metadata returns `404 M_UNRECOGNIZED`. No hosted
  policy server or support-contact document is configured. These discovery
  endpoints also return 404. Policy-server participation uses external servers.
- Run the final version-negotiated SDK/federation gate and exact-commit CI/review,
  provision the persistent signing identity, merge, take the fresh production
  backup and deploy the immutable release.
- River client encryption and recovery UI is separate client work. Its delegated
  grant must never be widened silently; homeserver E2EE is verified with standard
  Matrix clients.

Do not claim this branch has deployed until the release checks are complete.

References: [Matrix 1.19](https://spec.matrix.org/v1.19/),
[client API](https://spec.matrix.org/v1.19/client-server-api/),
[server API](https://spec.matrix.org/v1.19/server-server-api/),
[room version 12](https://spec.matrix.org/v1.19/rooms/v12/), and
[MSC4186](https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md).
