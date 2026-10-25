# Native Matrix compatibility

Gravitas implements Matrix in Elixir. This branch adds native room versions 11
and 12, signed event graphs, state resolution, room federation, and homeserver
E2EE services. It is still **not a complete Matrix 1.19 implementation**. The
client versions endpoint remains conservative until the remaining conformance
work and release checks pass.

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
read and send encrypted room content. Server support verified by the reference
clients does not mean River client E2EE is complete.

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
- Authenticated local/remote media and multipart federation downloads, with
  separate visibility for private River uploads and standard Matrix media.
- Matrix 1.19 policy-server requests and signature validation. Local operations
  retry outside database transactions; unapproved inbound events soft-fail.

Native creation is controlled by `:native_event_graph`; background federation
workers by `:federation_enabled`. Both default to false until rollout.
`MATRIX_SIGNING_KEY` must contain a persistent dedicated Ed25519 seed. Do not
reuse the IAM JWT key or rotate a seed under an existing key ID.

## Remaining release and conformance work

- Complete remaining account-management, search, reporting, OpenID, third-party,
  media and administration work. Audit every Matrix 1.19 module and required
  behavior, document server policies and optional operations, and return honest
  Matrix errors for unsupported endpoints.
- Integrate maintained crypto and recovery into River without widening its
  existing delegated grant silently. Test web and native clients.
- Finish the reset/release tooling, signing-key provisioning, runtime flags,
  fresh production backup, final CI/review, merge and immutable deployment.

Do not advertise full v1.19 compliance, enable production federation, or claim
this branch has deployed until these checks are complete.

References: [Matrix 1.19](https://spec.matrix.org/v1.19/),
[client API](https://spec.matrix.org/v1.19/client-server-api/),
[server API](https://spec.matrix.org/v1.19/server-server-api/),
[room version 12](https://spec.matrix.org/v1.19/rooms/v12/), and
[MSC4186](https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md).
