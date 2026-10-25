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
in both directions, two-way message delivery and leave, federated encrypted-room
invites, Olm key sharing, Megolm decryption in both directions, cross-signing,
encrypted secret storage, client-encrypted key backups and fresh-device recovery.
The native event API exposes ciphertext only. Synapse is a test peer and is not
part of the production deployment.

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
- Ordinary sync with state-after support and native MSC4186 sliding sync,
  scoped cursors, device/account data, resolved-state updates and receipts.
- Local aliases, explicitly published room directories with filtering and
  pagination, native membership moderation, typing and presence with expiry.
- Matrix 1.19 policy-server requests and signature validation. Local operations
  retry outside database transactions; unapproved inbound events soft-fail.

Native creation is controlled by `:native_event_graph`; background federation
workers by `:federation_enabled`. Both default to false until rollout.
`MATRIX_SIGNING_KEY` must contain a persistent dedicated Ed25519 seed. Do not
reuse the IAM JWT key or rotate a seed under an existing key ID.

## Remaining release and conformance work

- Complete authenticated local/remote media, history/backfill pagination and
  room visibility semantics; exercise them against an independent homeserver.
- Complete core client room lifecycle, context/relations/threads, space
  hierarchy, profile/directory and notification/push-rule APIs and audit the
  remaining Matrix 1.19 required behavior. Optional modules must be documented
  explicitly and unsupported endpoints must return honest Matrix errors.
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
