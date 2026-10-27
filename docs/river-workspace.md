# River workspace APIs

Extends the contacts release without changing the Go/Flutter architecture. Source
reference for Orbit parity: jeethsuresh/orbit f8abebcb407bc8a4d4e4920a6862e549f7ec3e00.

A conversation is exactly one ordinary Matrix room. A space is an `m.space`
with multiple child conversation rooms linked by `m.space.child`/`m.space.parent`.
Posts and discussions belong to that space, not to any child room or DM/group.
Their custom `cool.gravitas.river.post.v1` / `cool.gravitas.river.discussion.v1`
objects contain `version: 1`, the canonical Matrix `space_id`, `title` and `body`.
The space root is the Matrix transport for those objects. Legacy space events
without an explicit ID remain readable; immutable history is not rewritten.

- GET /app/v1/spaces/:id/entries?kind=post|discussion reads the space feed.
- PUT /app/v1/spaces/:id/entries/:type/:txn creates an idempotent custom event.
- POST /app/v1/spaces/:id/entry writes an authored immutable edit.
  Conversation and channel targets return `space_required`, including through
  old group API aliases and native Matrix writes. Membership, operation scopes,
  author checks and encryption rules still apply.
- `matrix.full` requires all current/future rooms in the explicit consent screen.
  River requests it by default alongside its operation scopes. Existing selected
  grants require consent again. Other applications can keep room selection.

- POST /app/v1/conversations takes name, member_ids (1–24 Matrix user IDs) and
  txn_id. Each recipient must be an accepted, unblocked contact who has consented
  to this app. A pair reuses its existing direct room; a group owns a separate
  Gravitas group/Matrix room and invites recipients. Joining remains explicit.
- POST /app/v1/groups/:id/invitations takes space_id and txn_id. The actor must
  belong to the conversation and own the space. It creates auditable Matrix
  membership invitations and a versioned conversation card. Accept/ignore uses
  the ordinary membership endpoint and propagates to separate channel rooms.
- GET /app/v1/home returns unread entries and participating threads, filtered by
  current room selection and membership. POST groups/:id/entry/read records an
  account-private acknowledgement independently of a room timeline read marker.
- GET /app/v1/live streams only ready/invalidate/revoked events. PostgreSQL NOTIFY
  wakes connections after commit, including across pods. No content is carried
  in the notification; the client fetches its current authorized projection.
  The stream checks token validity before each signal and every 10 seconds.
- GET /app/v1/presence exposes only currently connected, accepted contacts using
  the same app origin, with the existing contacts.read permission. Eight live
  connections per account/app are allowed. Process exits release presence.

Apply migration 20261023150000 after the contacts migration. Keep automatic deployment disabled. Deploy IAM before River using the existing
maintenance adapter when a manual release is requested. The Gravitas overlay
configures MATRIX_RTC_URL=wss://rtc.gravitas.cool; the matching River media
resources and protected runtime configuration live in its deploy/media directory.
