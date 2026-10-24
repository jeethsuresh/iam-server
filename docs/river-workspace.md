# River workspace APIs

Extends the contacts release without changing the Go/Flutter architecture. Source
reference for Orbit parity: jeethsuresh/orbit f8abebcb407bc8a4d4e4920a6862e549f7ec3e00.

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
