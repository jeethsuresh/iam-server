# Gravitas contacts

Contacts are mutual, account-level relationships shared by explicitly consenting
apps. A pending request is not a contact. Signing into an app never accepts a
request or writes an extra per-app friendship. Removal and blocking apply across
apps; unblocking never restores the old request/contact.

## Delegated API

- `contacts.read`: GET `/app/v1/contacts` returns `contacts`, `requests`, `blocked`.
  People have `principal_id`, `username` and the canonical Gravitas `user_id`.
  Accepted contacts have `uses_app`, indicating whether that active person has a
  current `contacts.read` consent grant for the **calling token's app origin**.
  This is consent-based app participation, not online status or a live session.
  Pending requests have `id` and `direction` and reveal no app participation.
  An `app_origin` query parameter cannot inspect another app. Other people's
  blocks and unrelated contact graphs are never returned.
- `contacts.manage`: POST `/app/v1/contacts` with `action`, `username` (or local
  qualified `user_id`) and `txn_id`. Actions are `request`, `accept`, `ignore`,
  `cancel`, `remove`, `block`, `unblock`. The authenticated grant supplies actor and
  app origin. Only the recipient can accept/ignore and only the sender can cancel.
- `contacts.read`: GET `/app/v1/contacts/events` returns at most 100 chronological
  events attributed to the calling app and involving the current account. Block
  events are visible only to their actor. It is not an arbitrary app-usage lookup;
  re-read the contact list to see changes made in other apps.

Actions retain pair locking, request rate limits and immutable idempotent audit
records. New account events use `cool.gravitas.contact.v1`, `content.version=1`,
action, target `user_id`, originating app and sender. Events stay private account
data and never enter group timelines. No credentials are recorded.

The first-party `/contacts` page uses the central authenticated browser session,
server CSRF protection and the same action implementation. It has no delegated
admin bypass and never takes an actor ID from submitted fields.

## River mapping

`/app/v1/friends` remains a compatibility-shaped River projection over Contacts,
now requiring the explicit new contact scopes. Accepted contacts with `uses_app`
are `friends`; others are `other_contacts`. Requests remain pending. User IDs in
this projection use the configured Matrix domain for existing DM interoperability.
A canonical direct room can be opened only for an accepted, unblocked contact
who approved the same app's contact access, in addition to existing group scopes
and room selection checks. Contact removal preserves existing DM history. Blocks
continue to deny direct writes, without altering shared-space membership.

The shared Flutter client reads this projection during login and foreground
refresh. It sends no synthetic friend requests or accept operations. If a contact
later approves River access, they appear automatically; revoking that access
moves them back to Other Gravitas contacts on refresh. A logged-out but still
consenting contact remains a friend. Both people must approve the new permission.

## Compatibility and release order

Existing River relationships, pending requests, blocks and IDs are reused in
place. The historical `river_friendships`, `river_friend_blocks` and
`river_social_events` SQL table names remain to avoid copies and destructive
renames. The domain implementation and schemas now live in `lakehouse_iam`.
Migration `20261023120000` only adds an event `type`, defaulting to the historical
`cool.gravitas.river.friend.v1` for existing rows and old writers. Existing events
retain their original types and IDs; new actions explicitly use contact.v1.

Legacy `friends.read/manage` remain recognized protocol strings for old clients,
but do not grant access to the shared contacts API or friend projection. Token
scope snapshots and legacy-nil-snapshot exclusion prevent silent privilege
upgrades. The new consent page explains shared data, participation discoverability
and cross-app write effects. App revocation and account deactivation remain
immediate access boundaries.

Deploy the additive IAM migration/API first, then the River backend/client with
`contacts.read contacts.manage`. Keep the existing approved deployment and IAM
maintenance procedures. Old River sessions need one explicit reconnect; chat
remains usable while contact consent is missing. Old peer grants do not imply new
contact discoverability: the peer must approve River's contacts access too.
Do not merge/deploy under an unrelated earlier release approval. No live fixtures
or production data changes are needed to run the PostgreSQL/Chromium CI suite.
