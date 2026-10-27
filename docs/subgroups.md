# Gravitas participant sub-groups

A participant set is a registered, nonempty set of stable person identities.
Singletons are the minimum. Only actual rosters and their singleton participants
are registered; no power set is generated. Local people use `principal:<uuid>`;
verified remote Matrix members use their full qualified `matrix:<mxid>` identity.

`participant_sets` stores canonical sorted member arrays, their cardinality, and a
SHA-256 identity. Exact equality is checked when a fingerprint already exists.
`participant_set_edges` stores the strict-containment cover DAG, oriented from
superset to subset. Insertion reconnects immediate edges, preserving reachability.
An advisory transaction lock serializes concurrent registration and edge updates.
GIN membership and cardinality indexes narrow containment candidates.

A group/room keeps its stable ID and refers to its current set through
`group_subgroups`. Roster changes append `group_subgroup_revisions`; identical
rosters reuse a set. Invitations do not change the joined set. Empty rooms have a
null current subgroup, retain their revision history, and never register an empty
set. Historical sets remain registered. Equal participants never merge rooms,
histories, role assignments, app selections, or encryption state.

The legacy membership writer and native Matrix resolved-state projector update
the registry in the same transaction as authoritative membership. Native state
resolution includes remote members and removals. Account registration creates a
singleton in its account transaction. The additive migration backfills existing
people and rooms. Restoring an older application image does not undo the tables;
before re-enabling subgroup queries after an old writer ran, use a maintenance
transaction to run `LakehouseMatrix.Subgroups.backfill!()` against current rosters.

## Membership, placement, and visibility

Containment follows the joined participant set. Adding or removing a participant
moves the conversation to the resulting subgroup. No single containing group owns
this mathematical relationship. Removing someone from an independently existing
containing group does not remove them from every subset conversation. Existing
full-space channels retain their explicit roster-following behavior.

Visibility and placement remain conversation metadata and existing ACLs. The
optional `cool.gravitas.river.context.v1` state records a conversation's explicit
`context_id` and participant-only visibility. Changing its audience never rewrites
that metadata. Matrix navigation and signed event graphs are separate structures.
Containment does not grant access, app consent, or management rights.

Contacts remain independent private account relationships. Group members need not
be contacts, and subgroup operations never create or remove contact edges.

## Delegated API

- `POST /app/v1/conversations` accepts optional `context_id` (or `space_id`) in
  addition to `name`, `member_ids`, and `txn_id`. The actor must have authorized
  read access to that context, and every invited peer must currently be joined
  there. No contact relationship or `contacts.read` scope is needed for this path.
  Recipients are invited and must explicitly accept. A one-peer contextual
  conversation gets its own room; it never reuses an unrelated private DM.
- Without a context, existing contact consent and canonical-DM rules remain.
- Group descriptions include `subgroup_id`, `subgroup_revision`, and `context_id`.
  Invited users receive no subgroup identity before joining.
- `GET /app/v1/groups/:id/subgroups` requires `chats.list`, `chats.read`, current
  joined membership, and existing app selection. It returns the current subgroup,
  revision, participant count, singleton references, `containing_groups`,
  `contained_groups`, `same_participant_groups`, and immediate `parents`/`children`.
  Immediate edges are computed within the authorized projection; hidden
  intermediates do not influence returned edges or counts. There is no arbitrary
  set-ID lookup or global membership-enumeration endpoint.

Apply migration `20261027120000` with the existing IAM maintenance procedure before
deploying the dependent River client. Preserve immutable room and group IDs.
