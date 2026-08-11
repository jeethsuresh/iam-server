# Room Info Panel + Media Uploads Design

Date: 2026-08-10

## Goal

Add a Room Info slide-over panel for viewing and editing room metadata, managing membership (creator), and listing uploaded files. Support general file uploads into the conversation, with compressed image previews in the timeline. Persist name, avatar, membership, and file messages as Matrix events. Store media on the local filesystem with a pluggable store for remote backends (S3, NFS) later.

## Decisions

| Choice | Decision |
|--------|----------|
| Media storage | Local filesystem (`LAKEHOUSE_MEDIA_ROOT`, Docker volume); `Media.Store` behaviour scaffolds remote |
| Authz: name / avatar | Any joined member |
| Authz: add / remove members | Room creator only (from `m.room.create` `creator` mxid) |
| Remove semantics | v1 kick = `m.room.member` with `membership: "leave"`; UI label “Remove”; ban deferred |
| Uploads | Any joined member with send permission; any MIME; soft cap ~10 MB/file |
| Images | Always compress on upload; timeline shows compressed preview; original downloadable |
| UI | Right slide-over / drawer; open from header (avatar / name / Info); members leave the chat header |
| Event source of truth | Name, avatar, membership, file messages are events; no parallel “shadow” tables for file lists |
| Uploaded files list | Derived from timeline `m.room.message` with `msgtype` `m.image` or `m.file` |
| Default avatar | Static asset under `priv/static` when `m.room.avatar` unset |
| Approach | Matrix CS–shaped media + facade APIs; LiveView calls Elixir APIs (same pattern as today) |

## Architecture

```
LiveView RoomLive (drawer + composer uploads)
        │
        ▼
LakehouseMatrix.Matrix  ──set_name / set_avatar / remove_member / send_message / add_member
        │
        ▼
Events.Processor + handlers (name, avatar, member, message)
        │
        ├── room_events / room_state / memberships
        └── RoomServer PubSub → LiveView

Upload / download HTTP
        │
        ▼
LakehouseMatrix.Media ──► Media.Store behaviour
                              ├── Local (v1)
                              └── Remote stub (S3 / NFS later)
```

### Media module

- `LakehouseMatrix.Media.upload(principal_id, binary, opts)` — validate size, detect MIME, `Store.put` original; if image, write compressed derivative; return `%{media_id, content_uri, info}` with `thumbnail_url` when applicable.
- `LakehouseMatrix.Media.download(principal_id, server_name, media_id)` — auth gate (uploader or room member for media referenced by a room the user joined; exact policy: authenticated + access check), then `Store.get`.
- `Media.Store` callbacks: `put/3`, `get/2`, `delete/2` (delete optional / unused in v1).
- `Local`: files under configurable root; media id is opaque (UUID or content-hash + random).
- `Remote`: stub that documents the contract and returns `{:error, :not_implemented}` until configured.
- Events store Matrix-ish URIs (`mxc://server/media_id`); HTTP serves `GET /_matrix/media/v3/download/:serverName/:mediaId`.
- Upload: `POST /_matrix/media/v3/upload` (authenticated Matrix or session auth as implemented for other CS routes).

### Events

| Action | Event | Content (essentials) |
|--------|-------|----------------------|
| Edit name | `m.room.name` (state) | `%{"name" => name}` |
| Set avatar | `m.room.avatar` (state) | `%{"url" => content_uri, "info" => …}` |
| Add member | `m.room.member` | `membership: "join"` (existing path; creator-only) |
| Remove member | `m.room.member` | `membership: "leave"` for target; actor = creator |
| Chat file | `m.room.message` | `msgtype: "m.file"`, `body`, `url`, `info` |
| Chat image | `m.room.message` | `msgtype: "m.image"`, `body`, `url`, `info` (+ thumbnail fields) |

New handler: `m.room.avatar` → upsert room state (and optional denormalized room field only if useful for list UI; state remains authoritative).

Creator resolution: read `m.room.create` state content `creator`; do not add a `rooms.creator_id` column for v1.

### LiveView UI

- Assign `info_open?`; toggle from header control (room avatar / name / Info).
- Drawer sections:
  1. Avatar (change upload) + editable room name
  2. Members list; Add by username; Remove button if current user is creator (not for self)
  3. Uploaded files (filename, type, link/download; image thumb optional)
- Composer: attach control via LiveView `allow_upload`; after consume → Media.upload → `send_message` with `m.image` / `m.file`.
- Timeline: text as today; images show compressed preview (`thumbnail_url` preferred); non-images show filename + download affordance.
- Remove inline members strip from chat header (moved into drawer). Leave room stays available (header or drawer).

### Authz summary

| Action | Who |
|--------|-----|
| View Room Info | Joined member |
| Edit name / avatar | Joined member |
| Upload chat files | Joined + send permission |
| Add / remove members | Creator only |
| Remove self via Remove | Forbidden (`:cannot_remove_self`); use Leave |
| Download media | Authenticated; uploader or member of a room that references it |

### Image handling

- Detect by MIME / magic bytes.
- Always generate compressed preview on upload (e.g. max edge ~1280, JPEG or WebP).
- If decode fails for a claimed image: store as `m.file` without thumbnail (no crash).
- GC of orphaned media: out of scope v1 (changing avatar leaves old blobs).

### Limits

- Soft max ~10 MB per file (`:too_large` when exceeded).
- Any file type allowed; images additionally get compression pipeline.

## Data flow

1. Client uploads bytes → `Media.upload` → store original (+ preview if image) → `{content_uri, info}`.
2. Client emits Matrix event referencing URI only (never embed bytes in event content).
3. Processor persists event/state; RoomServer broadcasts; LiveView refreshes.
4. Download resolves URI → access check → `Store.get`.

## HTTP / facade surface

**Matrix facade (Elixir):**

- `set_name/3`
- `set_avatar/3` (or `/4` with info)
- `remove_member/3`
- `add_member/3` — enforce creator-only (tighten from “any joined member” if currently looser)
- `send_message/4` — already; accept `m.image` / `m.file`
- `list_room_files/2` — timeline filter
- `Media.upload` / `Media.download`

**HTTP:**

- `POST /_matrix/media/v3/upload`
- `GET /_matrix/media/v3/download/:serverName/:mediaId`
- Optional CS state PUTs for name/avatar if needed for API BDD; LiveView may call facade directly.

## Errors

| Case | Result |
|------|--------|
| Not a member | `:not_member` / flash / `M_FORBIDDEN` |
| Non-creator add/remove | `:forbidden` |
| Remove self via Remove | `:cannot_remove_self` |
| User not found / inactive | existing add_member errors |
| File &gt; 10 MB | `:too_large` |
| Empty / invalid upload | `:invalid_upload` |
| Image decode fails | store as `m.file`, no thumb |
| Media missing | 404 |
| No send permission | `:no_send_permission` |

## Testing

### Unit (ExUnit)

- `Media.Local` put/get; image compress produces smaller preview
- `Media.Store` contract; Remote stub `:not_implemented`
- `Matrix.set_name` / `set_avatar` / `remove_member` events + authz
- `RoomMessage` accepts `m.image` / `m.file`
- `list_room_files` filters correctly
- Avatar handler updates room state

### BDD `@api`

- Upload → send `m.image` → messages include event; download succeeds
- Set room name / avatar via API or facade-backed endpoints
- Creator removes member → target no longer in room sync; non-creator cannot remove

### BDD `@browser`

- Open Room Info drawer
- Edit room name
- Creator add/remove member in panel
- Upload image in composer → compressed preview in timeline
- Uploaded files section lists the file

## Out of scope (v1)

- Ban / unban
- Media garbage collection
- Virus / content scanning
- Public unauthenticated media
- Full Synapse media CS surface beyond upload/download needed here
- Third-column or full-page Room Info layouts

## Defaults & config

- `LAKEHOUSE_MEDIA_ROOT` — local store path (Docker volume in compose)
- Default room avatar static path under `priv/static/images/`
- Server name for `mxc://` from existing Identity / config host (e.g. `localhost`)
