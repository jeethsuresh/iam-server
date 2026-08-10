# Room Info + Media Uploads Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Ship Room Info slide-over (name, avatar, creator membership, uploaded files) and chat file uploads with compressed image previews, all backed by Matrix events and a pluggable local media store.

**Architecture:** `LakehouseMatrix.Media` + `Media.Store` (Local + Remote stub) stores blobs under `LAKEHOUSE_MEDIA_ROOT`; Matrix facade emits `m.room.name` / `m.room.avatar` / `m.room.member` leave / `m.room.message` (`m.image`|`m.file`). LiveView drawer + LiveView uploads call the facade; HTTP media upload/download under `/_matrix/media/v3`.

**Tech Stack:** Elixir umbrella, Ecto, Phoenix LiveView uploads, ImageMagick (`magick`/`convert`) for image compression, Cucumber + Wallaby BDD.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-10-room-info-media-design.md`
- Always add unit + BDD (`@api` / `@browser`) for new behavior
- Soft max 10MB/file; any MIME; always compress images
- Creator-only add/remove; any member edit name/avatar
- Do not commit secrets or `miquelon ferries receipt.pdf`
- Verify with `./build.sh` and `./test.sh` (scoped flags OK while iterating; full green at end)
- Frequent commits per task

## File map

| Path | Role |
|------|------|
| `apps/lakehouse_iam/priv/repo/migrations/*_media_objects.exs` | `media_objects` table |
| `apps/lakehouse_matrix/lib/lakehouse_matrix/schema/media_object.ex` | Ecto schema |
| `apps/lakehouse_matrix/lib/lakehouse_matrix/media.ex` | Upload/download API |
| `apps/lakehouse_matrix/lib/lakehouse_matrix/media/store.ex` | Behaviour |
| `apps/lakehouse_matrix/lib/lakehouse_matrix/media/store/local.ex` | Local FS adapter |
| `apps/lakehouse_matrix/lib/lakehouse_matrix/media/store/remote.ex` | Stub for S3/NFS |
| `apps/lakehouse_matrix/lib/lakehouse_matrix/media/image.ex` | ImageMagick compress |
| `apps/lakehouse_matrix/lib/lakehouse_matrix/matrix.ex` | set_name, set_avatar, remove_member, creator checks, list_room_files |
| `apps/lakehouse_matrix/lib/lakehouse_matrix/events/handlers/room_avatar.ex` | State handler |
| `apps/lakehouse_matrix/lib/lakehouse_matrix/events/processor.ex` | Register avatar |
| `apps/lakehouse_web/lib/.../controllers/matrix/media_controller.ex` | Upload/download |
| `apps/lakehouse_web/lib/lakehouse_web/router.ex` | Media routes |
| `apps/lakehouse_web/lib/.../live/room_live.ex` + `.html.heex` + CSS | Drawer + uploads |
| `priv/static/images/room-default.svg` | Default avatar |
| Tests: unit, `features/matrix/media.feature`, browser room info steps |
| `Dockerfile` / compose | media volume + imagemagick |
| `config/*.exs` | `media_root`, store module |

---

### Task 1: Media store + upload/download (unit)

**Files:** migration, schema, Media modules, config, Dockerfile imagemagick, unit tests

**Interfaces:**
- Produces: `Media.upload/3`, `Media.download/3`, `Media.content_uri/1`, `Store.put/get`

- [x] Write failing unit tests for Local put/get, size limit, image compress smaller preview, Remote `:not_implemented`
- [x] Implement migration + modules + ImageMagick compress + config
- [x] Run unit tests green; commit

### Task 2: Matrix events — name, avatar, remove_member, file messages

**Files:** `matrix.ex`, `room_avatar.ex`, `processor.ex`, `events.ex` (list files), unit tests

**Interfaces:**
- Consumes: Media content URIs
- Produces: `set_name/3`, `set_avatar/3`, `remove_member/3`, creator-gated `add_member`, `list_room_files/2`

- [x] Failing tests for authz + event shapes + list_room_files
- [x] Implement handlers/facade; tighten add_member to creator
- [x] Green unit tests; commit

### Task 3: HTTP media + API BDD

**Files:** `media_controller.ex`, router, `matrix_client.ex` helpers, `features/matrix/media.feature` (+ membership scenarios)

- [x] Failing `@api` scenarios (upload, image message, name/avatar, remove member)
- [x] Implement controller + client steps
- [x] `./test.sh --api` green; commit

### Task 4: LiveView Room Info + composer uploads + browser BDD

**Files:** `room_live.*`, CSS, default SVG, browser feature/steps

- [x] Failing `@browser` scenarios (drawer, rename, remove, image preview, uploaded files)
- [x] Implement UI + LiveView uploads
- [x] `./test.sh --browser` (or full) green; commit

### Task 5: Wire deploy volume + full gate

- [x] Compose volume for media root; document env
- [x] `./build.sh` && `./test.sh` green
- [x] Update `ai-project-iam-matrix` notes; commit

---

## Notes

- Image compress via `magick`/`convert` (present on host; add to Alpine image).
- Access check on download: uploader OR member of a room whose events reference the media id.
- Room message handler already requires non-empty `body` — use filename as body for files.
