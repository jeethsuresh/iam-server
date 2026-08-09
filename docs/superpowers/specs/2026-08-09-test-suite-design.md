# Lakehouse IAM + Matrix Test Suite Design

Date: 2026-08-09

## Goal

Provide a single Elixir-first verification gate that exercises IAM and Matrix through:

1. Domain ExUnit tests (per umbrella app)
2. API BDD (Gherkin + ConnTest)
3. Browser BDD (Gherkin + Wallaby/Chromium)

## Decisions

| Choice | Decision |
|--------|----------|
| Host language | Elixir-first |
| BDD | `cucumber` (Hex) with `.feature` files |
| Browser | Wallaby + Chromium/ChromeDriver |
| Packaging | Domain ExUnit in each app; BDD + browser in `lakehouse_web/test` (no `lakehouse_test` app) |
| API style | Phoenix.ConnTest (in-process); no Req HTTP client in v1 |
| Coverage | Broad regression (happy paths + negatives + multi-user concurrency) |
| Gate scripts | Root `build.sh` / `test.sh` / `deploy.sh` / `teardown.sh` with `--project-name` and `--host-port` |

## Architecture

```
apps/lakehouse_iam/test     → Authorization, Accounts, Token, CallbackURL
apps/lakehouse_matrix/test  → Processor, Matrix facade, Sync, Memberships
apps/lakehouse_web/test
  lakehouse_web/**          → existing ConnCase controller tests
  features/**/*.feature     → Gherkin (iam / matrix / browser)
  features/step_definitions → Cucumber steps (.exs)
  features/support          → hooks (sandbox, Wallaby session)
  support/api               → thin ConnTest clients (compiled)
  support/*_case.ex         → ConnCase / Feature helpers
```

### Tags

| Tag | Meaning |
|-----|---------|
| `@api` | ConnTest IAM/Matrix HTTP surface |
| `@browser` | Wallaby UI flows (`server: true`, shared sandbox) |
| `@negative` | Auth failures, missing permissions, unauthenticated Matrix |
| `@concurrency` | Multi-principal send/sync |

`./test.sh` runs all layers. Flags: `--unit`, `--api`, `--browser`, `--exclude-browser`.

### Sandbox

- API/BDD: checkout + shared mode for non-async scenarios.
- Browser: Phoenix.Ecto.SQL.Sandbox metadata on Wallaby session; Endpoint `server: true` when browser tests run.
- Default `config/test.exs` keeps `server: false`; browser hook / test_helper enables the server when Chromium is available or `--browser` is selected.

### Chrome

- Prefer system Chromium + chromedriver when present.
- Else `./test.sh` may download Chrome for Testing into `.tools/chrome/` (gitignored).
- If neither is available and browser is not excluded, fail with install instructions (do not silently skip in full gate).

## Feature inventory (v1)

### IAM `@api`

- Register pending user; admin approves; login returns token
- Invalid login → 401
- Change password (Bearer) → old password fails, new works
- Unauthenticated admin approve → 401

### Matrix `@api`

- Login, createRoom, join, send, messages, sync, leave
- Unauthenticated sync/send → 401
- User without `matrix.room.send` cannot send
- Two users concurrent send; both appear in messages/sync

### Browser `@browser`

- Sign in → land on `/rooms`
- Create room → send message → message visible
- Add member by username (second user prepared via API/fixtures)
- Settings: change password
- Admin approves pending user from settings
- Invalid sign-in shows error

### Domain ExUnit

- `LakehouseIam.Authorization` grant/deny + global ARN fallback
- `LakehouseIam.Accounts` register/approve/login
- `LakehouseMatrix.Events.Processor` (existing + negatives)
- `LakehouseMatrix.Matrix` create/join/send permission paths
- `LakehouseMatrix.Sync` joined-rooms-only

## Non-goals (v1)

- Separate Node/Playwright harness
- Real HTTP Req client for all API steps
- Matrix federation / WebRTC coverage
- Full CS API surface beyond existing routes

## Success criteria

- `./build.sh` compiles the umbrella
- `./test.sh` (with Postgres available) is green for unit + API BDD + browser BDD
- Tags allow faster slices during development
