# Lakehouse Test Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an Elixir-first IAM + Matrix test gate (ExUnit + Cucumber API BDD + Wallaby browser BDD) with root `build.sh`/`test.sh`.

**Architecture:** Domain tests stay in each app; Gherkin features and Wallaby live under `apps/lakehouse_web/test/features`. API steps use ConnTest helpers; browser steps use Wallaby with SQL Sandbox metadata.

**Tech Stack:** ExUnit, cucumber ~> 1.0, wallaby, Chrome/Chromium, Ecto SQL Sandbox, Phoenix.ConnTest

## Global Constraints

- No separate `lakehouse_test` app
- ConnTest for API (not Req) in v1
- Chromium via system or `.tools/chrome` download
- Root scripts accept `--project-name` and `--host-port`
- Do not commit secrets or `.tools/`

---

### Task 1: Root scripts + gitignore tooling

**Files:**
- Create: `scripts/lib/common.sh`, `build.sh`, `test.sh`, `deploy.sh`, `teardown.sh`
- Modify: `.gitignore` (add `.tools/`)

- [ ] Add compose helpers and executable scripts
- [ ] `build.sh` runs `mix deps.get` (unless `--skip-install`) + `mix compile`
- [ ] `test.sh` prepares test DB, optional Chrome, runs `mix test` with tag filters
- [ ] Commit

### Task 2: Deps + test config for cucumber/wallaby

**Files:**
- Modify: `apps/lakehouse_web/mix.exs`, `config/test.exs`, `apps/lakehouse_web/test/test_helper.exs`

- [ ] Add `{:cucumber, "~> 1.0", only: :test}`, `{:wallaby, "~> 0.30", runtime: false, only: :test}`, `{:phoenix_ecto, ...}` already present
- [ ] Configure `:cucumber` paths; Wallaby `otp_app`, `base_url`, Chrome headless
- [ ] Call `Cucumber.compile_features!()` in web `test_helper.exs`
- [ ] Exclude non-`*_test.exs` warnings via `test_pattern` / `elixirc_paths` as needed
- [ ] Commit

### Task 3: Support modules (API clients, hooks)

**Files:**
- Create: `apps/lakehouse_web/test/support/api/iam_client.ex`, `matrix_client.ex`
- Create: `apps/lakehouse_web/test/features/support/hooks.exs`
- Modify: `apps/lakehouse_web/test/support/conn_case.ex`, `matrix_fixtures.ex`

- [ ] IAM client: register/login/approve/password via ConnTest
- [ ] Matrix client: login/create/join/leave/send/messages/sync
- [ ] Hooks: sandbox checkout/shared; `@browser` starts Wallaby + Endpoint server
- [ ] Commit

### Task 4: Domain ExUnit expansions

**Files:**
- Create: `apps/lakehouse_iam/test/lakehouse_iam/authorization_test.exs`, `accounts_test.exs`
- Create: `apps/lakehouse_matrix/test/lakehouse_matrix/sync_test.exs`
- Extend: existing processor/matrix tests for permission negatives

- [ ] Authorization can?/cannot
- [ ] Accounts register pending → approve → authenticate
- [ ] Sync joined-only
- [ ] Commit

### Task 5: Gherkin features + step defs

**Files:**
- Create feature files under `apps/lakehouse_web/test/features/{iam,matrix,browser}/`
- Create step defs under `apps/lakehouse_web/test/features/step_definitions/`

- [ ] Implement inventory from the design spec
- [ ] Run API features green
- [ ] Commit

### Task 6: Browser green + full gate

- [ ] Ensure Chrome available (system or download)
- [ ] Run browser features green
- [ ] `./build.sh && ./test.sh` green
- [ ] Update `ai-project-iam-matrix` note
- [ ] Commit

## Execution

User requested immediate execution of the whole plan in-session (inline).
