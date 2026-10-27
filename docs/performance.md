# Gravitas performance measurements

The October 27, 2026 audit found repeated reads of the same Matrix PDUs and room state during sync, expensive snapshot reconstruction during idle long polls, and home/call requests computing full room detail they do not use. The production app and database were each capped at 100m CPU; Postgres had been throttled in about 20% of its cumulative scheduling periods. These effects amplified River's serial account-refresh requests.

## Changes and boundaries

`ReadSnapshot` memoizes at most 512 reads in the calling process for one stream-locked sync build. It is discarded on success or failure. Keys for authorization, account data and erased views include the principal; there is no cross-request or global permission cache. Writers and reads outside a sync build use the repository directly. The existing stream lock and transaction ordering remain intact.

`SyncWait` checks the committed stream position without locking it instead of reconstructing a full response every 200 ms. It also checks account moderation on each idle interval: administrative locks do not advance the Matrix stream. Both classic and sliding sync rebuild on a stream change, moderation change or deadline. The existing test for locking an account during a pending poll must continue to pass.

Home and call lists use authorized room summaries. They retain room visibility and membership checks while avoiding unread history, full rosters, participant-set projection and an unused recent-event overview.

The Gravitas Kubernetes overlay allows Phoenix and Postgres to burst to one CPU, with the same 100m reservations and 256Mi memory limits. This changes their QoS to Burstable and does not provision nodes. Monitor node CPU contention after rollout. See `kubernetes.md` for deployment details.

## Measurements

One native-graph fixture with ten rooms and one message per room produced these SQL counts on the pinned Elixir/OTP toolchain and a disposable Postgres 16 database:

| Scenario | Before | After |
| --- | ---: | ---: |
| Classic initial sync | 1638 | 616 |
| Classic idle request, 1000 ms timeout | 4155 | 1283 |
| Sliding initial sync | 1108 | 579 |
| Sliding idle request, 1000 ms timeout | 1506 | 592 |
| Delegated overview | 393 | 393 |
| Home | 418 | 87 |
| Calls | 323 | 63 |

The unchanged overview count is deliberate: its complete detail is still used by clients, while other endpoints no longer recompute it. Idle request wall times include the requested one-second wait. Query counts and BEAM reductions are more useful than elapsed time for comparing idle work. In the paired CPU profiles, the initial classic-sync caller's recorded function time fell from about 441 ms to 197 ms; this excludes database-process CPU and network wait.

## Repeat the profile

Use a disposable test database, the pinned toolchain in `Dockerfile.tests`, and the test environment:

```sh
MIX_ENV=test mix ecto.create
MIX_ENV=test mix ecto.migrate
MIX_ENV=test PROFILE_ROOMS=10 PROFILE_OUTPUT=/tmp/river-profile.jsonl \
  mix run scripts/profile-river.exs
MIX_ENV=test PROFILE_CPU=1 PROFILE_CPU_OUTPUT=/tmp/river-eprof.txt \
  mix run scripts/profile-river.exs
```

The fixture is wrapped in the SQL sandbox and rolled back. The script refuses non-test Mix environments. Install the matching Erlang/OTP tools application to use `eprof`; minimal runtime images may omit it. `PROFILE_CPU_PATH` can point to a separately installed matching tools `ebin` directory. The JSON contains elapsed microseconds, query count, SQL/queue/decode time, process reductions and frequently repeated parameterized SQL shapes; it never records parameter values or message bodies. CPU tracing runs separately from those measurements.

Run `mix test --exclude browser` for the complete unit/API gate, and `WALLABY_SKIP=0 mix test --only browser apps/lakehouse_web/test` for browser scenarios. Use the image's Chromium and chromedriver with 256Mi shared memory. Do not mount the app tree read-only for upload scenarios.

## Runtime instrumentation

`LakehouseWeb.Performance` emits `[:lakehouse, :request, :stop]` measurements: `duration`, `queries`, `query_time`, `queue_time` and `decode_time`. Time values use native Erlang units. Metadata contains only HTTP method, route template and response status. Attach a telemetry reporter to aggregate route/status distributions and counts.

Responses expose `Server-Timing` for app duration, SQL time, SQL pool queue time and query count. Query text and parameters are not included in these headers. Long-poll duration includes deliberate waiting; separate those routes when calculating interactive latency alerts. Ecto's definitions of query and queue time are documented in [Ecto.Repo](https://ecto.hexdocs.pm/Ecto.Repo.html). Stream-lock behavior follows [PostgreSQL row-lock semantics](https://www.postgresql.org/docs/17/explicit-locking.html).
