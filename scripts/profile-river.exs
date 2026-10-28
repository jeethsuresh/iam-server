# Run only against a disposable test database: MIX_ENV=test mix run scripts/profile-river.exs
# Sandbox rolls back all fixture data. Output contains timings and SQL shapes, never values.
unless Mix.env() == :test, do: raise("This profiler requires MIX_ENV=test")
alias LakehouseIam.Repo
alias LakehouseMatrix.{ClientRooms, ClientSync, Fixtures, SlidingSync}
:ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
Application.put_env(:lakehouse_matrix, :native_event_graph, true)
Application.put_env(:lakehouse_matrix, :signing_key, Base.encode64(<<0::256>>, padding: false))
Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:profile")
alice = Fixtures.user_fixture("performancefixture")
rooms = String.to_integer(System.get_env("PROFILE_ROOMS", "10"))

for n <- 1..rooms do
  {:ok, %{"room_id" => ref}} = ClientRooms.create(alice.id, %{"name" => "Fixture #{n}"})

  {:ok, _} =
    ClientRooms.send(alice.id, "PROFILE", ref, "m.room.message", "fixture", %{"body" => "fixture"})
end

handler = "river-profile-#{System.unique_integer()}"

:telemetry.attach(
  handler,
  [:lakehouse_iam, :repo, :query],
  fn _, m, meta, owner ->
    if self() == owner do
      queries = Process.get(:profile_queries, [])
      Process.put(:profile_queries, [{meta.query, m} | queries])
    end
  end,
  self()
)

measure = fn name, operation ->
  Process.put(:profile_queries, [])
  {:reductions, before_reductions} = Process.info(self(), :reductions)
  {elapsed, result} = :timer.tc(operation)
  {:ok, _} = result
  {:reductions, after_reductions} = Process.info(self(), :reductions)
  queries = Process.get(:profile_queries)

  sums =
    for key <- [:query_time, :queue_time, :decode_time], into: %{} do
      {key,
       Enum.reduce(queries, 0, fn {_, m}, sum -> sum + (m[key] || 0) end)
       |> System.convert_time_unit(:native, :microsecond)}
    end

  top =
    queries
    |> Enum.frequencies_by(fn {sql, _} -> sql end)
    |> Enum.sort_by(fn {_, count} -> -count end)
    |> Enum.take(8)

  report = %{
    scenario: name,
    rooms: rooms,
    elapsed_us: elapsed,
    queries: length(queries),
    sql_us: sums,
    reductions: after_reductions - before_reductions,
    top_queries: Enum.map(top, fn {sql, count} -> %{sql: sql, count: count} end)
  }

  if output = System.get_env("PROFILE_OUTPUT"),
    do: File.write!(output, Jason.encode!(report) <> "\n", [:append])

  IO.puts(Jason.encode!(Map.delete(report, :top_queries)))
  result
end

{:ok, initial} = measure.("classic_initial", fn -> ClientSync.sync(alice.id, "PROFILE", %{}) end)

measure.("classic_idle_1000ms", fn ->
  ClientSync.sync(alice.id, "PROFILE", %{"since" => initial["next_batch"], "timeout" => 1000})
end)

params = %{
  "lists" => %{
    "all" => %{
      "ranges" => [[0, 99]],
      "timeline_limit" => 30,
      "required_state" => [["m.room.name", ""]]
    }
  }
}

{:ok, initial} =
  measure.("sliding_initial", fn -> SlidingSync.sync(alice.id, "PROFILE", params) end)

measure.("sliding_idle_1000ms", fn ->
  SlidingSync.sync(
    alice.id,
    "PROFILE",
    Map.merge(params, %{"pos" => initial["pos"], "timeout" => 1000})
  )
end)

grant = %LakehouseIam.Schema.AppGrant{
  id: Ecto.UUID.generate(),
  principal_id: alice.id,
  app_origin: "https://profile.example",
  room_mode: :all,
  scopes: ["chats.list", "chats.read", "calls.read"]
}

measure.("delegated_overview", fn -> LakehouseMatrix.DelegatedGroups.overview(grant) end)
measure.("delegated_home", fn -> LakehouseMatrix.RiverWorkspace.home(grant) end)
measure.("delegated_calls", fn -> LakehouseMatrix.RiverRtc.list(grant) end)
:telemetry.detach(handler)

if System.get_env("PROFILE_CPU") == "1" do
  if path = System.get_env("PROFILE_CPU_PATH"), do: Code.prepend_path(path)
  unless Code.ensure_loaded?(:eprof),
    do: raise("PROFILE_CPU requires the Erlang/OTP tools application (eprof)")

  :eprof.start()
  :eprof.start_profiling([self()])
  {:ok, _} = ClientSync.sync(alice.id, "PROFILE", %{})
  :eprof.stop_profiling()
  :eprof.log(System.get_env("PROFILE_CPU_OUTPUT", "/tmp/river-eprof.txt") |> String.to_charlist())
  :eprof.analyze(:total, sort: :time)
  :eprof.stop()
end

Ecto.Adapters.SQL.Sandbox.checkin(Repo)
