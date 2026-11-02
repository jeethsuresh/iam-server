# Separate real connections verify MVCC and writer progress. Never use production.
alias LakehouseIam.Repo
alias LakehouseMatrix.{ClientRooms, ClientSync, Fixtures, Identity, ReadSnapshot, SlidingSync}
alias LakehouseMatrix.Protocol.Graph

unless System.get_env("MIX_ENV") == "test" and
         String.starts_with?(Repo.config()[:database], "lakehouse_test"),
       do: raise("sync concurrency checks require the isolated test database")

:ok = Supervisor.terminate_child(LakehouseIam.Supervisor, Repo)

Application.put_env(
  :lakehouse_iam,
  Repo,
  Repo.config() |> Keyword.put(:pool, DBConnection.ConnectionPool) |> Keyword.put(:pool_size, 3)
)

{:ok, _} = Supervisor.restart_child(LakehouseIam.Supervisor, Repo)
Application.put_env(:lakehouse_matrix, :native_event_graph, true)
Application.put_env(:lakehouse_matrix, :signing_key, Base.encode64(<<0::256>>, padding: false))
Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:concurrency")

user =
  Fixtures.user_fixture("syncparallel" <> Integer.to_string(System.unique_integer([:positive])))

{:ok, created} = ClientRooms.create(user.id, %{})
{:ok, room} = Identity.parse_room_id(created["room_id"])
owner = self()
handler = "matrix-sync-concurrency"

:telemetry.attach(
  handler,
  [:lakehouse_iam, :repo, :query],
  fn _, _, metadata, _ ->
    if Process.get(:pause_sync_snapshot) == true and
         not is_nil(Process.get({ReadSnapshot, :values})) and
         is_binary(metadata.query) and String.contains?(metadata.query, "matrix_stream") do
      Process.delete(:pause_sync_snapshot)
      send(owner, {:snapshot_open, self()})

      receive do
        :finish_snapshot -> :ok
      after
        10_000 -> raise "snapshot barrier timed out"
      end
    end
  end,
  nil
)

for mode <- [:classic, :sliding] do
  read = fn ->
    case mode do
      :classic ->
        ClientSync.snapshot(user.id, "CONCURRENCY", 0, true)

      :sliding ->
        SlidingSync.sync(user.id, "CONCURRENCY", %{
          "conn_id" => "parallel",
          "lists" => %{"rooms" => %{"ranges" => [[0, 99]], "timeline_limit" => 30}}
        })
    end
  end

  snapshot =
    Task.async(fn ->
      Process.put(:pause_sync_snapshot, true)
      read.()
    end)

  reader =
    receive do
      {:snapshot_open, pid} -> pid
    after
      10_000 -> raise "sync snapshot did not open"
    end

  try do
    writer =
      Task.async(fn ->
        Graph.send(room, Identity.user_id(user.username), "m.room.message", %{
          "body" => "concurrent message"
        })
      end)

    result = Task.yield(writer, 1500)
    send(reader, :finish_snapshot)

    unless match?({:ok, {:ok, _}}, result),
      do: raise("sync rendering blocked a concurrent sender")

    {:ok, {:ok, event}} = result
    {:ok, before} = Task.await(snapshot)
    {:ok, after_send} = read.()

    events = fn payload ->
      case mode do
        :classic -> get_in(payload, ["rooms", "join", created["room_id"], "timeline", "events"])
        :sliding -> get_in(payload, ["rooms", created["room_id"], "timeline"])
      end
    end

    if Enum.any?(events.(before), &(&1["event_id"] == event["event_id"])),
      do: raise("snapshot included an event committed after its stream position")

    unless Enum.any?(events.(after_send), &(&1["event_id"] == event["event_id"])),
      do: raise("next sync lost the concurrent event")

    IO.puts(
      "Matrix #{mode} sync concurrency: sender progresses during rendering, snapshot is consistent, next sync delivers the event"
    )
  after
    send(reader, :finish_snapshot)
  end
end

:telemetry.detach(handler)
