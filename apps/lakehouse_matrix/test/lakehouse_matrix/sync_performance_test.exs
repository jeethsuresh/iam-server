defmodule LakehouseMatrix.SyncPerformanceTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientHistory, ClientRooms, ClientSync, Fixtures, Identity, ReadSnapshot}
  alias LakehouseMatrix.Protocol.Graph

  test "snapshot cache is scoped, bounded and cleared after failures" do
    Process.put(:loads, 0)

    load = fn ->
      value = Process.get(:loads) + 1
      Process.put(:loads, value)
      value
    end

    assert ReadSnapshot.run(fn ->
             assert ReadSnapshot.fetch(:same, load) == 1
             ReadSnapshot.fetch(:same, load)
           end) == 1

    assert ReadSnapshot.run(fn -> ReadSnapshot.fetch(:same, load) end) == 2
    assert_raise RuntimeError, fn -> ReadSnapshot.run(fn -> raise "fixture" end) end
    assert ReadSnapshot.fetch(:same, load) == 3

    ReadSnapshot.run(fn ->
      for n <- 1..600, do: ReadSnapshot.fetch(n, fn -> n end)
      # Once capacity is reached, values are loaded rather than retained.
      assert ReadSnapshot.fetch(:beyond_capacity, load) == 4
      assert ReadSnapshot.fetch(:beyond_capacity, load) == 5
    end)
  end

  setup do
    keys = [:native_event_graph, :signing_key, :signing_key_id]
    old = Map.new(keys, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :native_event_graph, true)

    Application.put_env(
      :lakehouse_matrix,
      :signing_key,
      Base.encode64(<<0::256>>, padding: false)
    )

    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:performance")

    on_exit(fn ->
      for {key, value} <- old do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    :ok
  end

  test "ten-room initial sync does not repeat immutable PDU reads hundreds of times" do
    alice = Fixtures.user_fixture("profilealice")

    for n <- 1..10 do
      assert {:ok, _} = ClientRooms.create(alice.id, %{"name" => "Room #{n}"})
    end

    owner = self()
    handler = "sync-query-budget-#{System.unique_integer()}"
    Process.put(:queries, 0)

    :telemetry.attach(
      handler,
      [:lakehouse_iam, :repo, :query],
      fn _, _, _, _ ->
        if self() == owner, do: Process.put(:queries, Process.get(:queries) + 1)
      end,
      nil
    )

    try do
      assert {:ok, _} = ClientSync.sync(alice.id, "PROFILE", %{})
      assert Process.get(:queries) < 1000
    after
      :telemetry.detach(handler)
    end
  end

  test "refreshing the latest history page does not render the room's entire backlog" do
    alice = Fixtures.user_fixture("historybudget")
    assert {:ok, created} = ClientRooms.create(alice.id, %{})
    {:ok, room} = Identity.parse_room_id(created["room_id"])
    sender = Identity.user_id(alice.username)

    for n <- 1..25 do
      assert {:ok, _} = Graph.send(room, sender, "m.room.message", %{"body" => "message #{n}"})
    end

    page = fn ->
      assert {:ok, result} = ClientHistory.page(alice.id, "HISTORY", room, %{"limit" => 10})
      assert length(result["chunk"]) == 10
      assert result["end"]
    end

    small = count_queries(page)

    for n <- 26..100 do
      assert {:ok, _} = Graph.send(room, sender, "m.room.message", %{"body" => "message #{n}"})
    end

    large = count_queries(page)
    IO.puts("HISTORY_REFRESH_QUERIES small=#{small} large=#{large}")
    assert large <= small + 20
  end

  test "applied redactions in another private room cannot enter history or displace its latest message" do
    alice = Fixtures.user_fixture("historyreader")
    bob = Fixtures.user_fixture("privateredactor")
    assert {:ok, created} = ClientRooms.create(alice.id, %{})
    {:ok, room} = Identity.parse_room_id(created["room_id"])

    assert {:ok, message} =
             Graph.send(room, Identity.user_id(alice.username), "m.room.message", %{
               "msgtype" => "m.text",
               "body" => "Latest message 👋🏽🙂"
             })

    assert {:ok, private} = ClientRooms.create(bob.id, %{})
    {:ok, other_room} = Identity.parse_room_id(private["room_id"])

    for n <- 1..8 do
      assert {:ok, other} =
               Graph.send(other_room, Identity.user_id(bob.username), "m.room.message", %{
                 "body" => "Private message #{n}"
               })

      assert {:ok, removed} =
               ClientRooms.redact(
                 bob.id,
                 "REDACTOR",
                 private["room_id"],
                 other["event_id"],
                 "remove-#{n}",
                 %{}
               )

      assert Graph.event(removed["event_id"]).redaction_applied
    end

    records = Repo.all(ClientHistory.query(room, alice.id))
    assert Enum.all?(records, &(&1.local_room_id == room))

    assert {:ok, page} = ClientHistory.page(alice.id, "HISTORY", room, %{"limit" => 1})
    assert Enum.map(page["chunk"], & &1["event_id"]) == [message["event_id"]]
    assert hd(page["chunk"])["content"]["body"] == "Latest message 👋🏽🙂"
  end

  test "an applied redaction must still satisfy every history acceptance flag" do
    import Ecto.Query
    alias LakehouseMatrix.Schema.Pdu
    alice = Fixtures.user_fixture("redactionflags")
    assert {:ok, created} = ClientRooms.create(alice.id, %{})
    {:ok, room} = Identity.parse_room_id(created["room_id"])

    assert {:ok, message} =
             Graph.send(room, Identity.user_id(alice.username), "m.room.message", %{
               "body" => "remove"
             })

    assert {:ok, removed} =
             ClientRooms.redact(
               alice.id,
               "HISTORY",
               created["room_id"],
               message["event_id"],
               "remove",
               %{}
             )

    id = removed["event_id"]
    assert Graph.event(id).redaction_applied
    assert Enum.any?(Repo.all(ClientHistory.query(room, alice.id)), &(&1.event_id == id))

    for flag <- [:outlier, :auth_rejected, :state_rejected, :soft_failed] do
      Repo.update_all(from(p in Pdu, where: p.event_id == ^id), set: [{flag, true}])
      refute Enum.any?(Repo.all(ClientHistory.query(room, alice.id)), &(&1.event_id == id))
      Repo.update_all(from(p in Pdu, where: p.event_id == ^id), set: [{flag, false}])
    end
  end

  defp count_queries(callback) do
    owner = self()
    handler = "history-query-budget-#{System.unique_integer()}"
    Process.put(:history_queries, 0)

    :telemetry.attach(
      handler,
      [:lakehouse_iam, :repo, :query],
      fn _, _, _, _ ->
        if self() == owner, do: Process.put(:history_queries, Process.get(:history_queries) + 1)
      end,
      nil
    )

    try do
      callback.()
      Process.get(:history_queries)
    after
      :telemetry.detach(handler)
    end
  end
end
