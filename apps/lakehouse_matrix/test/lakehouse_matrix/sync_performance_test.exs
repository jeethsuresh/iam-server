defmodule LakehouseMatrix.SyncPerformanceTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientRooms, ClientSync, Fixtures, ReadSnapshot}

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
end
