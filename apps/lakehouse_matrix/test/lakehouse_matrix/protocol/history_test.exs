defmodule LakehouseMatrix.ClientHistoryTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{
    ClientContext,
    ClientHistory,
    ClientRooms,
    ClientSync,
    Fixtures,
    Identity,
    Rooms
  }

  alias LakehouseMatrix.Protocol.{Graph, Import}
  alias LakehouseMatrix.ProtocolFixtures, as: F

  setup do
    settings = [:signing_key, :signing_key_id]
    old = Map.new(settings, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :signing_key, Base.encode64(F.seed(), padding: false))
    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")

    on_exit(fn ->
      for {key, value} <- old do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    user = Fixtures.user_fixture("joiner")

    remote =
      Enum.reduce(1..5, F.public_room("12"), fn n, chain ->
        {_, next} = F.append(chain, "m.room.message", %{"body" => "old #{n}"})
        next
      end)

    mxid = Identity.user_id(user.username)

    {join, _} =
      F.append(remote, "m.room.member", %{"membership" => "join"}, sender: mxid, key: mxid)

    {:ok, snapshot} =
      Import.snapshot(
        remote.room,
        "12",
        wire(join),
        Enum.map(remote.state, fn {_, event} -> wire(event) end),
        Enum.map(remote.graph, fn {_, event} -> wire(event) end),
        &F.lookup/3
      )

    {:ok, room} = Rooms.create_room_record(%{name: "Remote history"})
    {:ok, _} = Graph.install_snapshot(room.id, remote.room, "12", snapshot, :join)
    %{user: user, room: room, remote: remote, join: join}
  end

  defp wire(event), do: Map.drop(event, ["event_id", :auth_rejected])

  defp requester(remote) do
    fn :get, "example.org", path, nil ->
      query = URI.decode_query(URI.parse(path).query || "")

      if String.contains?(path, "/backfill/") do
        root = remote.graph[query["v"]]
        depth = if root, do: root["depth"], else: 1_000_000

        {:ok,
         %{
           "pdus" =>
             remote.graph
             |> Map.values()
             |> Enum.filter(&(&1["depth"] < depth))
             |> Enum.sort_by(&(-&1["depth"]))
             |> Enum.take(20)
             |> Enum.map(&wire/1)
         }}
      else
        target = remote.graph[query["event_id"]]

        state =
          remote.graph
          |> Map.values()
          |> Enum.filter(&(is_binary(&1["state_key"]) and &1["depth"] < target["depth"]))
          |> Enum.sort_by(& &1["depth"])
          |> Map.new(&{{&1["type"], &1["state_key"]}, &1})

        {:ok,
         %{
           "pdus" => Enum.map(state, fn {_, event} -> wire(event) end),
           "auth_chain" => Enum.map(remote.graph, fn {_, event} -> wire(event) end)
         }}
      end
    end
  end

  test "scrollback imports verified pre-join history, preserves current state and paginates without duplicates",
       ctx do
    {:ok, sync} = ClientSync.sync(ctx.user.id, "A", %{})
    token = get_in(sync, ["rooms", "join", ctx.remote.room, "timeline", "prev_batch"])
    before = Graph.room(ctx.room.id)
    filter = Jason.encode!(%{"types" => ["m.room.message"]})
    params = %{"from" => token, "limit" => 2, "filter" => filter}

    assert {:ok, first} =
             ClientHistory.page(
               ctx.user.id,
               "A",
               ctx.room.id,
               params,
               requester(ctx.remote),
               &F.lookup/3
             )

    assert Enum.map(first["chunk"], & &1["content"]["body"]) == ["old 5", "old 4"]

    assert {:ok, second} =
             ClientHistory.page(
               ctx.user.id,
               "A",
               ctx.room.id,
               %{params | "from" => first["end"]},
               requester(ctx.remote),
               &F.lookup/3
             )

    assert Enum.map(second["chunk"], & &1["content"]["body"]) == ["old 3", "old 2"]

    assert {:ok, third} =
             ClientHistory.page(
               ctx.user.id,
               "A",
               ctx.room.id,
               %{params | "from" => second["end"]},
               requester(ctx.remote),
               &F.lookup/3
             )

    assert Enum.map(third["chunk"], & &1["content"]["body"]) == ["old 1"]
    refute Map.has_key?(third, "end")
    assert Graph.room(ctx.room.id).current_state == before.current_state
    assert Graph.room(ctx.room.id).extremities == before.extremities

    assert {:ok, event} =
             ClientRooms.event(ctx.user.id, ctx.remote.room, hd(first["chunk"])["event_id"])

    assert event["content"]["body"] == "old 5"

    assert {:error, :invalid_cursor} =
             ClientHistory.page(
               ctx.user.id,
               "other device",
               ctx.room.id,
               params,
               requester(ctx.remote),
               &F.lookup/3
             )
  end

  test "member state accepts sync topology cursors and context uses the requested event's position",
       ctx do
    {:ok, _} =
      ClientHistory.page(
        ctx.user.id,
        "A",
        ctx.room.id,
        %{"limit" => 100},
        requester(ctx.remote),
        &F.lookup/3
      )

    token = ClientHistory.before(ctx.user.id, "A", ctx.room.id, ctx.join["event_id"])

    assert {:ok, %{"chunk" => members}} =
             ClientContext.members(ctx.user.id, "A", ctx.remote.room, %{"at" => token})

    assert Enum.any?(members, &(&1["state_key"] == F.alice()))
    refute Enum.any?(members, &(&1["state_key"] == Identity.user_id(ctx.user.username)))
    target = Enum.find(Map.values(ctx.remote.graph), &(&1["content"]["body"] == "old 3"))

    assert {:ok, context} =
             ClientContext.context(ctx.user.id, "A", ctx.remote.room, target["event_id"], %{
               "limit" => 4
             })

    assert Enum.map(context["events_before"], & &1["content"]["body"]) == ["old 2", "old 1"]
    assert Enum.map(context["events_after"], & &1["content"]["body"]) == ["old 4", "old 5"]
    assert context["event"]["event_id"] == target["event_id"]
    assert Enum.any?(context["state"], &(&1["type"] == "m.room.create"))

    {:ok, _} =
      Graph.send(
        ctx.room.id,
        Identity.user_id(ctx.user.username),
        "m.room.member",
        %{"membership" => "invite"},
        "@invited:remote.org"
      )

    assert {:ok, %{"chunk" => combined}} =
             ClientContext.members(ctx.user.id, "A", ctx.remote.room, %{
               "membership" => "join",
               "not_membership" => "ban"
             })

    assert Enum.any?(combined, &(&1["content"]["membership"] == "invite"))

    assert {:ok, %{"chunk" => joined}} =
             ClientContext.members(ctx.user.id, "A", ctx.remote.room, %{"membership" => "join"})

    refute Enum.any?(joined, &(&1["content"]["membership"] == "invite"))
  end

  test "an unavailable peer does not falsely signal that a history gap is the beginning of the room",
       ctx do
    token = ClientHistory.before(ctx.user.id, "A", ctx.room.id, ctx.join["event_id"])

    assert {:error, :unavailable} =
             ClientHistory.page(
               ctx.user.id,
               "A",
               ctx.room.id,
               %{"from" => token},
               fn _, _, _, _ -> {:error, :unavailable} end,
               &F.lookup/3
             )
  end
end
