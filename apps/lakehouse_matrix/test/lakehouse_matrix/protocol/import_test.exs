defmodule LakehouseMatrix.Protocol.ImportTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientSync, Fixtures, Identity, Memberships, Rooms}
  alias LakehouseMatrix.Federation.{Invites, RemoteJoin}
  alias LakehouseMatrix.Protocol.{Event, Graph, Import}
  alias LakehouseMatrix.ProtocolFixtures, as: F
  @seed <<0::256>>

  setup do
    settings = [:signing_key, :signing_key_id]
    old = Map.new(settings, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :signing_key, Base.encode64(@seed, padding: false))
    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")

    on_exit(fn ->
      for {k, v} <- old do
        if is_nil(v),
          do: Application.delete_env(:lakehouse_matrix, k),
          else: Application.put_env(:lakehouse_matrix, k, v)
      end
    end)

    user = Fixtures.user_fixture("joiner")
    %{user: user, mxid: Identity.user_id(user.username), remote: F.public_room("12")}
  end

  defp wire(event), do: Map.drop(event, ["event_id", :auth_rejected])

  test "a complete signed snapshot seeds state before its visible join and cannot be replayed over later state",
       ctx do
    {join, _} =
      F.append(ctx.remote, "m.room.member", %{"membership" => "join"},
        sender: ctx.mxid,
        key: ctx.mxid
      )

    state = Enum.map(ctx.remote.state, fn {_, event} -> wire(event) end)
    auth = Enum.map(ctx.remote.graph, fn {_, event} -> wire(event) end)

    assert {:ok, snapshot} =
             Import.snapshot(ctx.remote.room, "12", wire(join), state, auth, &F.lookup/3)

    {:ok, room} = Rooms.create_room_record(%{name: "Remote"})
    assert {:ok, _} = Graph.install_snapshot(room.id, ctx.remote.room, "12", snapshot, :join)
    assert Memberships.joined?(room.id, ctx.user.id)
    assert {:ok, response} = ClientSync.sync(ctx.user.id, "A", %{})
    payload = get_in(response, ["rooms", "join", ctx.remote.room])
    assert Enum.any?(payload["state"]["events"], &(&1["type"] == "m.room.create"))
    assert Enum.map(payload["timeline"]["events"], & &1["event_id"]) == [join["event_id"]]
    assert {:ok, later} = Graph.send(room.id, ctx.mxid, "m.room.message", %{"body" => "later"})
    assert {:ok, _} = Graph.install_snapshot(room.id, ctx.remote.room, "12", snapshot, :join)
    assert Graph.room(room.id).extremities == [later["event_id"]]
  end

  test "a resident cannot inject a self-signed power escalation into the join snapshot", ctx do
    {_, remote} =
      F.append(ctx.remote, "m.room.member", %{"membership" => "join"},
        sender: F.bob(),
        key: F.bob()
      )

    {_, remote} =
      F.append(remote, "m.room.power_levels", %{"users" => %{F.bob() => 1000}},
        sender: F.bob(),
        key: ""
      )

    {join, _} =
      F.append(remote, "m.room.member", %{"membership" => "join"},
        sender: ctx.mxid,
        key: ctx.mxid
      )

    state = Enum.map(remote.state, fn {_, event} -> wire(event) end)
    auth = Enum.map(remote.graph, fn {_, event} -> wire(event) end)
    assert {:error, _} = Import.snapshot(remote.room, "12", wire(join), state, auth, &F.lookup/3)
  end

  test "an incoming invite is an outlier until the subsequent verified remote join", ctx do
    {invite, invited} =
      F.append(ctx.remote, "m.room.member", %{"membership" => "invite"}, key: ctx.mxid)

    stripped =
      Enum.map(ctx.remote.state, fn {_, event} ->
        Map.take(event, ~w(type state_key sender content))
      end)

    assert {:ok, _} =
             Invites.receive(
               "example.org",
               ctx.remote.room,
               invite["event_id"],
               %{
                 "room_version" => "12",
                 "event" => wire(invite),
                 "invite_room_state" => stripped
               },
               &F.lookup/3
             )

    metadata = Graph.room_by_id(ctx.remote.room)
    assert Memberships.invited?(metadata.local_room_id, ctx.user.id)
    assert Graph.event(invite["event_id"]).outlier
    assert {:ok, sync} = ClientSync.sync(ctx.user.id, "A", %{})
    assert get_in(sync, ["rooms", "invite", ctx.remote.room, "invite_state", "events"])

    request = fn
      :get, "example.org", _, nil ->
        template = %{
          "room_id" => invited.room,
          "type" => "m.room.member",
          "sender" => ctx.mxid,
          "state_key" => ctx.mxid,
          "content" => %{"membership" => "join"},
          "prev_events" => [invite["event_id"]],
          "auth_events" =>
            LakehouseMatrix.Protocol.Authorization.select_auth(
              %{
                "type" => "m.room.member",
                "sender" => ctx.mxid,
                "state_key" => ctx.mxid,
                "content" => %{"membership" => "join"}
              },
              invited.state,
              "12"
            ),
          "depth" => invite["depth"] + 1
        }

        {:ok, %{"room_version" => "12", "event" => template}}

      :put, "example.org", _, event ->
        {:ok,
         %{
           "event" => Event.add_signature(event, "12", @seed, "ed25519:test", "example.org"),
           "state" => Enum.map(invited.state, fn {_, e} -> wire(e) end),
           "auth_chain" => Enum.map(invited.graph, fn {_, e} -> wire(e) end)
         }}
    end

    assert {:ok, %{"room_id" => ref}} =
             RemoteJoin.join(ctx.user.id, ctx.remote.room, [], %{}, request, &F.lookup/3)

    assert ref == ctx.remote.room
    assert Memberships.joined?(metadata.local_room_id, ctx.user.id)
    refute Invites.pending(metadata.local_room_id, ctx.mxid)
  end
end
