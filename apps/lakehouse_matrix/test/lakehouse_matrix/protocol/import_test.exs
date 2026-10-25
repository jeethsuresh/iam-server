defmodule LakehouseMatrix.Protocol.ImportTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientSync, Fixtures, Identity, Memberships, Rooms}
  alias LakehouseMatrix.Federation.{Invites, RemoteJoin}
  alias LakehouseMatrix.Protocol.{Event, Graph, Import}
  alias LakehouseMatrix.ProtocolFixtures, as: F
  @seed <<0::256>>

  setup do
    settings = [:signing_key, :signing_key_id, :federation_requester]
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
    # Auth outliers remain available to joined peers for event verification;
    # unverified/incomplete historical state is not represented as a snapshot.
    alias LakehouseMatrix.Federation.{RoomAccess, RoomProtocol}
    metadata = Graph.room(room.id)
    assert Graph.event(snapshot.create["event_id"]).outlier
    assert RoomAccess.visible_event?(metadata, "example.org", snapshot.create["event_id"])
    refute RoomAccess.visible_event?(metadata, "outsider.org", snapshot.create["event_id"])
    assert {:ok, _} = RoomProtocol.event("example.org", snapshot.create["event_id"])

    assert {:ok, _} =
             RoomProtocol.event_auth("example.org", metadata.room_id, snapshot.create["event_id"])

    assert {:error, :not_found} =
             RoomProtocol.state("example.org", metadata.room_id, snapshot.create["event_id"])

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

  test "a remote knock is a pending notification and can be cancelled through signed leave",
       ctx do
    alias LakehouseMatrix.{ClientRooms, Matrix}
    alias LakehouseMatrix.Federation.Outbox
    {_, remote} = F.append(ctx.remote, "m.room.join_rules", %{"join_rule" => "knock"}, key: "")

    {template, _} =
      F.append(remote, "m.room.member", %{"membership" => "knock"},
        sender: ctx.mxid,
        key: ctx.mxid
      )

    request = fn method, "example.org", path, body ->
      cond do
        method == :get and String.contains?(path, "/make_knock/") ->
          {:ok, %{"room_version" => "12", "event" => wire(template)}}

        method == :put and String.contains?(path, "/send_knock/") ->
          assert {:ok, verified} = Event.verify(body, "12", &F.lookup/3)
          Process.put(:knock_wire, verified)

          {:ok,
           %{
             "knock_room_state" =>
               Enum.map(remote.state, fn {_, event} ->
                 Map.take(event, ~w(type state_key sender content))
               end)
           }}

        method == :get and String.contains?(path, "/make_leave/") ->
          knock = Process.get(:knock_wire)

          chain = %{
            remote
            | head: knock,
              state: Map.put(remote.state, {"m.room.member", ctx.mxid}, knock),
              graph: Map.put(remote.graph, knock["event_id"], knock)
          }

          {leave, _} =
            F.append(chain, "m.room.member", %{"membership" => "leave"},
              sender: ctx.mxid,
              key: ctx.mxid
            )

          {:ok, %{"room_version" => "12", "event" => wire(leave)}}

        method == :put and String.contains?(path, "/send_leave/") ->
          assert {:ok, _} = Event.verify(body, "12", &F.lookup/3)
          {:ok, %{}}
      end
    end

    Application.put_env(:lakehouse_matrix, :federation_requester, request)

    assert {:ok, %{"room_id" => ref}} =
             ClientRooms.knock(ctx.user.id, remote.room, ["example.org"], %{"reason" => "Hello"})

    assert ref == remote.room
    metadata = Graph.room_by_id(ref)
    assert metadata.current_state == %{}
    assert metadata.extremities == []
    assert {:ok, sync} = ClientSync.sync(ctx.user.id, "A", %{})
    assert get_in(sync, ["rooms", "knock", ref, "knock_state", "events"])
    assert {:ok, %{}} = Matrix.leave_room(ctx.user.id, ref)
    assert :delivered = Outbox.deliver_once(request, &F.lookup/3)

    assert {:ok, after_leave} =
             ClientSync.sync(ctx.user.id, "A", %{"since" => sync["next_batch"]})

    assert get_in(after_leave, ["rooms", "leave", ref])
    refute get_in(after_leave, ["rooms", "knock", ref])
  end

  test "declining a remote invite queues a stable signed leave and emits an incremental membership change",
       ctx do
    alias LakehouseMatrix.Federation.{Outbox, RemoteMembership}
    {:ok, before} = ClientSync.sync(ctx.user.id, "A", %{})

    {invite, invited} =
      F.append(ctx.remote, "m.room.member", %{"membership" => "invite"}, key: ctx.mxid)

    {:ok, _} =
      Invites.receive(
        "example.org",
        ctx.remote.room,
        invite["event_id"],
        %{
          "room_version" => "12",
          "event" => wire(invite),
          "invite_room_state" => Enum.map(ctx.remote.state, fn {_, event} -> wire(event) end)
        },
        &F.lookup/3
      )

    {leave, _} =
      F.append(invited, "m.room.member", %{"membership" => "leave"},
        key: ctx.mxid,
        sender: ctx.mxid
      )

    metadata = Graph.room_by_id(ctx.remote.room)

    assert {:ok, %{}} =
             RemoteMembership.reject_invite(
               ctx.user.id,
               metadata.local_room_id,
               %{"reason" => "No thanks"},
               fn :get, "example.org", path, nil ->
                 assert String.contains?(path, "/make_leave/")
                 {:ok, %{"room_version" => "12", "event" => wire(leave)}}
               end
             )

    refute Invites.pending(metadata.local_room_id, ctx.mxid)
    assert Memberships.membership(metadata.local_room_id, ctx.user.id) == "leave"
    assert Graph.room(metadata.local_room_id).current_state == %{}
    assert Graph.room(metadata.local_room_id).extremities == []
    assert {:ok, sync} = ClientSync.sync(ctx.user.id, "A", %{"since" => before["next_batch"]})
    assert get_in(sync, ["rooms", "leave", ctx.remote.room])

    assert :delivered =
             Outbox.deliver_once(fn :put, "example.org", path, signed ->
               assert String.contains?(path, "/v2/send_leave/")
               assert signed["content"] == %{"membership" => "leave", "reason" => "No thanks"}
               assert {:ok, _} = Event.verify(signed, "12", &F.lookup/3)
               {:ok, %{}}
             end)

    assert :idle = Outbox.deliver_once(fn _, _, _, _ -> flunk("delivered leave retried") end)
  end

  for version <- ["11", "12"] do
    test "#{version}: invitation previews require the create PDU, signatures and the same room",
         ctx do
      version = unquote(version)
      remote = F.public_room(version)
      {invite, _} = F.append(remote, "m.room.member", %{"membership" => "invite"}, key: ctx.mxid)
      preview = Enum.map(remote.state, fn {_, event} -> wire(event) end)
      {name, _} = F.append(remote, "m.room.name", %{"name" => "Another room"}, key: "")

      foreign =
        wire(name)
        |> Map.put(
          "room_id",
          if(version == "12", do: "!" <> String.duplicate("A", 43), else: "!other:example.org")
        )
        |> Event.sign(version, F.seed(), "ed25519:test", "example.org")

      invalid_signature =
        put_in(
          wire(remote.create),
          ["signatures", "example.org", "ed25519:test"],
          Base.encode64(<<0::512>>, padding: false)
        )

      for bad <- [
            [],
            Enum.map(preview, &Map.take(&1, ~w(type sender state_key content))),
            Enum.reject(preview, &(&1["type"] == "m.room.create")),
            [invalid_signature],
            preview ++ [foreign]
          ] do
        assert {:error, :invalid_param} =
                 Invites.receive(
                   "example.org",
                   remote.room,
                   invite["event_id"],
                   %{
                     "room_version" => version,
                     "event" => wire(invite),
                     "invite_room_state" => bad
                   },
                   &F.lookup/3
                 )

        assert Graph.room_by_id(remote.room) == nil
      end

      assert {:ok, _} =
               Invites.receive(
                 "example.org",
                 remote.room,
                 invite["event_id"],
                 %{
                   "room_version" => version,
                   "event" => wire(invite),
                   "invite_room_state" => preview
                 },
                 &F.lookup/3
               )

      metadata = Graph.room_by_id(remote.room)
      assert metadata.current_state == %{}
      assert Graph.event(remote.create["event_id"]) == nil
      pending = Invites.pending(metadata.local_room_id, ctx.mxid)
      assert Enum.any?(pending.state["events"], &(&1["type"] == "m.room.create"))
      refute Enum.any?(pending.state["events"], &Map.has_key?(&1, "auth_events"))
    end
  end

  test "an incoming invite is an outlier until the subsequent verified remote join", ctx do
    {:ok, before} = ClientSync.sync(ctx.user.id, "A", %{})

    {invite, invited} =
      F.append(ctx.remote, "m.room.member", %{"membership" => "invite"}, key: ctx.mxid)

    stripped =
      Enum.map(ctx.remote.state, fn {_, event} ->
        wire(event)
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

    assert {:ok, incremental} =
             ClientSync.sync(ctx.user.id, "A", %{"since" => before["next_batch"]})

    assert get_in(incremental, ["rooms", "invite", ctx.remote.room, "invite_state", "events"])
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
