defmodule LakehouseMatrix.Protocol.RoomsTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientRooms, ClientSync, Fixtures, Identity, Matrix}
  alias LakehouseMatrix.Protocol.Graph

  setup do
    keys = [:native_event_graph, :signing_key, :signing_key_id]
    old = Map.new(keys, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :native_event_graph, true)

    Application.put_env(
      :lakehouse_matrix,
      :signing_key,
      Base.encode64(<<0::256>>, padding: false)
    )

    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")

    on_exit(fn ->
      for {k, v} <- old do
        if is_nil(v),
          do: Application.delete_env(:lakehouse_matrix, k),
          else: Application.put_env(:lakehouse_matrix, k, v)
      end
    end)

    %{alice: Fixtures.user_fixture("alice"), bob: Fixtures.user_fixture("bob")}
  end

  test "native createRoom produces a version-12 graph and Matrix 1.19 state_after sync", ctx do
    assert {:ok, %{"room_id" => ref}} = ClientRooms.create(ctx.alice.id, %{"name" => "Native"})
    assert {:ok, local} = Identity.parse_room_id(ref)
    assert Graph.room(local).version == "12"
    assert Matrix.creator?(local, ctx.alice.id)

    assert {:ok, _} =
             ClientRooms.send(ctx.alice.id, "A", ref, "m.room.message", "one", %{
               "body" => "hello",
               "msgtype" => "m.text"
             })

    assert {:ok, sync} = ClientSync.sync(ctx.alice.id, "A", %{"use_state_after" => "true"})
    room = get_in(sync, ["rooms", "join", ref])
    refute Map.has_key?(room, "state")
    assert Enum.any?(room["state_after"]["events"], &(&1["type"] == "m.room.create"))
    assert Enum.any?(room["timeline"]["events"], &(&1["content"]["body"] == "hello"))
    assert {:ok, traditional} = ClientSync.sync(ctx.alice.id, "A", %{})
    assert get_in(traditional, ["rooms", "join", ref, "state"])

    assert {:error, :invalid_param} =
             ClientSync.sync(ctx.alice.id, "A", %{"use_state_after" => "invalid"})
  end

  test "native invitations and acceptance project the same memberships to Matrix and River",
       ctx do
    assert {:ok, %{"room_id" => ref}} =
             Matrix.create_room(ctx.alice.id, %{"invite" => [Identity.user_id("bob")]})

    assert {:ok, sync} = ClientSync.sync(ctx.bob.id, "B", %{})
    assert get_in(sync, ["rooms", "invite", ref])
    assert {:ok, %{"room_id" => ^ref}} = Matrix.join_room(ctx.bob.id, ref)

    assert {:ok, _} =
             ClientRooms.send(ctx.bob.id, "B", ref, "m.room.encrypted", "cipher", %{
               "algorithm" => "m.megolm.v1.aes-sha2",
               "ciphertext" => "opaque"
             })

    assert {:ok, _} = Matrix.leave_room(ctx.bob.id, ref)
  end

  test "departed users retain eligible history without access to later events", ctx do
    {:ok, %{"room_id" => ref}} = ClientRooms.create(ctx.alice.id, %{"preset" => "public_chat"})
    {:ok, local} = Identity.parse_room_id(ref)
    {:ok, _} = Matrix.join_room(ctx.bob.id, ref)

    {:ok, before} =
      ClientRooms.send(ctx.alice.id, "A", ref, "m.room.message", "before", %{
        "body" => "before departure"
      })

    {:ok, _} = Matrix.leave_room(ctx.bob.id, ref)

    {:ok, after_event} =
      ClientRooms.send(ctx.alice.id, "A", ref, "m.room.message", "after", %{
        "body" => "after departure"
      })

    assert {:ok, _} = ClientRooms.event(ctx.bob.id, ref, before["event_id"])
    assert {:error, :not_found} = ClientRooms.event(ctx.bob.id, ref, after_event["event_id"])
    assert {:ok, history} = ClientSync.history(ctx.bob.id, "B", local, %{"limit" => 100})
    assert Enum.any?(history["chunk"], &(&1["event_id"] == before["event_id"]))
    refute Enum.any?(history["chunk"], &(&1["event_id"] == after_event["event_id"]))

    assert {:error, _} =
             ClientRooms.send(ctx.bob.id, "B", ref, "m.room.message", "denied", %{
               "body" => "cannot publish after leaving"
             })
  end

  test "native knocking exposes stripped state until the user is invited and joins", ctx do
    {:ok, %{"room_id" => ref}} = ClientRooms.create(ctx.alice.id, %{})

    {:ok, _} =
      ClientRooms.put_state(ctx.alice.id, ref, "m.room.join_rules", "", %{"join_rule" => "knock"})

    assert {:ok, %{"room_id" => ^ref}} =
             ClientRooms.knock(ctx.bob.id, ref, [], %{"reason" => "Please invite"})

    assert {:ok, sync} = ClientSync.sync(ctx.bob.id, "B", %{})
    assert get_in(sync, ["rooms", "knock", ref, "knock_state", "events"])
    refute get_in(sync, ["rooms", "join", ref])
    assert {:error, _} = ClientRooms.history_access(ctx.bob.id, ref)
    assert {:ok, _} = Matrix.invite(ctx.alice.id, ref, "bob")
    assert {:ok, _} = Matrix.join_room(ctx.bob.id, ref)
    assert {:ok, joined} = ClientSync.sync(ctx.bob.id, "B", %{"since" => sync["next_batch"]})
    assert get_in(joined, ["rooms", "join", ref])
  end

  test "native room names and topics can be unset and long valid metadata remains intact", ctx do
    {:ok, %{"room_id" => ref}} =
      ClientRooms.create(ctx.alice.id, %{"name" => "Before", "visibility" => "public"})

    {:ok, room} = Identity.parse_room_id(ref)
    long = String.duplicate("n", 1024)

    assert {:ok, _} =
             ClientRooms.put_state(ctx.alice.id, ref, "m.room.name", "", %{"name" => long})

    assert LakehouseMatrix.Rooms.get_room(room).name == long

    assert {:ok, _} =
             ClientRooms.put_state(ctx.alice.id, ref, "m.room.name", "", %{"name" => nil})

    assert LakehouseMatrix.Rooms.get_room(room).name == ""
    assert {:ok, _} = ClientRooms.put_state(ctx.alice.id, ref, "m.room.topic", "", %{})
    assert LakehouseMatrix.Rooms.get_room(room).topic == ""

    assert {:ok, _} =
             Graph.send(room, Identity.user_id("alice"), "m.room.name", %{"name" => 1}, "")

    assert {:ok, %{"chunk" => [%{}]}} = LakehouseMatrix.Directory.public_rooms(%{})
  end

  test "forgetting is private, requires departure and is reversed by joining again", ctx do
    alias LakehouseMatrix.ClientStore
    {:ok, %{"room_id" => ref}} = ClientRooms.create(ctx.alice.id, %{"preset" => "public_chat"})
    {:ok, room} = Identity.parse_room_id(ref)
    {:ok, _} = Matrix.join_room(ctx.bob.id, ref)
    {:ok, before} = ClientSync.sync(ctx.bob.id, "B", %{})
    assert {:error, :forbidden} = ClientRooms.forget(ctx.bob.id, ref)
    {:ok, _} = Matrix.leave_room(ctx.bob.id, ref)
    assert {:ok, %{}} = ClientRooms.forget(ctx.bob.id, ref)
    assert {:ok, %{}} = ClientRooms.forget(ctx.bob.id, ref)
    assert ClientStore.room_forgotten?(ctx.bob.id, room)

    assert {:ok, after_forget} =
             ClientSync.sync(ctx.bob.id, "B", %{"since" => before["next_batch"]})

    refute get_in(after_forget, ["rooms", "leave", ref])

    {:ok, _} =
      Graph.send(
        room,
        Identity.user_id("alice"),
        "m.room.history_visibility",
        %{"history_visibility" => "world_readable"},
        ""
      )

    assert {:error, _} = ClientRooms.history_access(ctx.bob.id, ref)
    assert {:ok, _, _} = ClientRooms.history_access(ctx.alice.id, ref)
    assert {:ok, _} = Matrix.join_room(ctx.bob.id, ref)
    refute ClientStore.room_forgotten?(ctx.bob.id, room)

    assert {:ok, joined} =
             ClientSync.sync(ctx.bob.id, "B", %{"since" => after_forget["next_batch"]})

    assert get_in(joined, ["rooms", "join", ref])
  end

  test "sync membership and summaries stop at the device-delivery high watermark", ctx do
    alias LakehouseMatrix.ClientStore

    {:ok, %{"room_id" => ref}} =
      ClientRooms.create(ctx.alice.id, %{"invite" => [Identity.user_id("bob")]})

    rows =
      for _ <- 1..101,
          do: %{
            principal_id: ClientStore.dump_id(ctx.bob.id),
            device_id: "B",
            sender: Identity.user_id("alice"),
            type: "m.test",
            content: %{}
          }

    Repo.insert_all("matrix_to_device", rows)
    {:ok, _} = Matrix.join_room(ctx.bob.id, ref)
    assert {:ok, first} = ClientSync.sync(ctx.bob.id, "B", %{})
    assert length(first["to_device"]["events"]) == 100
    assert get_in(first, ["rooms", "invite", ref])
    refute get_in(first, ["rooms", "join", ref])
    assert {:ok, second} = ClientSync.sync(ctx.bob.id, "B", %{"since" => first["next_batch"]})
    assert get_in(second, ["rooms", "join", ref])
    refute get_in(second, ["rooms", "invite", ref])
  end

  test "River spaces and channels share signed events, stable retries and restricted membership with Matrix clients",
       ctx do
    alias LakehouseMatrix.{DelegatedGroups, Memberships, State}
    alias LakehouseIam.Apps.Grants

    scopes =
      ~w(chats.list chats.read chats.write groups.create groups.manage groups.join spaces.channels)

    {:ok, grant} = Grants.upsert(ctx.alice.id, "https://chat.gravitas.cool", scopes, :all, [])

    assert {:ok, space} =
             DelegatedGroups.create(grant, %{
               "name" => "Federated River",
               "kind" => "space",
               "txn_id" => "space"
             })

    assert Graph.room(space.id).version == "12"
    assert State.get(space.id, "m.room.create")["content"]["type"] == "m.space"
    assert {:ok, %{channels: channels}} = DelegatedGroups.channels(grant, space.id)
    assert length(channels) == 2
    assert Enum.all?(channels, &(Graph.room(&1.id).version == "12"))

    assert {:ok, _} =
             DelegatedGroups.membership(grant, space.id, %{
               "action" => "invite",
               "user_id" => Identity.user_id(ctx.bob.username)
             })

    assert {:ok, _} = Matrix.join_room(ctx.bob.id, space.room_id)
    assert Enum.all?(channels, &Memberships.joined?(&1.id, ctx.bob.id))
    channel = hd(channels)

    assert {:ok, sent} =
             DelegatedGroups.send(grant, channel.id, "m.room.message", "same", %{
               "body" => "River"
             })

    assert {:ok, ^sent} =
             DelegatedGroups.send(grant, channel.id, "m.room.message", "same", %{
               "body" => "River"
             })

    assert Graph.event(sent["event_id"])

    assert {:error, :transaction_conflict} =
             DelegatedGroups.send(grant, channel.id, "m.room.message", "same", %{
               "body" => "changed"
             })

    assert {:ok, _} =
             ClientRooms.send(ctx.bob.id, "B", channel.room_id, "m.room.message", "matrix", %{
               "body" => "Matrix"
             })

    assert {:ok, %{events: events}} = DelegatedGroups.timeline(grant, channel.id, %{})
    assert Enum.any?(events, &(&1["content"]["body"] == "Matrix"))
    assert {:ok, _} = Matrix.leave_room(ctx.bob.id, channel.room_id)
    assert {:ok, _} = Matrix.join_room(ctx.bob.id, channel.room_id)
    assert State.get(channel.id, "m.room.join_rules")["content"]["join_rule"] == "restricted"
    assert {:ok, _} = Matrix.invite(ctx.alice.id, space.room_id, "@remote:remote.org")
  end
end
