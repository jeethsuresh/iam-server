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
