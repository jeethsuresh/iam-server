defmodule LakehouseMatrix.Protocol.InvitePermissionTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{
    ClientRooms,
    ClientStore,
    ClientSync,
    Cursor,
    Fixtures,
    Identity,
    LegacySync,
    Matrix,
    SlidingSync
  }

  alias LakehouseMatrix.Protocol.Graph
  alias LakehouseMatrix.ProtocolFixtures, as: F

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

    alice = Fixtures.user_fixture("alice")
    bob = Fixtures.user_fixture("bob")
    {:ok, %{"room_id" => ref}} = ClientRooms.create(alice.id, %{})
    {:ok, local} = Identity.parse_room_id(ref)
    %{alice: alice, bob: bob, ref: ref, local: local, user: Identity.user_id("bob")}
  end

  defp block(user, value \\ %{"default_action" => "block"}),
    do: ClientStore.put_data(user.id, "", "m.invite_permission_config", value)

  test "existing invitations disappear from every sync format and return when unblocked", c do
    {:ok, _} = Matrix.invite(c.alice.id, c.ref, c.user)
    assert {:ok, before} = ClientSync.sync(c.bob.id, "B", %{})
    assert before["rooms"]["invite"][c.ref]

    request = %{
      "room_subscriptions" => %{
        c.ref => %{"timeline_limit" => 20, "required_state" => [["*", "*"]]}
      }
    }

    assert {:ok, sliding_before} = SlidingSync.sync(c.bob.id, "B", request)
    assert sliding_before["rooms"][c.ref]["membership"] == "invite"
    assert {:ok, _} = block(c.bob)
    assert {:ok, current} = ClientSync.sync(c.bob.id, "B", %{})
    assert current["rooms"]["invite"] == %{}
    assert {:ok, %{"rooms" => []}} = LegacySync.initial(c.bob.id, "B", %{})

    assert {:ok, %{"chunk" => []}} =
             LegacySync.stream(c.bob.id, "B", %{
               "from" => Cursor.encode("sync", c.bob.id, "B", 0),
               "timeout" => 0
             })

    assert {:ok, %{"rooms" => %{}}} =
             SlidingSync.sync(c.bob.id, "B", Map.put(request, "pos", sliding_before["pos"]))

    assert {:ok, %{"rooms" => %{}}} = SlidingSync.sync(c.bob.id, "B", request, :v4)
    assert {:ok, _} = block(c.bob, %{})
    assert {:ok, restored} = ClientSync.sync(c.bob.id, "B", %{})
    assert restored["rooms"]["invite"][c.ref]
  end

  test "local invitations and room creation cannot bypass blocking through raw membership state",
       c do
    {:ok, _} = block(c.bob)
    assert {:error, :invite_blocked} = Matrix.invite(c.alice.id, c.ref, c.user)

    assert {:error, :invite_blocked} =
             ClientRooms.put_state(c.alice.id, c.ref, "m.room.member", c.user, %{
               "membership" => "invite"
             })

    assert {:error, :invite_blocked} = ClientRooms.create(c.alice.id, %{"invite" => [c.user]})
    assert LakehouseMatrix.Memberships.membership(c.local, c.bob.id) == nil
    {:ok, _} = block(c.bob, %{})
    assert {:ok, _} = Matrix.invite(c.alice.id, c.ref, c.user)
    assert {:ok, _} = Matrix.join_room(c.bob.id, c.ref)
    {:ok, _} = block(c.bob)
    assert {:ok, sync} = ClientSync.sync(c.bob.id, "B", %{})
    events = sync["rooms"]["join"][c.ref]["timeline"]["events"]

    refute Enum.any?(
             events,
             &(get_in(&1, ["content", "membership"]) == "invite" and &1["state_key"] == c.user)
           )

    assert Enum.any?(
             events,
             &(get_in(&1, ["content", "membership"]) == "join" and &1["state_key"] == c.user)
           )
  end

  test "authenticated remote invitations return blocked without creating an outlier room", c do
    remote = F.public_room("12")
    {invite, _} = F.append(remote, "m.room.member", %{"membership" => "invite"}, key: c.user)

    params = %{
      "room_version" => "12",
      "event" => Map.drop(invite, ["event_id", :auth_rejected]),
      "invite_room_state" => []
    }

    {:ok, _} = block(c.bob)

    assert {:error, :invite_blocked} =
             LakehouseMatrix.Federation.Invites.receive(
               "example.org",
               remote.room,
               invite["event_id"],
               params,
               &F.lookup/3
             )

    assert Graph.room_by_id(remote.room) == nil
    assert Graph.event(invite["event_id"]) == nil
    {:ok, _} = block(c.bob, %{})

    assert {:ok, _} =
             LakehouseMatrix.Federation.Invites.receive(
               "example.org",
               remote.room,
               invite["event_id"],
               params,
               &F.lookup/3
             )

    {:ok, _} = block(c.bob)
    assert {:ok, current} = ClientSync.sync(c.bob.id, "B", %{})
    assert current["rooms"]["invite"] == %{}
  end
end
