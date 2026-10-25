defmodule LakehouseMatrix.EphemeralTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseIam.Repo

  alias LakehouseMatrix.{
    ClientRooms,
    ClientStore,
    ClientSync,
    Ephemeral,
    Fixtures,
    Identity,
    Matrix,
    SlidingSync
  }

  alias LakehouseMatrix.Federation.Edus
  alias LakehouseMatrix.Protocol.Graph
  import Ecto.Query

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
    outsider = Fixtures.user_fixture("outsider")
    {:ok, %{"room_id" => ref}} = ClientRooms.create(alice.id, %{"preset" => "public_chat"})
    {:ok, _} = Matrix.join_room(bob.id, ref)
    {:ok, local} = Identity.parse_room_id(ref)
    %{alice: alice, bob: bob, outsider: outsider, ref: ref, local: local}
  end

  test "typing reaches ordinary and sliding sync, expires, and cannot impersonate another user",
       ctx do
    {:ok, initial} = ClientSync.sync(ctx.alice.id, "A", %{})
    user = Identity.user_id("bob")
    assert {:error, _} = Ephemeral.typing(ctx.outsider.id, ctx.ref, user, %{"typing" => true})

    assert {:ok, %{}} =
             Ephemeral.typing(ctx.bob.id, ctx.ref, user, %{"typing" => true, "timeout" => 1000})

    {:ok, update} = ClientSync.sync(ctx.alice.id, "A", %{"since" => initial["next_batch"]})

    assert Enum.any?(
             get_in(update, ["rooms", "join", ctx.ref, "ephemeral", "events"]),
             &(&1 == %{"type" => "m.typing", "content" => %{"user_ids" => [user]}})
           )

    params = %{
      "room_subscriptions" => %{ctx.ref => %{"timeline_limit" => 1}},
      "extensions" => %{"typing" => %{"enabled" => true}}
    }

    {:ok, sliding} = SlidingSync.sync(ctx.alice.id, "S", params)

    assert get_in(sliding, ["extensions", "typing", "rooms", ctx.ref, "content", "user_ids"]) == [
             user
           ]

    assert {:ok, 1} = Ephemeral.expire(DateTime.add(ClientStore.now(), 2, :second))
    {:ok, stopped} = ClientSync.sync(ctx.alice.id, "A", %{"since" => update["next_batch"]})

    assert Enum.any?(
             get_in(stopped, ["rooms", "join", ctx.ref, "ephemeral", "events"]),
             &(&1["type"] == "m.typing" and &1["content"]["user_ids"] == [])
           )

    assert {:ok, 0} = Ephemeral.expire(DateTime.add(ClientStore.now(), 2, :second))
  end

  test "presence respects shared rooms, keeps status messages and delivers remote changes", ctx do
    user = Identity.user_id("bob")

    assert {:ok, _} =
             Ephemeral.set_presence(ctx.bob.id, %{
               "presence" => "unavailable",
               "status_msg" => "Away"
             })

    assert {:ok, %{"presence" => "unavailable", "status_msg" => "Away"}} =
             Ephemeral.get_presence(ctx.alice.id, user)

    assert {:error, :forbidden} = Ephemeral.get_presence(ctx.outsider.id, user)
    assert {:ok, _} = ClientSync.sync(ctx.bob.id, "B", %{"set_presence" => "unavailable"})
    assert {:ok, %{"status_msg" => "Away"}} = Ephemeral.get_presence(ctx.alice.id, user)

    assert {:ok, _} =
             Edus.receive("remote.org", %{
               "edu_type" => "m.presence",
               "content" => %{
                 "push" => [%{"user_id" => "@stranger:remote.org", "presence" => "online"}]
               }
             })

    refute Enum.any?(
             Ephemeral.presence_events(ctx.alice.id, 0, ClientStore.position()),
             &(&1["sender"] == "@stranger:remote.org")
           )

    {:ok, _} =
      Graph.send(
        ctx.local,
        Identity.user_id("alice"),
        "m.room.member",
        %{"membership" => "invite"},
        "@remote:remote.org"
      )

    # A signed joined member is required; an invitation alone does not authorize presence delivery.
    assert {:ok, _} =
             Edus.receive("remote.org", %{
               "edu_type" => "m.presence",
               "content" => %{
                 "push" => [%{"user_id" => "@remote:remote.org", "presence" => "online"}]
               }
             })

    refute Repo.exists?(
             from e in "matrix_ephemeral_events", where: e.user_id == "@remote:remote.org"
           )

    assert {:ok, _} = Ephemeral.expire(DateTime.add(ClientStore.now(), 181, :second))

    assert Enum.any?(
             Ephemeral.presence_events(ctx.alice.id, 0, ClientStore.position()),
             &(&1["sender"] == user and &1["content"]["presence"] == "offline")
           )
  end
end
