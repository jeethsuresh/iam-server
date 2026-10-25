defmodule LakehouseMatrix.Protocol.PolicyTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientRooms, Fixtures, Identity, Rooms}
  alias LakehouseMatrix.Protocol.{Event, Graph, Policy}
  alias LakehouseMatrix.ProtocolFixtures, as: F
  alias LakehouseMatrix.Federation.Signing
  @policy_seed <<17::256>>
  @server "remote.org"

  setup do
    settings = [:homeserver_domain, :signing_key, :signing_key_id, :federation_requester]
    old = Map.new(settings, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :homeserver_domain, "example.org")
    Application.put_env(:lakehouse_matrix, :signing_key, Base.encode64(F.seed(), padding: false))
    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")

    on_exit(fn ->
      for {key, value} <- old do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    alice = Fixtures.user_fixture("alice")
    {:ok, room} = Rooms.create_room_record(%{name: "Policy"})
    {:ok, _} = Graph.create(room.id, F.alice())

    {:ok, _} =
      Graph.send(room.id, F.alice(), "m.room.member", %{"membership" => "join"}, F.alice())

    {:ok, _} = Graph.send(room.id, F.alice(), "m.room.join_rules", %{"join_rule" => "public"}, "")

    join =
      Graph.template(
        Graph.room(room.id),
        Graph.load_graph(room.id),
        F.bob(),
        "m.room.member",
        %{"membership" => "join"},
        F.bob()
      )
      |> Event.sign("12", F.seed(), "ed25519:test", @server)

    {:ok, _} = Graph.receive_pdu(room.id, join, &F.lookup/3)

    {:ok, _} =
      Graph.send(
        room.id,
        F.alice(),
        "m.room.policy",
        %{
          "via" => @server,
          "public_keys" => %{
            "ed25519" => Base.encode64(Signing.public_key(@policy_seed), padding: false)
          }
        },
        ""
      )

    %{alice: alice, room: room, ref: Identity.room_id(room.id)}
  end

  defp signer do
    parent = self()

    fn :post, @server, "/_matrix/policy/v1/sign", wire ->
      send(parent, {:policy_request, Repo.in_transaction?(), wire})
      signed = Event.add_signature(wire, "12", @policy_seed, "ed25519:policy_server", @server)
      {:ok, Map.take(signed["signatures"], [@server])}
    end
  end

  test "client sends acquire a policy signature outside their atomic transaction and preserve transaction retries",
       ctx do
    Application.put_env(:lakehouse_matrix, :federation_requester, signer())

    assert {:ok, sent} =
             ClientRooms.send(ctx.alice.id, "A", ctx.ref, "m.room.message", "one", %{
               "body" => "moderated"
             })

    assert_receive {:policy_request, false, requested}
    assert Event.id(requested, "12") == sent["event_id"]
    stored = Graph.event(sent["event_id"])

    assert Policy.recommended?(
             stored.pdu,
             LakehouseMatrix.Federation.RoomAccess.state(Graph.room(ctx.room.id)),
             "12"
           )

    assert {:ok, ^sent} =
             ClientRooms.send(ctx.alice.id, "A", ctx.ref, "m.room.message", "one", %{
               "body" => "moderated"
             })

    refute_receive {:policy_request, _, _}
  end

  test "a replacement room's create hash and predecessor references survive an outer policy retry",
       ctx do
    Application.put_env(:lakehouse_matrix, :federation_requester, signer())
    id = Ecto.UUID.generate()
    parent = self()

    assert {:ok, {replacement, message}} =
             Policy.transaction(fn ->
               {:ok, created} =
                 LakehouseMatrix.Protocol.Rooms.create(ctx.alice.id, %{"name" => "Replacement"},
                   id: id
                 )

               send(parent, {:replacement, created["room_id"]})

               case Graph.send(ctx.room.id, F.alice(), "m.room.message", %{
                      "replacement_room" => created["room_id"]
                    }) do
                 {:ok, message} -> {created, message}
                 {:error, reason} -> Repo.rollback(reason)
               end
             end)

    ref = replacement["room_id"]
    assert_receive {:replacement, ^ref}
    assert_receive {:replacement, ^ref}
    assert_receive {:policy_request, false, wire}
    refute_receive {:policy_request, _, _}
    assert wire["content"]["replacement_room"] == ref
    assert message["content"]["replacement_room"] == ref
    assert Identity.room_id(id) == ref
  end

  test "a policy-moderated upgrade retains one replacement across tombstone and freeze approvals",
       ctx do
    Application.put_env(:lakehouse_matrix, :federation_requester, signer())

    assert {:ok, %{"replacement_room" => ref}} =
             LakehouseMatrix.RoomUpgrades.upgrade(ctx.alice.id, ctx.ref, %{"new_version" => "12"})

    assert_receive {:policy_request, false, tombstone}
    assert tombstone["type"] == "m.room.tombstone"
    assert tombstone["content"]["replacement_room"] == ref
    assert_receive {:policy_request, false, freeze}
    assert freeze["type"] == "m.room.power_levels"
    refute_receive {:policy_request, _, _}
    assert Graph.room_by_id(ref).version == "12"
    assert Repo.aggregate(LakehouseMatrix.Schema.Room, :count) == 2
    assert Repo.aggregate("matrix_room_upgrades", :count) == 1
  end

  test "policy refusal rolls back the event and transaction ledger; disabling the policy stays possible",
       ctx do
    error = %{"errcode" => "M_FORBIDDEN", "error" => "Policy declined"}

    Application.put_env(:lakehouse_matrix, :federation_requester, fn _, _, _, _ ->
      {:error, {:http, 403, error}}
    end)

    heads = Graph.room(ctx.room.id).extremities

    assert {:error, {:policy_error, 403, ^error}} =
             ClientRooms.send(ctx.alice.id, "A", ctx.ref, "m.room.message", "blocked", %{
               "body" => "blocked"
             })

    assert Graph.room(ctx.room.id).extremities == heads
    assert Repo.aggregate("matrix_transactions", :count) == 0
    assert {:ok, _} = Graph.send(ctx.room.id, F.alice(), "m.room.policy", %{}, "")

    assert {:ok, _} =
             Graph.send(ctx.room.id, F.alice(), "m.room.message", %{"body" => "policy disabled"})
  end

  test "federated policy failures soft-fail and can be retried with a valid policy signature",
       ctx do
    Application.put_env(:lakehouse_matrix, :federation_requester, fn _, _, _, _ ->
      {:error, :unavailable}
    end)

    wire =
      Graph.template(
        Graph.room(ctx.room.id),
        Graph.load_graph(ctx.room.id),
        F.bob(),
        "m.room.message",
        %{"body" => "pending policy"},
        nil
      )
      |> Event.sign("12", F.seed(), "ed25519:test", @server)

    id = Event.id(wire, "12")
    heads = Graph.room(ctx.room.id).extremities
    assert {:ok, _} = Graph.receive_pdu(ctx.room.id, wire, &F.lookup/3)
    assert Graph.event(id).policy_rejected
    assert Graph.event(id).soft_failed
    assert Graph.room(ctx.room.id).extremities == heads
    refute Repo.exists?(from e in LakehouseMatrix.Schema.RoomEvent, where: e.event_id == ^id)
    signed = Event.add_signature(wire, "12", @policy_seed, "ed25519:policy_server", @server)
    assert {:ok, _} = Graph.receive_pdu(ctx.room.id, signed, &F.lookup/3)
    refute Graph.event(id).policy_rejected
    refute Graph.event(id).soft_failed
    assert Repo.exists?(from e in LakehouseMatrix.Schema.RoomEvent, where: e.event_id == ^id)
  end
end
