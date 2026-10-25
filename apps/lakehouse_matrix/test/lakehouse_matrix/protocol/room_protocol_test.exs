defmodule LakehouseMatrix.Federation.RoomProtocolTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{Fixtures, Identity, Rooms}
  alias LakehouseMatrix.Federation.{RoomAccess, RoomProtocol, Signing}
  alias LakehouseMatrix.Protocol.{Event, Graph}
  @local_seed <<0::256>>
  @remote_seed <<1::256>>
  @remote "@bob:remote.org"

  setup do
    keys = [:homeserver_domain, :signing_key, :signing_key_id]
    old = Map.new(keys, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :homeserver_domain, "example.org")

    Application.put_env(
      :lakehouse_matrix,
      :signing_key,
      Base.encode64(@local_seed, padding: false)
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
    {:ok, room} = Rooms.create_room_record(%{name: "Federation"})
    {:ok, _} = Graph.create(room.id, Identity.user_id(alice.username))

    {:ok, _} =
      Graph.send(
        room.id,
        Identity.user_id(alice.username),
        "m.room.member",
        %{"membership" => "join"},
        Identity.user_id(alice.username)
      )

    %{room: room, ref: Graph.room(room.id).room_id, alice: Identity.user_id(alice.username)}
  end

  defp lookup("remote.org", "ed25519:test", _), do: {:ok, Signing.public_key(@remote_seed)}
  defp lookup("example.org", "ed25519:test", _), do: {:ok, Signing.public_key(@local_seed)}
  defp lookup(_, _, _), do: {:error, :unknown_key}

  defp join_remote(room, ref, alice) do
    {:ok, _} = Graph.send(room.id, alice, "m.room.join_rules", %{"join_rule" => "public"}, "")
    {:ok, response} = RoomProtocol.make_membership("remote.org", ref, @remote, "join", ["12"])
    signed = Event.sign(response["event"], "12", @remote_seed, "ed25519:test", "remote.org")
    id = Event.id(signed, "12")

    {:ok, response} =
      RoomProtocol.send_membership("remote.org", ref, id, "join", signed, &lookup/3)

    {id, response}
  end

  test "restricted remote joins include the local authorizer in the signed auth graph", ctx do
    {:ok, parent} = Rooms.create_room_record(%{name: "Parent"})
    {:ok, _} = Graph.create(parent.id, ctx.alice)

    {:ok, _} =
      Graph.send(parent.id, ctx.alice, "m.room.member", %{"membership" => "join"}, ctx.alice)

    parent_ref = Graph.room(parent.id).room_id

    {:ok, _} =
      Graph.send(
        ctx.room.id,
        ctx.alice,
        "m.room.join_rules",
        %{
          "join_rule" => "restricted",
          "allow" => [%{"type" => "m.room_membership", "room_id" => parent_ref}]
        },
        ""
      )

    assert {:error, :unable_to_authorise_join} =
             RoomProtocol.make_membership("remote.org", ctx.ref, @remote, "join", ["12"])

    join_remote(parent, parent_ref, ctx.alice)

    assert {:ok, template} =
             RoomProtocol.make_membership("remote.org", ctx.ref, @remote, "join", ["12"])

    state = RoomAccess.state(Graph.room(ctx.room.id))
    authorizer = state[{"m.room.member", ctx.alice}]["event_id"]
    assert template["event"]["content"]["join_authorised_via_users_server"] == ctx.alice
    assert authorizer in template["event"]["auth_events"]
    signed = Event.sign(template["event"], "12", @remote_seed, "ed25519:test", "remote.org")

    assert {:ok, response} =
             RoomProtocol.send_membership(
               "remote.org",
               ctx.ref,
               Event.id(signed, "12"),
               "join",
               signed,
               &lookup/3
             )

    assert {:ok, _} = Event.verify(response["event"], "12", &lookup/3)

    malformed =
      template["event"]
      |> Map.update!("auth_events", &List.delete(&1, authorizer))
      |> Event.sign("12", @remote_seed, "ed25519:test", "remote.org")

    assert {:error, _} =
             RoomProtocol.send_membership(
               "remote.org",
               ctx.ref,
               Event.id(malformed, "12"),
               "join",
               malformed,
               &lookup/3
             )

    {:ok, other} =
      RoomProtocol.make_membership("remote.org", parent_ref, "@charlie:remote.org", "join", ["12"])

    signed_other = Event.sign(other["event"], "12", @remote_seed, "ed25519:test", "remote.org")

    assert {:ok, _} =
             RoomProtocol.send_membership(
               "remote.org",
               parent_ref,
               Event.id(signed_other, "12"),
               "join",
               signed_other,
               &lookup/3
             )

    {:ok, _} =
      Graph.send(parent.id, ctx.alice, "m.room.member", %{"membership" => "leave"}, ctx.alice)

    assert {:error, :unable_to_authorise_join} =
             RoomProtocol.make_membership("remote.org", ctx.ref, "@charlie:remote.org", "join", [
               "12"
             ])
  end

  test "knock previews contain the full signed create PDU and room-version state", ctx do
    {:ok, _} =
      Graph.send(ctx.room.id, ctx.alice, "m.room.join_rules", %{"join_rule" => "knock"}, "")

    {:ok, template} =
      RoomProtocol.make_membership("remote.org", ctx.ref, @remote, "knock", ["12"])

    signed = Event.sign(template["event"], "12", @remote_seed, "ed25519:test", "remote.org")

    assert {:ok, response} =
             RoomProtocol.send_membership(
               "remote.org",
               ctx.ref,
               Event.id(signed, "12"),
               "knock",
               signed,
               &lookup/3
             )

    assert Enum.any?(response["knock_room_state"], &(&1["type"] == "m.room.create"))

    assert Enum.all?(response["knock_room_state"], fn event ->
             match?({:ok, _}, Event.verify(event, "12", &lookup/3))
           end)
  end

  test "join returns signed full state and auth chain, then supports retrieval and leave", ctx do
    {id, response} = join_remote(ctx.room, ctx.ref, ctx.alice)

    refute Repo.exists?(
             from o in "matrix_federation_outbox",
               where: o.event_id == ^id and o.destination == "remote.org"
           )

    assert response["members_omitted"] == false
    assert Enum.any?(response["state"], &(&1["type"] == "m.room.create"))
    assert {:ok, _} = Event.verify(response["event"], "12", &lookup/3)
    assert {:ok, %{"pdus" => [_]}} = RoomProtocol.event("remote.org", id)
    assert {:ok, %{"pdu_ids" => ids}} = RoomProtocol.state("remote.org", ctx.ref, id, true)
    refute id in ids
    assert {:ok, %{"auth_chain" => [_ | _]}} = RoomProtocol.event_auth("remote.org", ctx.ref, id)
    assert {:ok, %{"pdus" => pdus}} = RoomProtocol.backfill("remote.org", ctx.ref, [id], 100)
    assert Enum.any?(pdus, &(&1["type"] == "m.room.create"))
    refute Enum.any?(pdus, &(Event.id(&1, "12") == id))
    assert {:ok, %{"pdus" => [previous]}} = RoomProtocol.backfill("remote.org", ctx.ref, [id], 1)
    assert Event.id(previous, "12") in Graph.event(id).pdu["prev_events"]
    assert {:ok, template} = RoomProtocol.make_membership("remote.org", ctx.ref, @remote, "leave")
    signed = Event.sign(template["event"], "12", @remote_seed, "ed25519:test", "remote.org")

    assert {:ok, %{}} =
             RoomProtocol.send_membership(
               "remote.org",
               ctx.ref,
               Event.id(signed, "12"),
               "leave",
               signed,
               &lookup/3
             )

    refute RoomAccess.joined?(RoomAccess.state(Graph.room(ctx.room.id)), "remote.org")
    assert {:ok, %{"pdus" => [_]}} = RoomProtocol.event("remote.org", id)
    assert {:ok, %{"pdus" => history}} = RoomProtocol.backfill("remote.org", ctx.ref, [id], 100)
    assert Enum.any?(history, &(&1["type"] == "m.room.create"))

    {:ok, future} =
      Graph.send(ctx.room.id, ctx.alice, "m.room.message", %{
        "body" => "after the remote server left"
      })

    assert {:error, :not_found} = RoomProtocol.event("remote.org", future["event_id"])
    assert {:error, :not_found} = RoomProtocol.state("remote.org", ctx.ref, future["event_id"])

    assert {:error, :not_found} =
             RoomProtocol.event_auth("remote.org", ctx.ref, future["event_id"])
  end

  test "private rooms, origin spoofing and ACLs block unauthorized joins and reads", ctx do
    assert {:error, :forbidden} =
             RoomProtocol.make_membership("remote.org", ctx.ref, @remote, "join", ["12"])

    assert {:error, _} =
             RoomProtocol.make_membership("spoof.org", ctx.ref, @remote, "join", ["12"])

    {id, _} = join_remote(ctx.room, ctx.ref, ctx.alice)
    assert {:error, :not_found} = RoomProtocol.event("outsider.org", id)

    {:ok, _} =
      Graph.send(
        ctx.room.id,
        ctx.alice,
        "m.room.server_acl",
        %{"allow" => ["*"], "deny" => ["remote.org"]},
        ""
      )

    assert {:error, :forbidden} =
             RoomProtocol.make_membership("remote.org", ctx.ref, @remote, "leave")

    assert {:error, :not_found} = RoomProtocol.event("remote.org", id)
  end

  test "non-federating rooms reject foreign reads even with world-readable history", ctx do
    {:ok, room} = Rooms.create_room_record(%{name: "Local-only"})
    {:ok, _} = Graph.create(room.id, ctx.alice, "12", %{"m.federate" => false})

    {:ok, _} =
      Graph.send(room.id, ctx.alice, "m.room.member", %{"membership" => "join"}, ctx.alice)

    {:ok, visible} =
      Graph.send(
        room.id,
        ctx.alice,
        "m.room.history_visibility",
        %{"history_visibility" => "world_readable"},
        ""
      )

    refute RoomAccess.allowed?(Graph.room(room.id), "remote.org")
    assert {:error, :not_found} = RoomProtocol.event("remote.org", visible["event_id"])
  end

  test "ACLs ignore ports, are case-insensitive and handle IP literal policy" do
    acl = %{
      "content" => %{
        "allow" => ["*.example.org"],
        "deny" => ["EVIL.example.org"],
        "allow_ip_literals" => false
      }
    }

    assert RoomAccess.acl_allowed?(acl, "ok.example.org:8448")
    refute RoomAccess.acl_allowed?(acl, "evil.example.org:443")
    refute RoomAccess.acl_allowed?(acl, "127.0.0.1:8448")
    refute RoomAccess.acl_allowed?(%{"content" => %{}}, "example.org")
    assert RoomAccess.acl_allowed?(nil, "example.org")
  end
end
