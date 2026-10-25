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

  test "join returns signed full state and auth chain, then supports retrieval and leave", ctx do
    {id, response} = join_remote(ctx.room, ctx.ref, ctx.alice)
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
