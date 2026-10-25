defmodule LakehouseMatrix.Protocol.GraphTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{Fixtures, Identity, Memberships, Rooms, State}
  alias LakehouseMatrix.Federation.Signing
  alias LakehouseMatrix.Protocol.{Event, Graph}
  alias LakehouseMatrix.Schema.RoomEvent
  @seed <<0::256>>
  @remote_seed <<1::256>>
  @remote "@bob:remote.org"

  setup do
    keys = [:homeserver_domain, :signing_key, :signing_key_id]
    previous = Map.new(keys, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :homeserver_domain, "example.org")
    Application.put_env(:lakehouse_matrix, :signing_key, Base.encode64(@seed, padding: false))
    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")

    on_exit(fn ->
      for {key, value} <- previous do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    alice = Fixtures.user_fixture("alice")
    {:ok, room} = Rooms.create_room_record(%{name: "Protocol"})
    {:ok, create} = Graph.create(room.id, Identity.user_id(alice.username))
    %{alice: alice, room: room, create: create, sender: Identity.user_id(alice.username)}
  end

  defp lookup("remote.org", "ed25519:test", _), do: {:ok, Signing.public_key(@remote_seed)}
  defp lookup("example.org", "ed25519:test", _), do: {:ok, Signing.public_key(@seed)}
  defp lookup(_, _, _), do: {:error, :unknown_key}

  defp join_and_open(room, sender) do
    {:ok, _} = Graph.send(room.id, sender, "m.room.member", %{"membership" => "join"}, sender)
    {:ok, _} = Graph.send(room.id, sender, "m.room.join_rules", %{"join_rule" => "public"}, "")
  end

  defp remote_event(room, type, content, key \\ nil) do
    metadata = Graph.room(room.id)

    Graph.template(metadata, Graph.load_graph(room.id), @remote, type, content, key)
    |> Event.sign(metadata.version, @remote_seed, "ed25519:test", "remote.org")
  end

  test "create PDU, hashed room identity, snapshots and client projection are atomic", %{
    room: room,
    create: create,
    sender: sender,
    alice: alice
  } do
    metadata = Graph.room(room.id)
    assert metadata.room_id == String.replace_prefix(create["event_id"], "$", "!")
    assert metadata.create_id == create["event_id"]
    assert Graph.event(create["event_id"]).pdu["room_id"] == nil
    assert Repo.get_by!(RoomEvent, event_id: create["event_id"]).room_id == room.id

    assert {:error, :sender_not_joined} =
             Graph.send(room.id, sender, "m.room.message", %{"body" => "too soon"})

    assert {:ok, join} =
             Graph.send(room.id, sender, "m.room.member", %{"membership" => "join"}, sender)

    assert Memberships.joined?(room.id, alice.id)
    assert Graph.room(room.id).extremities == [join["event_id"]]
    assert State.get(room.id, "m.room.member", sender)["event_id"] == join["event_id"]
    assert {:error, :room_reset_required} = Graph.create(room.id, sender)
    assert {:error, :foreign_sender} = Graph.send(room.id, @remote, "m.room.message", %{})
  end

  test "remote replays are idempotent and a forged signature never touches persistence", %{
    room: room,
    sender: sender
  } do
    join_and_open(room, sender)
    join = remote_event(room, "m.room.member", %{"membership" => "join"}, @remote)
    assert {:ok, accepted} = Graph.receive_pdu(room.id, join, &lookup/3)
    assert {:ok, replay} = Graph.receive_pdu(room.id, join, &lookup/3)
    assert accepted["event_id"] == replay["event_id"]

    assert Repo.aggregate(
             from(e in RoomEvent, where: e.event_id == ^accepted["event_id"]),
             :count
           ) == 1

    forged =
      put_in(
        join,
        ["signatures", "remote.org", "ed25519:test"],
        Base.encode64(<<0::512>>, padding: false)
      )

    assert {:error, :invalid_signature} = Graph.receive_pdu(room.id, forged, &lookup/3)
  end

  test "a delayed pre-ban message is retained for federation but hidden from clients and extremities",
       %{room: room, sender: sender} do
    join_and_open(room, sender)

    assert {:ok, _} =
             Graph.receive_pdu(
               room.id,
               remote_event(room, "m.room.member", %{"membership" => "join"}, @remote),
               &lookup/3
             )

    late = remote_event(room, "m.room.message", %{"body" => "delayed"})
    {:ok, ban} = Graph.send(room.id, sender, "m.room.member", %{"membership" => "ban"}, @remote)
    assert {:ok, accepted} = Graph.receive_pdu(room.id, late, &lookup/3)
    assert Graph.event(accepted["event_id"]).soft_failed
    refute Repo.get_by(RoomEvent, event_id: accepted["event_id"])
    assert Graph.room(room.id).extremities == [ban["event_id"]]

    assert Repo.exists?(
             from o in "matrix_federation_outbox",
               where: o.destination == "remote.org" and o.event_id == ^ban["event_id"]
           )
  end

  test "auth rejection preserves previous state so valid descendants can reference a rejected PDU",
       %{room: room, sender: sender} do
    join_and_open(room, sender)

    assert {:ok, _} =
             Graph.receive_pdu(
               room.id,
               remote_event(room, "m.room.member", %{"membership" => "join"}, @remote),
               &lookup/3
             )

    rejected = remote_event(room, "m.room.member", %{"membership" => "ban"}, sender)
    assert {:error, :forbidden} = Graph.receive_pdu(room.id, rejected, &lookup/3)
    id = Event.id(rejected, "12")
    record = Graph.event(id)
    assert record.auth_rejected
    assert record.state_before == record.state_after
    refute Repo.get_by(RoomEvent, event_id: id)
    metadata = Graph.room(room.id)

    descendant =
      Graph.template(
        metadata,
        Graph.load_graph(room.id),
        sender,
        "m.room.message",
        %{"body" => "valid child"},
        nil
      )
      |> Map.put("prev_events", [id])
      |> Event.sign("12", @seed, "ed25519:test", "example.org")

    assert {:ok, child} = Graph.receive_pdu(room.id, descendant, &lookup/3)
    assert Repo.get_by(RoomEvent, event_id: child["event_id"])
  end
end
