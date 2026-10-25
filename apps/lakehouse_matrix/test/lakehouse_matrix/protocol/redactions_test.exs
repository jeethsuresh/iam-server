defmodule LakehouseMatrix.Protocol.RedactionsTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{
    ClientRooms,
    ClientStore,
    ClientSync,
    Events,
    Fixtures,
    Identity,
    Rooms,
    State
  }

  alias LakehouseMatrix.Protocol.{Event, Graph}
  alias LakehouseMatrix.ProtocolFixtures, as: F
  @bob "@bob:remote.org"
  setup do
    settings = [:homeserver_domain, :signing_key, :signing_key_id]
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
    {:ok, room} = Rooms.create_room_record(%{name: "Redactions"})
    {:ok, _} = Graph.create(room.id, F.alice())

    {:ok, _} =
      Graph.send(
        room.id,
        F.alice(),
        "m.room.member",
        %{"membership" => "join", "displayname" => "Alice"},
        F.alice()
      )

    {:ok, _} = Graph.send(room.id, F.alice(), "m.room.join_rules", %{"join_rule" => "public"}, "")

    {:ok, _} =
      Graph.receive_pdu(
        room.id,
        remote(room.id, "m.room.member", %{"membership" => "join"}, @bob),
        &F.lookup/3
      )

    %{alice: alice, room: room, ref: Identity.room_id(room.id)}
  end

  defp remote(room, type, content, key \\ nil),
    do:
      Graph.template(Graph.room(room), Graph.load_graph(room), @bob, type, content, key)
      |> Event.sign("12", F.seed(), "ed25519:test", "remote.org")

  defp client(id),
    do: Events.to_client_event(Repo.get_by!(LakehouseMatrix.Schema.RoomEvent, event_id: id))

  test "a low-powered foreign sender cannot erase another server's content or expose an unapplied redaction",
       ctx do
    {:ok, message} = Graph.send(ctx.room.id, F.alice(), "m.room.message", %{"body" => "retained"})
    redaction = remote(ctx.room.id, "m.room.redaction", %{"redacts" => message["event_id"]})
    assert {:ok, _} = Graph.receive_pdu(ctx.room.id, redaction, &F.lookup/3)
    assert client(message["event_id"])["content"]["body"] == "retained"

    assert {:error, :not_found} =
             ClientRooms.event(ctx.alice.id, ctx.ref, Event.id(redaction, "12"))

    refute Graph.event(Event.id(redaction, "12")).redaction_applied
  end

  test "room creators can redact state without deleting authorization-critical membership fields",
       ctx do
    member = State.get(ctx.room.id, "m.room.member", F.alice())["event_id"]

    assert {:ok, redaction} =
             ClientRooms.redact(ctx.alice.id, "A", ctx.ref, member, "state", %{
               "reason" => "remove display"
             })

    event = client(member)
    assert event["content"] == %{"membership" => "join"}
    assert event["unsigned"]["redacted_because"]["event_id"] == redaction["event_id"]
    assert Graph.event(member).pdu["content"] == %{"membership" => "join"}

    assert State.get(ctx.room.id, "m.room.member", F.alice())["content"] == %{
             "membership" => "join"
           }
  end

  test "an earlier valid redaction is delivered with a new stream position when its missing target arrives",
       ctx do
    target = remote(ctx.room.id, "m.room.message", %{"body" => "must not leak"})
    id = Event.id(target, "12")
    redaction = remote(ctx.room.id, "m.room.redaction", %{"redacts" => id})
    assert {:ok, _} = Graph.receive_pdu(ctx.room.id, redaction, &F.lookup/3)
    position = ClientStore.position()
    assert {:ok, _} = Graph.receive_pdu(ctx.room.id, target, &F.lookup/3)
    assert client(id)["content"] == %{}
    assert Graph.event(id).pdu["content"] == %{}
    assert Event.id(Graph.event(id).pdu, "12") == id
    rows = ClientSync.timeline(ctx.room.id, position, ClientStore.position(), 100, ctx.alice.id)
    assert Enum.any?(rows, &(&1.event_id == Event.id(redaction, "12")))
    assert Enum.any?(rows, &(&1.event_id == id and &1.content == %{}))
  end
end
