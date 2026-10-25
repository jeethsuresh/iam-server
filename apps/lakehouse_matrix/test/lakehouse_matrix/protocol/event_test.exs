defmodule LakehouseMatrix.Protocol.EventTest do
  use ExUnit.Case, async: true
  alias LakehouseMatrix.Protocol.Event
  alias LakehouseMatrix.ProtocolFixtures, as: F

  for version <- ["11", "12"] do
    @version version
    test "#{version}: signed messages survive transport, altered content is redacted" do
      chain = F.public_room(@version)

      {message, _} =
        F.append(chain, "m.room.message", %{"body" => "private", "msgtype" => "m.text"})

      assert {:ok, verified} = Event.verify(message, @version, &F.lookup/3)
      assert verified["content"] == message["content"]
      tampered = put_in(message, ["content", "body"], "attacker")
      assert {:ok, redacted} = Event.verify(tampered, @version, &F.lookup/3)
      assert redacted["content"] == %{}
      assert redacted["event_id"] == message["event_id"]

      assert {:error, :invalid_signature} =
               Event.verify(Map.put(message, "sender", F.bob()), @version, &F.lookup/3)
    end

    test "#{version}: unsigned data and extra server signatures do not change the event ID" do
      event = F.public_room(@version).head
      id = Event.id(event, @version)
      event = Map.put(event, "unsigned", %{"age" => 1000})
      assert Event.id(event, @version) == id
      event = put_in(event, ["signatures", "extra.org"], %{"ed25519:unused" => "anything"})
      assert Event.id(event, @version) == id
      assert {:ok, _} = Event.verify(event, @version, &F.lookup/3)

      event =
        put_in(event, ["signatures", "example.org", "ed25519:bad"], "invalid-extra-signature")

      lookup = fn _, _, _ -> {:ok, LakehouseMatrix.Federation.Signing.public_key(F.seed())} end
      assert {:ok, _} = Event.verify(event, @version, lookup)
    end

    test "#{version}: canonical JSON, field and reference limits are enforced" do
      event = F.public_room(@version).head

      assert {:error, :invalid_event} =
               Event.validate(put_in(event, ["content", "float"], 0.1), @version)

      assert {:error, :invalid_event} =
               Event.validate(Map.put(event, "state_key", String.duplicate("é", 128)), @version)

      assert {:error, :invalid_event} =
               Event.validate(Map.put(event, "auth_events", List.duplicate("$a", 11)), @version)

      assert {:error, :invalid_event} =
               Event.validate(Map.put(event, "prev_events", List.duplicate("$a", 21)), @version)

      assert {:error, :invalid_event} =
               Event.validate(
                 put_in(event, ["content", "body"], String.duplicate("x", 66_000)),
                 @version
               )

      assert {:error, :invalid_event} = Event.validate(Map.put(event, "depth", -1), @version)

      assert {:error, :invalid_event} =
               Event.validate(Map.delete(event, "origin_server_ts"), @version)
    end

    test "#{version}: restricted joins require the authorizing server's signature" do
      {join, _} =
        F.append(
          F.public_room(@version),
          "m.room.member",
          %{"membership" => "join", "join_authorised_via_users_server" => F.alice()},
          key: F.bob(),
          sender: F.bob()
        )

      assert {:error, :invalid_signature} = Event.verify(join, @version, &F.lookup/3)
      signed = Event.add_signature(join, @version, F.seed(), "ed25519:test", "example.org")
      assert {:ok, _} = Event.verify(signed, @version, &F.lookup/3)
    end
  end

  test "version 12 derives the room ID from the create PDU without a room_id field" do
    chain = F.room("12", %{"additional_creators" => [F.bob()]})
    assert chain.room == String.replace_prefix(chain.create["event_id"], "$", "!")
    assert :ok = Event.validate(chain.create, "12")

    assert {:error, :invalid_event} =
             Event.validate(Map.put(chain.create, "room_id", chain.room), "12")

    assert F.room("12", %{"additional_creators" => []}).room != chain.room
  end

  test "modern redactions retain authorization fields, create content and redaction targets" do
    base = %{
      "type" => "m.room.member",
      "content" => %{
        "membership" => "invite",
        "displayname" => "Name",
        "third_party_invite" => %{"signed" => %{"token" => "t"}, "display_name" => "drop"}
      },
      "unsigned" => %{"age" => 1}
    }

    assert Event.redact(base, "12") == %{
             "type" => "m.room.member",
             "content" => %{
               "membership" => "invite",
               "third_party_invite" => %{"signed" => %{"token" => "t"}}
             }
           }

    assert Event.redact(%{"type" => "m.room.create", "content" => %{"custom" => "kept"}}, "12")[
             "content"
           ] == %{"custom" => "kept"}

    assert Event.redact(
             %{
               "type" => "m.room.redaction",
               "content" => %{"redacts" => "$x", "reason" => "gone"}
             },
             "11"
           )["content"] == %{"redacts" => "$x"}
  end
end
