defmodule LakehouseMatrix.Protocol.AuthorizationTest do
  use ExUnit.Case, async: true
  alias LakehouseMatrix.Protocol.{Authorization, Event}
  alias LakehouseMatrix.ProtocolFixtures, as: F

  for version <- ["11", "12"] do
    @version version
    test "#{version}: creator bootstraps and remote users follow membership authorization" do
      chain = F.room(@version)
      assert :ok = Authorization.check(chain.create, %{}, @version)
      {join, joined} = F.append(chain, "m.room.member", %{"membership" => "join"}, key: F.alice())
      assert :ok = Authorization.check_auth_events(join, chain.graph, @version, chain.create)
      {message, _} = F.append(joined, "m.room.message", %{"body" => "hello"}, sender: F.bob())
      assert {:error, :sender_not_joined} = Authorization.check(message, joined.state, @version)

      {join, _} =
        F.append(joined, "m.room.member", %{"membership" => "join"},
          key: F.bob(),
          sender: F.bob()
        )

      assert {:error, :forbidden} = Authorization.check(join, joined.state, @version)
      public = F.public_room(@version)

      {join, remote} =
        F.append(public, "m.room.member", %{"membership" => "join"},
          key: F.bob(),
          sender: F.bob()
        )

      assert :ok = Authorization.check_auth_events(join, public.graph, @version, public.create)
      {message, _} = F.append(remote, "m.room.message", %{"body" => "hello"}, sender: F.bob())
      assert :ok = Authorization.check(message, remote.state, @version)
    end

    test "#{version}: non-federating rooms reject foreign senders" do
      chain = F.room(@version, %{"m.federate" => false})
      {_, chain} = F.append(chain, "m.room.member", %{"membership" => "join"}, key: F.alice())
      {_, chain} = F.append(chain, "m.room.join_rules", %{"join_rule" => "public"}, key: "")

      {join, _} =
        F.append(chain, "m.room.member", %{"membership" => "join"}, key: F.bob(), sender: F.bob())

      assert {:error, :non_federating_room} = Authorization.check(join, chain.state, @version)
    end

    test "#{version}: duplicate, cross-room, rejected and unrelated auth events are rejected" do
      chain = F.public_room(@version)
      {message, _} = F.append(chain, "m.room.message", %{"body" => "hello"})
      [id | _] = message["auth_events"]
      duplicate = Map.update!(message, "auth_events", &[id | &1])

      assert {:error, :duplicate_auth_event} =
               Authorization.check_auth_events(duplicate, chain.graph, @version, chain.create)

      graph = put_in(chain.graph, [id, "room_id"], "!elsewhere:example.org")

      assert {:error, :wrong_auth_room} =
               Authorization.check_auth_events(message, graph, @version, chain.create)

      graph = put_in(chain.graph, [id, :auth_rejected], true)

      assert {:error, :rejected_auth_event} =
               Authorization.check_auth_events(message, graph, @version, chain.create)

      assert {:error, :missing_auth_event} =
               Authorization.check_auth_events(
                 message,
                 Map.delete(chain.graph, id),
                 @version,
                 chain.create
               )

      rules = chain.state[{"m.room.join_rules", ""}]["event_id"]
      invalid = Map.update!(message, "auth_events", &[rules | &1])

      assert {:error, :unexpected_auth_event} =
               Authorization.check_auth_events(invalid, chain.graph, @version, chain.create)
    end

    test "#{version}: ban, unban, knock and restricted-join failure paths" do
      chain = F.public_room(@version)
      {ban, banned} = F.append(chain, "m.room.member", %{"membership" => "ban"}, key: F.bob())
      assert :ok = Authorization.check(ban, chain.state, @version)

      {join, _} =
        F.append(banned, "m.room.member", %{"membership" => "join"},
          key: F.bob(),
          sender: F.bob()
        )

      assert {:error, :forbidden} = Authorization.check(join, banned.state, @version)
      {unban, _} = F.append(banned, "m.room.member", %{"membership" => "leave"}, key: F.bob())
      assert :ok = Authorization.check(unban, banned.state, @version)

      {_, restricted} =
        F.append(chain, "m.room.join_rules", %{"join_rule" => "knock_restricted"}, key: "")

      {knock, knocked} =
        F.append(restricted, "m.room.member", %{"membership" => "knock"},
          key: F.bob(),
          sender: F.bob()
        )

      assert :ok = Authorization.check(knock, restricted.state, @version)

      {join, _} =
        F.append(knocked, "m.room.member", %{"membership" => "join"},
          key: F.bob(),
          sender: F.bob()
        )

      assert {:error, :forbidden} = Authorization.check(join, knocked.state, @version)
      join = put_in(join, ["content", "join_authorised_via_users_server"], F.alice())
      assert :ok = Authorization.check(join, knocked.state, @version)
    end

    test "#{version}: state keys cannot impersonate other users and power levels reject floats" do
      chain = F.public_room(@version)
      {event, _} = F.append(chain, "custom.state", %{}, key: F.bob())
      assert {:error, :wrong_state_key} = Authorization.check(event, chain.state, @version)
      levels = chain.state[{"m.room.power_levels", ""}]["content"]
      {event, _} = F.append(chain, "m.room.power_levels", levels, key: "")
      event = put_in(event, ["content", "ban"], 1.0)
      assert {:error, :invalid_power_levels} = Authorization.check(event, chain.state, @version)
    end
  end

  test "version 12 creators have infinite power and cannot be demoted, banned or included in power levels" do
    chain = F.public_room("12")
    assert Authorization.power(chain.state, F.alice(), "12") == :infinity

    {event, _} =
      F.append(chain, "m.room.power_levels", %{"users" => %{F.alice() => 100}}, key: "")

    assert {:error, :invalid_power_levels} = Authorization.check(event, chain.state, "12")

    {_, chain} =
      F.append(chain, "m.room.member", %{"membership" => "join"}, key: F.bob(), sender: F.bob())

    {_, chain} =
      F.append(chain, "m.room.power_levels", %{"users" => %{F.bob() => 999_999}}, key: "")

    {ban, _} =
      F.append(chain, "m.room.member", %{"membership" => "ban"}, key: F.alice(), sender: F.bob())

    assert {:error, :forbidden} = Authorization.check(ban, chain.state, "12")
  end

  test "version 12 requires the create event implied by the hashed room ID" do
    chain = F.public_room("12")
    {event, _} = F.append(chain, "m.room.message", %{})

    assert {:error, :wrong_create_event} =
             Authorization.check(event, F.public_room("11").state, "12")

    assert chain.create["event_id"] not in event["auth_events"]
    assert {:ok, _} = Event.verify(event, "12", &F.lookup/3)
  end
end
