defmodule LakehouseMatrix.ProtocolFixtures do
  alias LakehouseMatrix.Protocol.{Event, Authorization}
  @seed <<0::256>>
  @alice "@alice:example.org"
  def alice, do: @alice
  def bob, do: "@bob:remote.org"
  def seed, do: @seed

  def lookup(_, "ed25519:test", _),
    do: {:ok, LakehouseMatrix.Federation.Signing.public_key(@seed)}

  def lookup(_, _, _), do: {:error, :unknown_key}

  def room(version, content \\ %{}) do
    create = %{
      "type" => "m.room.create",
      "sender" => @alice,
      "state_key" => "",
      "content" => Map.merge(%{"room_version" => version}, content),
      "auth_events" => [],
      "prev_events" => [],
      "depth" => 0,
      "origin_server_ts" => 1_000_000
    }

    create = if version == "11", do: Map.put(create, "room_id", "!test:example.org"), else: create
    create = Event.sign(create, version, @seed, "ed25519:test", "example.org")
    create = Map.put(create, "event_id", Event.id(create, version))

    %{
      version: version,
      create: create,
      room: Event.room_id(create, version),
      head: create,
      state: %{{"m.room.create", ""} => create},
      graph: %{create["event_id"] => create}
    }
  end

  def append(chain, type, content, opts \\ []) do
    sender = Keyword.get(opts, :sender, @alice)

    event = %{
      "type" => type,
      "sender" => sender,
      "room_id" => chain.room,
      "content" => content,
      "prev_events" => [chain.head["event_id"]],
      "depth" => chain.head["depth"] + 1,
      "origin_server_ts" => Keyword.get(opts, :ts, chain.head["origin_server_ts"] + 1)
    }

    event =
      if Keyword.has_key?(opts, :key), do: Map.put(event, "state_key", opts[:key]), else: event

    event =
      Map.put(event, "auth_events", Authorization.select_auth(event, chain.state, chain.version))

    {:ok, server} = Event.user_domain(sender)
    event = Event.sign(event, chain.version, @seed, "ed25519:test", server)
    event = Map.put(event, "event_id", Event.id(event, chain.version))

    state =
      if Map.has_key?(event, "state_key"),
        do: Map.put(chain.state, Authorization.key(event), event),
        else: chain.state

    {event,
     %{chain | head: event, state: state, graph: Map.put(chain.graph, event["event_id"], event)}}
  end

  def public_room(version) do
    chain = room(version)
    {_, chain} = append(chain, "m.room.member", %{"membership" => "join"}, key: @alice)
    users = if version == "11", do: %{@alice => 100}, else: %{}

    {_, chain} =
      append(chain, "m.room.power_levels", %{"users" => users, "state_default" => 50}, key: "")

    {_, chain} = append(chain, "m.room.join_rules", %{"join_rule" => "public"}, key: "")
    chain
  end

  def state_ids(chain), do: Map.new(chain.state, fn {key, event} -> {key, event["event_id"]} end)
end
