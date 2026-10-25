defmodule LakehouseMatrix.Federation.RoomProtocol do
  @moduledoc "Signed joins, leaves, knocks, state and event retrieval for native protocol rooms."
  alias LakehouseMatrix.Federation.{Keyring, RoomAccess, Signing}
  alias LakehouseMatrix.Identity
  alias LakehouseMatrix.Protocol.{Authorization, Event, Graph}

  def directory(origin, ref) do
    with {:ok, name} <- Identity.parse_room_alias(ref),
         {:ok, room} <- LakehouseMatrix.Rooms.get_room_by_alias(name),
         metadata when not is_nil(metadata) <- Graph.room(room.id),
         true <- RoomAccess.allowed?(metadata, origin) do
      servers =
        for {{"m.room.member", user}, event} <- RoomAccess.state(metadata),
            event["content"]["membership"] == "join",
            {:ok, server} <- [Event.user_domain(user)],
            do: server

      {:ok,
       %{
         "room_id" => metadata.room_id,
         "servers" => Enum.uniq([Identity.homeserver_domain() | servers])
       }}
    else
      _ -> {:error, :not_found}
    end
  end

  def make_membership(origin, ref, user, membership, versions \\ []) do
    with metadata when not is_nil(metadata) <- Graph.room_by_id(ref),
         true <- RoomAccess.allowed?(metadata, origin),
         {:ok, ^origin} <- Event.user_domain(user),
         :ok <- compatible(metadata, membership, versions),
         event <-
           Graph.template(
             metadata,
             Graph.load_graph(metadata.local_room_id),
             user,
             "m.room.member",
             %{"membership" => membership},
             user
           ),
         {:ok, event} <-
           if(membership == "join",
             do: RoomAccess.restricted_join(metadata, user, event),
             else: {:ok, event}
           ),
         :ok <- Authorization.check(event, RoomAccess.state(metadata), metadata.version) do
      {:ok, %{"room_version" => metadata.version, "event" => event}}
    else
      nil -> {:error, :not_found}
      false -> {:error, :forbidden}
      {:error, _} = error -> error
      _ -> {:error, :forbidden}
    end
  end

  def send_membership(origin, ref, id, membership, wire, lookup \\ &Keyring.key/3) do
    with metadata when not is_nil(metadata) <- Graph.room_by_id(ref),
         true <- RoomAccess.allowed?(metadata, origin),
         true <-
           wire["type"] == "m.room.member" and wire["state_key"] == wire["sender"] and
             get_in(wire, ["content", "membership"]) == membership,
         {:ok, ^origin} <- Event.user_domain(wire["sender"]),
         :ok <- Event.verify_sender(wire, metadata.version, lookup),
         true <- wire["room_id"] == ref and Event.id(wire, metadata.version) == id,
         :ok <- check_restricted(metadata, wire, membership),
         {:ok, seed, key} <- Signing.config(),
         signed <-
           Event.add_signature(wire, metadata.version, seed, key, Identity.homeserver_domain()),
         {:ok, accepted} <- Graph.receive_pdu(metadata.local_room_id, signed, lookup),
         %{soft_failed: false, state_rejected: false} <- Graph.event(id) do
      response =
        case membership do
          "join" ->
            graph = Graph.load_graph(metadata.local_room_id)
            {:ok, before} = Graph.state_at(id)
            ids = Map.values(before)
            auth = Enum.uniq([metadata.create_id | Graph.auth_chain([id | ids], graph)])

            %{
              "origin" => Identity.homeserver_domain(),
              "state" => pdus(ids, graph),
              "auth_chain" => pdus(auth, graph),
              "event" => Map.delete(accepted, "event_id"),
              "members_omitted" => false
            }

          "knock" ->
            stripped =
              RoomAccess.state(Graph.room(metadata.local_room_id))
              |> Map.values()
              |> Enum.filter(
                &(&1["type"] in ~w(m.room.create m.room.name m.room.avatar m.room.topic m.room.join_rules m.room.encryption))
              )
              |> Enum.map(&Map.take(&1, ~w(type state_key content sender)))

            %{"knock_room_state" => stripped}

          "leave" ->
            %{}
        end

      {:ok, response}
    else
      nil -> {:error, :not_found}
      false -> {:error, :forbidden}
      {:error, _} = error -> error
      _ -> {:error, :forbidden}
    end
  end

  def event(origin, id) do
    with record when not is_nil(record) <- Graph.event(id),
         metadata <- Graph.room(record.local_room_id),
         true <- RoomAccess.visible_event?(metadata, origin, id) do
      {:ok,
       %{
         "origin" => Identity.homeserver_domain(),
         "origin_server_ts" => System.system_time(:millisecond),
         "pdus" => [record.pdu]
       }}
    else
      _ -> {:error, :not_found}
    end
  end

  def state(origin, ref, id, ids_only \\ false) do
    with {:ok, metadata} <- readable(origin, ref),
         record when not is_nil(record) <- Graph.event(id),
         true <-
           record.local_room_id == metadata.local_room_id and
             RoomAccess.visible_event?(metadata, origin, id),
         {:ok, state} <- Graph.state_at(id),
         graph <- Graph.load_graph(metadata.local_room_id, [id]) do
      ids = Map.values(state)
      auth = Enum.uniq([metadata.create_id | Graph.auth_chain(ids, graph)])

      if ids_only,
        do: {:ok, %{"pdu_ids" => Enum.sort(ids), "auth_chain_ids" => Enum.sort(auth)}},
        else: {:ok, %{"pdus" => pdus(ids, graph), "auth_chain" => pdus(auth, graph)}}
    else
      _ -> {:error, :not_found}
    end
  end

  def event_auth(origin, ref, id) do
    with {:ok, metadata} <- readable(origin, ref),
         record when not is_nil(record) <- Graph.event(id),
         true <-
           record.local_room_id == metadata.local_room_id and
             RoomAccess.visible_event?(metadata, origin, id) do
      graph = Graph.load_graph(metadata.local_room_id, [id])

      {:ok,
       %{
         "auth_chain" =>
           pdus(Enum.uniq([metadata.create_id | Graph.auth_chain([id], graph)]), graph)
       }}
    else
      _ -> {:error, :not_found}
    end
  end

  def backfill(origin, ref, roots, limit) do
    with {:ok, metadata} <- readable(origin, ref),
         true <- is_list(roots) and length(roots) <= 20,
         true <- is_integer(limit) and limit in 1..1000 do
      records =
        walk(
          predecessors(roots, metadata.local_room_id),
          metadata.local_room_id,
          MapSet.new(roots),
          [],
          limit,
          0
        )
        |> Enum.filter(&RoomAccess.visible_event?(metadata, origin, &1.event_id))

      {:ok,
       %{
         "origin" => Identity.homeserver_domain(),
         "origin_server_ts" => System.system_time(:millisecond),
         "pdus" => Enum.map(records, & &1.pdu)
       }}
    else
      false -> {:error, :invalid_param}
      error -> error
    end
  end

  defp predecessors(roots, room) do
    Enum.flat_map(roots, fn id ->
      case Graph.event(id) do
        %{local_room_id: ^room, pdu: pdu} -> pdu["prev_events"]
        _ -> []
      end
    end)
  end

  def missing(origin, ref, params) do
    earliest = params["earliest_events"]
    latest = params["latest_events"]
    limit = params["limit"] || 10
    depth = params["min_depth"] || 0

    with {:ok, metadata} <- readable(origin, ref),
         true <-
           is_list(earliest) and is_list(latest) and length(earliest) <= 100 and
             length(latest) <= 100 and
             is_integer(limit) and limit in 1..1000 and is_integer(depth) and depth >= 0 do
      roots =
        Enum.flat_map(latest, fn id ->
          case Graph.event(id) do
            %{local_room_id: room} = p when room == metadata.local_room_id -> p.pdu["prev_events"]
            _ -> []
          end
        end)

      records =
        walk(roots, metadata.local_room_id, MapSet.new(earliest ++ latest), [], limit, depth)
        |> Enum.filter(&RoomAccess.visible_event?(metadata, origin, &1.event_id))

      {:ok, %{"events" => Enum.map(records, & &1.pdu)}}
    else
      false -> {:error, :invalid_param}
      error -> error
    end
  end

  defp walk(_, _, _, result, 0, _), do: Enum.reverse(result)
  defp walk([], _, _, result, _, _), do: Enum.reverse(result)

  defp walk([id | rest], room, seen, result, limit, depth) do
    event = if is_binary(id), do: Graph.event(id)

    if MapSet.member?(seen, id) or is_nil(event) or event.local_room_id != room or
         event.pdu["depth"] < depth do
      walk(rest, room, seen, result, limit, depth)
    else
      walk(
        rest ++ event.pdu["prev_events"],
        room,
        MapSet.put(seen, id),
        [event | result],
        limit - 1,
        depth
      )
    end
  end

  defp readable(origin, ref) do
    case Graph.room_by_id(ref) do
      nil ->
        {:error, :not_found}

      metadata ->
        if RoomAccess.readable?(metadata, origin), do: {:ok, metadata}, else: {:error, :forbidden}
    end
  end

  defp compatible(metadata, "join", versions),
    do:
      if(metadata.version in versions,
        do: :ok,
        else: {:error, {:incompatible_room_version, metadata.version}}
      )

  defp compatible(_, _, _), do: :ok

  defp check_restricted(metadata, wire, "join") do
    case RoomAccess.restricted_join(metadata, wire["sender"], wire) do
      {:ok, authorized} ->
        if get_in(authorized, ["content", "join_authorised_via_users_server"]) ==
             get_in(wire, ["content", "join_authorised_via_users_server"]),
           do: :ok,
           else: {:error, :forbidden}

      error ->
        error
    end
  end

  defp check_restricted(_, _, _), do: :ok

  defp pdus(ids, graph),
    do: ids |> Enum.sort() |> Enum.map(&Map.drop(graph[&1], ["event_id", :auth_rejected]))
end
