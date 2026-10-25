defmodule LakehouseMatrix.ClientHistory do
  @moduledoc "Native room pagination in DAG order, with verified federation backfill outside room locks."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientRooms, ClientSync, Cursor, Events, Identity}
  alias LakehouseMatrix.Protocol.{Event, Graph, Import, Policy}
  alias LakehouseMatrix.Federation.{Keyring, RoomAccess, Transport}
  alias LakehouseMatrix.Schema.{Pdu, RoomEvent}
  @upper_bound [9_007_199_254_740_992, ""]
  @lower_bound [-1, ""]

  def before(principal, device, room, event) do
    value =
      case event && Graph.event(event) do
        nil -> @upper_bound
        record -> position(record)
      end

    Cursor.encode("topology", principal, device, value, room)
  end

  def at_stream(principal, device, room, stream) do
    record =
      Repo.one(
        from e in RoomEvent,
          join: p in Pdu,
          on: p.event_id == e.event_id,
          where: e.room_id == ^room and e.stream_id <= ^stream,
          order_by: [desc: e.stream_id],
          limit: 1,
          select: p
      )

    value = if record, do: [record.pdu["depth"], record.event_id <> "~"], else: @lower_bound
    Cursor.encode("topology", principal, device, value, room)
  end

  def page(
        principal,
        device,
        room,
        params,
        request \\ &Transport.request/4,
        lookup \\ &Keyring.key/3
      ) do
    with {:ok, _, _} <- ClientRooms.history_access(principal, Identity.room_id(room)),
         true <- params["dir"] in [nil, "b", "f"],
         {:ok, limit} <- ClientSync.integer(params["limit"], 10, 0, 100),
         {:ok, lower} <- cursor(params["from"], principal, device, room, params["dir"] || "b"),
         {:ok, upper} <- cursor(params["to"], principal, device, room, params["dir"] || "b"),
         {:ok, filter} <- event_filter(params["filter"]) do
      metadata = Graph.room(room)
      direction = params["dir"] || "b"
      candidates = records(room, lower, if(params["to"], do: upper), direction)
      gap = if direction == "b", do: frontier(room, lower, List.last(candidates))
      if gap && limit > 0, do: backfill(metadata, gap, request, lookup)

      candidates =
        if gap, do: records(room, lower, if(params["to"], do: upper), direction), else: candidates

      gap = if direction == "b", do: frontier(room, lower, List.last(candidates))

      safe =
        if gap,
          do: Enum.take_while(candidates, &(&1.pdu["depth"] >= gap.pdu["depth"])),
          else: candidates

      limit = min(limit, filter["limit"] || limit)
      ignored = ClientSync.ignored_users(principal)

      selected =
        visible(safe, metadata, principal)
        |> Enum.filter(&(Map.has_key?(&1.pdu, "state_key") or &1.pdu["sender"] not in ignored))
        |> Enum.map(&client_event/1)
        |> ClientSync.filter_events(Map.delete(filter, "limit"))

      chunk = Enum.take(selected, limit)
      start = params["from"] || Cursor.encode("topology", principal, device, lower, room)
      more = length(selected) > limit or length(candidates) >= 1000 or not is_nil(gap)

      response = %{
        "start" => start,
        "chunk" => LakehouseMatrix.ClientRelations.bundle(principal, room, chunk),
        "state" => []
      }

      last = if chunk != [], do: Graph.event(List.last(chunk)["event_id"]), else: List.last(safe)

      cond do
        limit == 0 ->
          {:ok, response}

        more and is_nil(last) ->
          {:error, :unavailable}

        more ->
          {:ok,
           Map.put(
             response,
             "end",
             Cursor.encode("topology", principal, device, position(last), room)
           )}

        true ->
          {:ok, response}
      end
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_param}
    end
  end

  def cursor(nil, _, _, _, "b"), do: {:ok, @upper_bound}
  def cursor(nil, _, _, _, "f"), do: {:ok, @lower_bound}

  def cursor(token, principal, device, room, direction) do
    case Cursor.decode(token, "topology", principal, device, room) do
      {:ok, position} ->
        {:ok, position}

      _ ->
        with {:ok, stream} <- ClientSync.history_cursor(token, principal, device, room) do
          record =
            Repo.one(
              from e in RoomEvent,
                join: p in Pdu,
                on: p.event_id == e.event_id,
                where: e.room_id == ^room and e.stream_id <= ^stream,
                order_by: [desc: e.stream_id],
                limit: 1,
                select: p
            )

          value =
            if record,
              do: [
                record.pdu["depth"],
                record.event_id <> if(direction == "b", do: "~", else: "")
              ],
              else: @lower_bound

          {:ok, value}
        end
    end
  end

  def query(room) do
    from p in Pdu,
      where:
        p.local_room_id == ^room and not p.outlier and not p.auth_rejected and
          not p.state_rejected and not p.soft_failed and
          fragment("?->>'type' <> 'm.room.redaction' OR ?", p.pdu, p.redaction_applied)
  end

  defp records(room, lower, upper, direction), do: ordered(query(room), lower, upper, direction)

  def ordered(query, [depth, id], upper, direction, limit \\ 1000) do
    query = from p in query, limit: ^limit

    query =
      if direction == "b" do
        from p in query,
          where:
            fragment(
              "(?->>'depth')::bigint < ? OR ((?->>'depth')::bigint = ? AND ? < ?)",
              p.pdu,
              ^depth,
              p.pdu,
              ^depth,
              p.event_id,
              ^id
            ),
          order_by: [desc: fragment("(?->>'depth')::bigint", p.pdu), desc: p.event_id]
      else
        from p in query,
          where:
            fragment(
              "(?->>'depth')::bigint > ? OR ((?->>'depth')::bigint = ? AND ? > ?)",
              p.pdu,
              ^depth,
              p.pdu,
              ^depth,
              p.event_id,
              ^id
            ),
          order_by: [asc: fragment("(?->>'depth')::bigint", p.pdu), asc: p.event_id]
      end

    query =
      case upper do
        [depth, id] when direction == "b" ->
          from p in query,
            where:
              fragment(
                "(?->>'depth')::bigint > ? OR ((?->>'depth')::bigint = ? AND ? > ?)",
                p.pdu,
                ^depth,
                p.pdu,
                ^depth,
                p.event_id,
                ^id
              )

        [depth, id] ->
          from p in query,
            where:
              fragment(
                "(?->>'depth')::bigint < ? OR ((?->>'depth')::bigint = ? AND ? < ?)",
                p.pdu,
                ^depth,
                p.pdu,
                ^depth,
                p.event_id,
                ^id
              )

        _ ->
          query
      end

    Repo.all(query)
  end

  defp frontier(room, [depth, _], last) do
    minimum = if last, do: last.pdu["depth"], else: 0

    Repo.one(
      from p in Pdu,
        where:
          p.local_room_id == ^room and not p.outlier and not p.auth_rejected and
            not p.state_rejected and not p.soft_failed and
            fragment(
              "(?->>'depth')::bigint <= ? AND (?->>'depth')::bigint >= ?",
              p.pdu,
              ^depth,
              p.pdu,
              ^minimum
            ) and
            fragment(
              "EXISTS (SELECT 1 FROM jsonb_array_elements_text(?->'prev_events') parent(id) LEFT JOIN matrix_pdus previous ON previous.event_id = parent.id WHERE previous.event_id IS NULL OR previous.outlier)",
              p.pdu
            ),
        order_by: [desc: fragment("(?->>'depth')::bigint", p.pdu)],
        limit: 1
    )
  end

  defp backfill(metadata, root, request, lookup) do
    state = RoomAccess.state(metadata)

    peers =
      for {{"m.room.member", user}, event} <- state,
          event["content"]["membership"] == "join",
          {:ok, server} <- [Event.user_domain(user)],
          server != Identity.homeserver_domain() and RoomAccess.allowed?(metadata, server),
          do: server

    creator = Graph.event(metadata.create_id)

    peers =
      case creator && Event.user_domain(creator.pdu["sender"]) do
        {:ok, server} -> peers ++ [server]
        _ -> peers
      end

    peers =
      peers |> Enum.uniq() |> Enum.reject(&(&1 == Identity.homeserver_domain())) |> Enum.take(3)

    Enum.reduce_while(peers, :unavailable, fn peer, _ ->
      path =
        "/_matrix/federation/v1/backfill/" <>
          escape(metadata.room_id) <>
          "?" <> URI.encode_query(%{"v" => root.event_id, "limit" => 20})

      case request.(:get, peer, path, nil) do
        {:ok, %{"pdus" => pdus}} when is_list(pdus) and length(pdus) <= 100 ->
          # Peer requests and signature/state verification finish before any room lock.
          snapshots =
            Task.async_stream(pdus, &snapshot(metadata, peer, &1, request, lookup),
              max_concurrency: 4,
              timeout: 30_000,
              on_timeout: :kill_task
            )

          installed =
            Enum.count(snapshots, fn
              {:ok, {:ok, snapshot}} ->
                match?(
                  {:ok, _},
                  Graph.install_snapshot(
                    metadata.local_room_id,
                    metadata.room_id,
                    metadata.version,
                    snapshot,
                    :backfill
                  )
                )

              _ ->
                false
            end)

          if installed > 0, do: {:halt, :ok}, else: {:cont, :unavailable}

        _ ->
          {:cont, :unavailable}
      end
    end)
  end

  defp snapshot(metadata, peer, wire, request, lookup) do
    with {:ok, event} <- Event.verify(wire, metadata.version, lookup),
         known <- Graph.event(event["event_id"]),
         true <- is_nil(known) or known.outlier,
         true <-
           (wire["type"] == "m.room.create" and
              Event.room_id(wire, metadata.version) == metadata.room_id) or
             wire["room_id"] == metadata.room_id do
      if wire["type"] == "m.room.create" do
        {:ok, %{event: event, graph: %{event["event_id"] => event}, state: %{}, create: event}}
      else
        path =
          "/_matrix/federation/v1/state/" <>
            escape(metadata.room_id) <> "?event_id=" <> escape(event["event_id"])

        with {:ok, %{"pdus" => state, "auth_chain" => auth}} <- request.(:get, peer, path, nil),
             {:ok, snapshot} <-
               Import.snapshot(metadata.room_id, metadata.version, wire, state, auth, lookup) do
          signed = Policy.recover(snapshot.event, RoomAccess.state(metadata), metadata.version)

          {:ok,
           %{snapshot | event: signed, graph: Map.put(snapshot.graph, signed["event_id"], signed)}}
        end
      end
    else
      _ -> {:error, :invalid_room_snapshot}
    end
  end

  def visible(records, metadata, principal) do
    user = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()
    member = Jason.encode!(["m.room.member", user])
    history = Jason.encode!(["m.room.history_visibility", ""])

    ids =
      Enum.flat_map(records, &[&1.state_before[member], &1.state_before[history]])
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    cache = Repo.all(from p in Pdu, where: p.event_id in ^ids) |> Map.new(&{&1.event_id, &1.pdu})
    current = RoomAccess.state(metadata)
    joined = LakehouseMatrix.Protocol.Authorization.membership(current, user) == "join"

    joins =
      if joined,
        do: [],
        else:
          Repo.all(
            from p in Pdu,
              where:
                p.local_room_id == ^metadata.local_room_id and not p.outlier and
                  not p.auth_rejected and not p.state_rejected and not p.soft_failed and
                  fragment(
                    "?->>'type' = 'm.room.member' AND ?->>'state_key' = ? AND ?->'content'->>'membership' = 'join'",
                    p.pdu,
                    p.pdu,
                    ^user,
                    p.pdu
                  ),
              select: p.event_id
          )

    Enum.filter(records, fn record ->
      before = get_in(cache, [record.state_before[member], "content", "membership"])

      visibility =
        get_in(cache, [record.state_before[history], "content", "history_visibility"]) || "shared"

      after_visibility =
        if record.pdu["type"] == "m.room.history_visibility" and record.pdu["state_key"] == "",
          do: record.pdu["content"]["history_visibility"],
          else: visibility

      visibility = Enum.min_by([visibility, after_visibility || "shared"], &rank/1)
      own = record.pdu["type"] == "m.room.member" and record.pdu["state_key"] == user

      own or
        case visibility do
          "world_readable" ->
            true

          "joined" ->
            before == "join"

          "invited" ->
            before in ~w(join invite)

          _ ->
            joined or before == "join" or
              Graph.ancestor?(metadata.local_room_id, record.event_id, joins)
        end
    end)
  end

  def event(principal, room, id) do
    with {:ok, _, _} <- ClientRooms.history_access(principal, Identity.room_id(room)),
         %Pdu{} = record <- Graph.event(id),
         true <-
           record.local_room_id == room and not record.outlier and not record.auth_rejected and
             not record.state_rejected and not record.soft_failed and
             (record.pdu["type"] != "m.room.redaction" or record.redaction_applied),
         [_] <- visible([record], Graph.room(room), principal) do
      {:ok, client_event(record)}
    else
      _ -> {:error, :not_found}
    end
  end

  def client_event(record) do
    case Repo.get_by(RoomEvent, event_id: record.event_id) do
      nil ->
        result =
          Map.take(record.pdu, ~w(type state_key sender content origin_server_ts room_id))
          |> Map.put("event_id", record.event_id)
          |> Map.put("room_id", Identity.room_id(record.local_room_id))

        if record.redacted_by do
          redaction = Graph.event(record.redacted_by)

          Map.put(result, "unsigned", %{
            "redacted_because" =>
              Map.take(redaction.pdu, ~w(type sender content origin_server_ts))
              |> Map.put("event_id", redaction.event_id)
          })
        else
          result
        end

      event ->
        Events.to_client_event(event)
        |> Map.put("room_id", Identity.room_id(record.local_room_id))
    end
  end

  defp event_filter(nil), do: {:ok, %{}}

  defp event_filter(value) when is_binary(value) and byte_size(value) <= 65_536 do
    with {:ok, filter} <- Jason.decode(value),
         true <- is_map(filter),
         {:ok, _} <- ClientSync.validate_filter(%{"room" => %{"timeline" => filter}}),
         do: {:ok, filter},
         else: (_ -> {:error, :invalid_param})
  end

  defp event_filter(_), do: {:error, :invalid_param}
  defp position(record), do: [record.pdu["depth"], record.event_id]
  defp rank("world_readable"), do: 0
  defp rank("shared"), do: 1
  defp rank("invited"), do: 2
  defp rank(_), do: 3
  defp escape(value), do: URI.encode(value, &URI.char_unreserved?/1)
end
