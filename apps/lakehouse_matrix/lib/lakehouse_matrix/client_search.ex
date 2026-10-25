defmodule LakehouseMatrix.ClientSearch do
  @moduledoc "Indexed, visibility-filtered search of plaintext rooms, with historical context."
  import Ecto.Query
  alias LakehouseIam.Repo

  alias LakehouseMatrix.{
    ClientFilters,
    ClientHistory,
    ClientRooms,
    ClientStore,
    ClientSync,
    Cursor,
    Identity,
    State
  }

  alias LakehouseMatrix.Protocol.Graph
  alias LakehouseMatrix.Schema.{RoomEvent, RoomMembership}

  @keys %{
    "content.body" => "m.room.message",
    "content.name" => "m.room.name",
    "content.topic" => "m.room.topic"
  }

  # Matrix explicitly permits search without pagination. No cursor is issued:
  # results are bounded after access and event filtering, never before them.
  def search(principal, device, params) do
    with true <- is_nil(params["next_batch"]),
         categories when is_map(categories) <- params["search_categories"] do
      if Map.has_key?(categories, "room_events"),
        do: run(principal, device, categories["room_events"]),
        else: {:ok, %{"search_categories" => %{}}}
    else
      _ -> {:error, :invalid_param}
    end
  end

  defp run(principal, device, criteria) when is_map(criteria) do
    term = criteria["search_term"]
    keys = Map.get(criteria, "keys", Map.keys(@keys))
    filter = Map.get(criteria, "filter", %{})
    context = Map.get(criteria, "event_context", %{})
    groups = Map.get(criteria, "groupings", %{})

    with true <- is_binary(term) and String.valid?(term) and byte_size(term) in 1..4096,
         true <-
           is_list(keys) and length(keys) <= 3 and Enum.all?(keys, &Map.has_key?(@keys, &1)),
         true <-
           criteria["order_by"] in [nil, "rank", "recent"] and
             criteria["include_state"] in [nil, true, false],
         {:ok, _} <- ClientFilters.validate(%{"room" => %{"timeline" => filter}}),
         true <- valid_context?(context) and valid_groups?(groups) do
      high = ClientStore.position()
      rooms = accessible_rooms(principal, filter)

      query =
        query(
          principal,
          high,
          rooms,
          Enum.map(keys, &@keys[&1]),
          term,
          criteria["order_by"] || "rank",
          filter
        )

      limit = min(filter["limit"] || 10, 100)
      # The SQL visibility predicate runs before ordering/limits. Rechecking the
      # rendered event excludes redactions and concurrent room revocations.
      results = collect(query, principal, limit, 0, [])

      response = %{
        "count" => length(results),
        "highlights" => highlights(term),
        "results" =>
          Enum.map(results, fn {event, rank} ->
            value = %{"rank" => rank, "result" => event}

            if Map.has_key?(criteria, "event_context"),
              do: Map.put(value, "context", context(principal, device, event, context)),
              else: value
          end)
      }

      response =
        if criteria["include_state"] == true,
          do: Map.put(response, "state", state(principal, results, high)),
          else: response

      response =
        if groups["group_by"],
          do: Map.put(response, "groups", groups(results, groups["group_by"])),
          else: response

      {:ok, %{"search_categories" => %{"room_events" => response}}}
    else
      _ -> {:error, :invalid_param}
    end
  end

  defp run(_, _, _), do: {:error, :invalid_param}

  defp accessible_rooms(principal, filter) do
    Repo.all(from m in RoomMembership, where: m.principal_id == ^principal, select: m.room_id)
    |> Enum.filter(fn room ->
      ref = Identity.room_id(room)

      ClientFilters.include_room?(ref, filter) and is_nil(State.get(room, "m.room.encryption")) and
        match?({:ok, _, _}, ClientRooms.history_access(principal, ref))
    end)
  end

  defp query(principal, high, rooms, types, term, ordering, filter) do
    query =
      from e in RoomEvent,
        where: e.room_id in ^rooms and e.stream_id <= ^high and e.type in ^types,
        where:
          fragment(
            "to_tsvector('english', matrix_search_text(?, ?)) @@ websearch_to_tsquery('english', ?)",
            e.type,
            e.content,
            ^term
          ),
        select:
          {e,
           fragment(
             "ts_rank_cd(to_tsvector('english', matrix_search_text(?, ?)), websearch_to_tsquery('english', ?))",
             e.type,
             e.content,
             ^term
           )}

    query = ClientSync.visible_query(query, principal) |> ClientFilters.sql(filter)

    if ordering == "recent",
      do: from(e in query, order_by: [desc: e.origin_server_ts, desc: e.event_id]),
      else:
        from(e in query,
          order_by: [
            desc:
              fragment(
                "ts_rank_cd(to_tsvector('english', matrix_search_text(?, ?)), websearch_to_tsquery('english', ?))",
                e.type,
                e.content,
                ^term
              ),
            desc: e.origin_server_ts,
            desc: e.event_id
          ]
        )
  end

  defp collect(_, _, 0, _, acc), do: Enum.reverse(acc)

  defp collect(query, principal, left, offset, acc) do
    rows = Repo.all(from e in query, limit: 100, offset: ^offset)

    accepted =
      Enum.flat_map(rows, fn {row, rank} ->
        ref = Identity.room_id(row.room_id)

        with true <- is_nil(State.get(row.room_id, "m.room.encryption")),
             {:ok, event} <- ClientRooms.event(principal, ref, row.event_id),
             true <- not Map.has_key?(event["unsigned"] || %{}, "redacted_because") do
          [{Map.put(event, "room_id", ref), rank}]
        else
          _ -> []
        end
      end)
      |> Enum.take(left)

    acc = Enum.reverse(accepted) ++ acc

    if length(rows) < 100 or length(accepted) == left,
      do: Enum.reverse(acc),
      else: collect(query, principal, left - length(accepted), offset + 100, acc)
  end

  defp context(principal, device, event, options) do
    {:ok, room} = Identity.parse_room_id(event["room_id"])
    token = token(principal, device, room, event)
    before = page(principal, device, room, token, "b", options["before_limit"] || 5)
    after_events = page(principal, device, room, token, "f", options["after_limit"] || 5)
    earlier = List.last(before) || event
    later = List.last(after_events) || event

    value = %{
      "events_before" => before,
      "events_after" => after_events,
      "start" => token(principal, device, room, earlier),
      "end" => token(principal, device, room, later)
    }

    if options["include_profile"] == true,
      do:
        Map.put(
          value,
          "profile_info",
          profiles(room, Enum.reverse(before) ++ [event] ++ after_events)
        ),
      else: value
  end

  defp token(principal, device, room, event) do
    if Graph.room(room),
      do: ClientHistory.before(principal, device, room, event["event_id"]),
      else:
        Cursor.encode(
          "history",
          principal,
          device,
          Repo.get_by!(RoomEvent, event_id: event["event_id"]).stream_id,
          room
        )
  end

  defp page(principal, device, room, token, direction, limit) do
    case ClientSync.history(principal, device, room, %{
           "from" => token,
           "dir" => direction,
           "limit" => limit
         }) do
      {:ok, result} -> result["chunk"]
      _ -> []
    end
  end

  defp profiles(room, events) do
    Map.new(events, fn event ->
      member =
        if Graph.room(room) do
          with record when not is_nil(record) <- Graph.event(event["event_id"]),
               id when is_binary(id) <-
                 record.state_before[Jason.encode!(["m.room.member", event["sender"]])],
               member when not is_nil(member) <- Graph.event(id),
               do: member.pdu["content"]
        else
          record = Repo.get_by!(RoomEvent, event_id: event["event_id"])
          state = ClientSync.state_at(room, record.stream_id)

          member =
            Enum.find(
              state,
              &(&1["type"] == "m.room.member" and &1["state_key"] == event["sender"])
            )

          if member, do: member["content"]
        end

      profile =
        if is_map(member),
          do:
            Map.take(member, ~w(displayname avatar_url))
            |> Map.reject(fn {_, value} -> is_nil(value) end),
          else: %{}

      {event["sender"], profile}
    end)
  end

  defp state(principal, results, high) do
    results
    |> Enum.map(fn {event, _} -> event["room_id"] end)
    |> Enum.uniq()
    |> Enum.flat_map(fn ref ->
      case ClientRooms.history_access(principal, ref) do
        {:ok, room, boundary} -> [{ref, ClientSync.state_at(room.id, min(boundary, high))}]
        _ -> []
      end
    end)
    |> Map.new()
  end

  defp groups(results, group_by) do
    Map.new(group_by, fn %{"key" => key} ->
      values = Enum.group_by(results, fn {event, _} -> event[key] end)

      {key,
       Map.new(values, fn {value, items} ->
         {value,
          %{
            "order" => Enum.find_index(results, &(&1 == hd(items))),
            "results" => Enum.map(items, fn {event, _} -> event["event_id"] end)
          }}
       end)}
    end)
  end

  defp valid_context?(value) when is_map(value),
    do:
      value["include_profile"] in [nil, true, false] and
        Enum.all?(~w(before_limit after_limit), fn key ->
          is_nil(value[key]) or (is_integer(value[key]) and value[key] in 0..100)
        end)

  defp valid_context?(_), do: false

  defp valid_groups?(value) when is_map(value),
    do:
      is_nil(value["group_by"]) or
        (is_list(value["group_by"]) and length(value["group_by"]) <= 2 and
           Enum.all?(value["group_by"], &(is_map(&1) and &1["key"] in ~w(room_id sender))))

  defp valid_groups?(_), do: false

  defp highlights(term),
    do:
      Regex.scan(~r/[\p{L}\p{N}]+/u, term)
      |> List.flatten()
      |> Enum.reject(&(&1 in ~w(OR AND NOT)))
      |> Enum.uniq()
end
