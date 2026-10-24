defmodule LakehouseMatrix.ClientSync do
  @moduledoc "Commit-ordered sync over the same events used by River, including private device and account data."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, Cursor, Events, Identity, Memberships}
  alias LakehouseMatrix.Schema.RoomEvent

  def sync(principal, device, params) do
    params =
      if device == "legacy" and is_binary(params["since"]) and
           Regex.match?(~r/\As[0-9]+\z/, params["since"]),
         do: Map.delete(params, "since"),
         else: params

    with {:ok, since} <- Cursor.decode(params["since"], "sync", principal, device),
         {:ok, filter} <- filter(principal, params["filter"]),
         {:ok, timeout} <- integer(params["timeout"], 0, 0, 30_000) do
      full = is_nil(params["since"]) or params["full_state"] in [true, "true"]
      ClientStore.acknowledge(principal, device, since)
      deadline = System.monotonic_time(:millisecond) + timeout

      poll(
        fn -> snapshot(principal, device, since, full, filter) end,
        deadline,
        not is_nil(params["since"])
      )
    end
  end

  def snapshot(principal, device, since, full, filter \\ %{}) do
    {:ok, result} =
      Repo.transaction(fn ->
        high = ClientStore.lock!() |> delivery_position(principal, device, since)
        joined = Memberships.joined_room_ids(principal)
        invited = Memberships.invited_room_ids(principal)
        left = Memberships.left_room_ids(principal)

        join =
          for room <- joined, into: %{} do
            {Identity.room_id(room),
             room_payload(principal, device, room, since, high, full, filter)}
          end

        join =
          if full, do: join, else: Map.reject(join, fn {_, payload} -> room_empty?(payload) end)

        invite =
          for room <- invited,
              full or membership_changed?(principal, room, since, high),
              into: %{} do
            {Identity.room_id(room),
             %{"invite_state" => %{"events" => stripped(room, high, principal)}}}
          end

        leave =
          for room <- left,
              not full and membership_changed?(principal, room, since, high),
              into: %{} do
            membership = last_membership(principal, room, high)

            {Identity.room_id(room),
             room_payload(principal, device, room, since, membership.stream_id, false, filter)}
          end

        %{
          "next_batch" => Cursor.encode("sync", principal, device, high),
          "rooms" => %{"join" => join, "invite" => invite, "leave" => leave},
          "account_data" => %{
            "events" =>
              ClientStore.account_data(principal, "", if(full, do: 0, else: since), high)
          },
          "to_device" => %{"events" => ClientStore.to_device(principal, device, since, high)},
          "device_lists" => device_lists(principal, since, high),
          "device_one_time_keys_count" => LakehouseMatrix.ClientKeys.counts(principal, device),
          "device_unused_fallback_key_types" =>
            LakehouseMatrix.ClientKeys.unused_fallback(principal, device),
          "presence" => %{"events" => []}
        }
      end)

    {:ok, result}
  end

  def room_payload(principal, device, room, since, high, full, filter \\ %{}) do
    limit = get_in(filter, ["room", "timeline", "limit"]) || 20
    limit = if is_integer(limit), do: min(max(limit, 0), 100), else: 20
    lower = if full, do: 0, else: since
    rows = timeline(room, lower, high, limit + 1, principal)
    limited = length(rows) > limit
    rows = Enum.take(rows, limit) |> Enum.reverse()
    # State in /sync describes the point immediately before its timeline.
    boundary =
      case rows do
        [e | _] -> e.stream_id - 1
        [] -> high
      end

    state = state_at(room, boundary)

    state =
      if full or joined_since?(principal, room, since, high),
        do: state,
        else: Enum.filter(state, fn event -> event_position(event["event_id"]) > since end)

    state = filter_events(state, get_in(filter, ["room", "state"]) || %{})

    events =
      rows
      |> Enum.map(&Events.to_client_event/1)
      |> filter_events(get_in(filter, ["room", "timeline"]) || %{})

    account = ClientStore.account_data(principal, Identity.room_id(room), lower, high)

    %{
      "timeline" => %{
        "events" => events,
        "limited" => limited,
        "prev_batch" => Cursor.encode("history", principal, device, boundary + 1, room)
      },
      "state" => %{"events" => state},
      "account_data" => %{"events" => account},
      "ephemeral" => %{"events" => receipts(principal, room, lower, high)},
      "summary" => %{
        "m.joined_member_count" => Memberships.member_count(room),
        "m.invited_member_count" => Memberships.invited_count(room)
      }
    }
  end

  def timeline(room, since, high, limit, principal) do
    query =
      from e in RoomEvent,
        where: e.room_id == ^room and e.stream_id > ^since and e.stream_id <= ^high,
        order_by: [desc: e.stream_id],
        limit: ^limit

    Repo.all(visible_query(query, principal))
  end

  def visible_query(query, principal) do
    user = mxid(principal)

    from e in query,
      where:
        (e.type == "m.room.member" and e.state_key == ^user) or
          fragment(
            """
            CASE COALESCE((SELECT h.content->>'history_visibility' FROM room_events h
              WHERE h.room_id = ? AND h.type = 'm.room.history_visibility' AND h.stream_id <= ?
              ORDER BY h.stream_id DESC LIMIT 1), 'shared')
            WHEN 'joined' THEN COALESCE((SELECT m.content->>'membership' FROM room_events m
              WHERE m.room_id = ? AND m.type = 'm.room.member' AND m.state_key = ? AND m.stream_id <= ?
              ORDER BY m.stream_id DESC LIMIT 1), '') = 'join'
            WHEN 'invited' THEN COALESCE((SELECT m.content->>'membership' FROM room_events m
              WHERE m.room_id = ? AND m.type = 'm.room.member' AND m.state_key = ? AND m.stream_id <= ?
              ORDER BY m.stream_id DESC LIMIT 1), '') IN ('join', 'invite')
            ELSE TRUE END
            """,
            e.room_id,
            e.stream_id,
            e.room_id,
            ^user,
            e.stream_id,
            e.room_id,
            ^user,
            e.stream_id
          )
  end

  def state_at(room, high) do
    Repo.all(
      from e in RoomEvent,
        where: e.room_id == ^room and not is_nil(e.state_key) and e.stream_id <= ^high,
        distinct: [e.type, e.state_key],
        order_by: [e.type, e.state_key, desc: e.stream_id]
    )
    |> Enum.map(&Events.to_client_event/1)
  end

  def stripped(room, high, principal),
    do:
      state_at(room, high)
      |> Enum.filter(
        &(&1["type"] in ~w(m.room.create m.room.name m.room.avatar m.room.topic m.room.join_rules m.room.canonical_alias m.room.member m.room.encryption))
      )
      |> Enum.filter(&(&1["type"] != "m.room.member" or &1["state_key"] == mxid(principal)))
      |> Enum.map(&Map.take(&1, ~w(type state_key content sender)))

  def history(principal, device, room, params) do
    with true <- Memberships.joined?(room, principal),
         {:ok, limit} <- integer(params["limit"], 10, 0, 100),
         true <- params["dir"] in [nil, "b", "f"],
         {:ok, from} <- history_cursor(params["from"], principal, device, room),
         {:ok, to} <- history_cursor(params["to"], principal, device, room) do
      direction = params["dir"] || "b"
      high = ClientStore.position()
      from = if params["from"], do: from, else: if(direction == "b", do: high + 1, else: 0)
      query = from e in RoomEvent, where: e.room_id == ^room and e.stream_id <= ^high
      query = visible_query(query, principal)

      query =
        if direction == "b",
          do: from(e in query, where: e.stream_id < ^from, order_by: [desc: e.stream_id]),
          else: from(e in query, where: e.stream_id > ^from, order_by: [asc: e.stream_id])

      query =
        if params["to"],
          do:
            if(direction == "b",
              do: from(e in query, where: e.stream_id > ^to),
              else: from(e in query, where: e.stream_id < ^to)
            ),
          else: query

      rows = Repo.all(from e in query, limit: ^(limit + 1))
      chunk = Enum.take(rows, limit)

      response = %{
        "start" => params["from"] || Cursor.encode("history", principal, device, from, room),
        "chunk" => Enum.map(chunk, &Events.to_client_event/1),
        "state" => []
      }

      response =
        if length(rows) > limit and chunk != [],
          do:
            Map.put(
              response,
              "end",
              Cursor.encode("history", principal, device, List.last(chunk).stream_id, room)
            ),
          else: response

      {:ok, response}
    else
      false -> {:error, :forbidden}
      error -> error
    end
  end

  def history_cursor(nil, _, _, _), do: {:ok, 0}

  def history_cursor(token, principal, device, room) do
    case Cursor.decode(token, "history", principal, device, room) do
      {:ok, n} -> {:ok, n}
      _ -> Cursor.decode(token, "sync", principal, device)
    end
  end

  def filter(_principal, nil), do: {:ok, %{}}

  def filter(principal, value) when is_binary(value) and byte_size(value) <= 65_536 do
    if String.starts_with?(value, "{") do
      case Jason.decode(value) do
        {:ok, map} when is_map(map) -> validate_filter(map)
        _ -> {:error, :invalid_param}
      end
    else
      case Integer.parse(value) do
        {id, ""} ->
          case Repo.one(
                 from f in "matrix_filters",
                   where: f.id == ^id and f.principal_id == type(^principal, :binary_id),
                   select: f.content
               ) do
            nil -> {:error, :not_found}
            filter -> validate_filter(filter)
          end

        _ ->
          {:error, :invalid_param}
      end
    end
  end

  def filter(_, _), do: {:error, :invalid_param}

  def validate_filter(filter) when is_map(filter) do
    room = filter["room"] || %{}

    valid =
      is_map(room) and
        Enum.all?(~w(timeline state), fn field ->
          config = room[field] || %{}

          is_map(config) and
            (is_nil(config["limit"]) or (is_integer(config["limit"]) and config["limit"] >= 0)) and
            Enum.all?(~w(types not_types senders not_senders), fn key ->
              values = config[key]

              is_nil(values) or
                (is_list(values) and length(values) <= 100 and Enum.all?(values, &is_binary/1))
            end)
        end)

    if valid, do: {:ok, filter}, else: {:error, :invalid_param}
  end

  def validate_filter(_), do: {:error, :invalid_param}

  def filter_events(events, filter) do
    Enum.filter(events, fn event ->
      types = filter["types"]
      not_types = filter["not_types"] || []

      (is_nil(types) or (is_list(types) and Enum.any?(types, &matches_type?(event["type"], &1)))) and
        is_list(not_types) and not Enum.any?(not_types, &matches_type?(event["type"], &1)) and
        (is_nil(filter["senders"]) or event["sender"] in filter["senders"]) and
        event["sender"] not in (filter["not_senders"] || [])
    end)
  end

  defp matches_type?(type, pattern) when is_binary(pattern),
    do:
      type == pattern or
        (String.ends_with?(pattern, "*") and
           String.starts_with?(type, String.trim_trailing(pattern, "*")))

  defp matches_type?(_, _), do: false

  def integer(nil, default, _, _), do: {:ok, default}
  def integer(n, _, min, max) when is_integer(n) and n >= min, do: {:ok, Kernel.min(n, max)}

  def integer(s, default, min, max) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} -> integer(n, default, min, max)
      _ -> {:error, :invalid_param}
    end
  end

  def integer(_, _, _, _), do: {:error, :invalid_param}

  defp poll(fun, deadline, wait) do
    {:ok, payload} = fun.()
    remaining = deadline - System.monotonic_time(:millisecond)

    if wait and empty?(payload) and remaining > 0 do
      Process.sleep(min(remaining, 200))
      poll(fun, deadline, true)
    else
      {:ok, payload}
    end
  end

  defp empty?(p),
    do:
      p["rooms"] == %{"join" => %{}, "invite" => %{}, "leave" => %{}} and
        p["account_data"]["events"] == [] and p["to_device"]["events"] == [] and
        p["device_lists"]["changed"] == []

  defp room_empty?(p),
    do:
      p["timeline"]["events"] == [] and p["state"]["events"] == [] and
        p["account_data"]["events"] == [] and p["ephemeral"]["events"] == []

  defp membership_changed?(principal, room, since, high) do
    Repo.exists?(
      from e in RoomEvent,
        where:
          e.room_id == ^room and e.type == "m.room.member" and e.state_key == ^mxid(principal) and
            e.stream_id > ^since and e.stream_id <= ^high
    )
  end

  defp joined_since?(principal, room, since, high) do
    Repo.exists?(
      from e in RoomEvent,
        where:
          e.room_id == ^room and e.type == "m.room.member" and e.state_key == ^mxid(principal) and
            e.stream_id > ^since and e.stream_id <= ^high and
            fragment("?->>'membership' = 'join'", e.content)
    )
  end

  defp last_membership(principal, room, high),
    do:
      Repo.one(
        from e in RoomEvent,
          where:
            e.room_id == ^room and e.type == "m.room.member" and e.state_key == ^mxid(principal) and
              e.stream_id <= ^high,
          order_by: [desc: e.stream_id],
          limit: 1
      )

  defp event_position(id),
    do: Repo.one(from e in RoomEvent, where: e.event_id == ^id, select: e.stream_id) || 0

  defp mxid(principal),
    do: Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

  def delivery_position(high, principal, device, since) do
    pending =
      Repo.all(
        from t in "matrix_to_device",
          where:
            t.principal_id == type(^principal, :binary_id) and t.device_id == ^device and
              t.stream_id > ^since and t.stream_id <= ^high,
          order_by: t.stream_id,
          limit: 101,
          select: t.stream_id
      )

    if length(pending) > 100, do: Enum.at(pending, 99), else: high
  end

  def device_lists(principal, since, high) do
    rooms = Memberships.joined_room_ids(principal)

    ids =
      Repo.all(
        from m in LakehouseMatrix.Schema.RoomMembership,
          where:
            m.room_id in ^rooms and fragment("?->>'membership' = 'join'", m.membership_state),
          select: m.principal_id
      )

    changed =
      Repo.all(
        from d in "matrix_devices",
          join: p in LakehouseIam.Schema.Principal,
          on: d.principal_id == p.id,
          where: p.id in ^ids and d.stream_id > ^since and d.stream_id <= ^high,
          distinct: p.username,
          select: p.username
      )
      |> Enum.map(&Identity.user_id/1)

    %{"changed" => changed, "left" => []}
  end

  def receipts(principal, room, since, high) do
    entries =
      Repo.all(
        from r in "matrix_receipts",
          join: p in LakehouseIam.Schema.Principal,
          on: r.principal_id == p.id,
          where:
            r.room_id == type(^room, :binary_id) and r.stream_id > ^since and r.stream_id <= ^high and
              (r.type != "m.read.private" or p.id == ^principal),
          select: {r.event_id, r.type, p.username, r.data}
      )

    content =
      Enum.reduce(entries, %{}, fn {event, type, user, data}, acc ->
        Map.update(acc, event, %{type => %{Identity.user_id(user) => data}}, fn types ->
          Map.update(
            types,
            type,
            %{Identity.user_id(user) => data},
            &Map.put(&1, Identity.user_id(user), data)
          )
        end)
      end)

    if entries == [], do: [], else: [%{"type" => "m.receipt", "content" => content}]
  end
end
