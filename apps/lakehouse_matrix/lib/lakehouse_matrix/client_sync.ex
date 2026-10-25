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
         {:ok, timeout} <- integer(params["timeout"], 0, 0, 30_000),
         true <-
           params["use_state_after"] in [nil, true, false, "true", "false"] and
             params["set_presence"] in [nil, "online", "offline", "unavailable"] do
      filter = Map.put(filter, "_use_state_after", params["use_state_after"] in [true, "true"])
      full = is_nil(params["since"]) or params["full_state"] in [true, "true"]

      LakehouseMatrix.Ephemeral.set_presence(
        principal,
        %{"presence" => params["set_presence"] || "online"},
        true
      )

      LakehouseMatrix.Ephemeral.expire()
      ClientStore.acknowledge(principal, device, since)
      deadline = System.monotonic_time(:millisecond) + timeout

      poll(
        fn -> snapshot(principal, device, since, full, filter) end,
        deadline,
        not is_nil(params["since"])
      )
    else
      false -> {:error, :invalid_param}
      error -> error
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
          "presence" => %{
            "events" =>
              LakehouseMatrix.Ephemeral.presence_events(
                principal,
                if(full, do: 0, else: since),
                high
              )
          }
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

    state_boundary = if filter["_use_state_after"], do: high, else: boundary
    state = state_at(room, state_boundary)

    state =
      if full or joined_since?(principal, room, since, high),
        do: state,
        else:
          Enum.filter(state, fn event ->
            state_position(room, event["event_id"], state_boundary) > since
          end)

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
      "account_data" => %{"events" => account},
      "ephemeral" => %{
        "events" =>
          receipts(principal, room, lower, high) ++
            LakehouseMatrix.Ephemeral.typing_events(room, lower, high)
      },
      "summary" => %{
        "m.joined_member_count" => Memberships.member_count(room),
        "m.invited_member_count" => Memberships.invited_count(room)
      }
    }
    |> Map.put(if(filter["_use_state_after"], do: "state_after", else: "state"), %{
      "events" => state
    })
  end

  def timeline(room, since, high, limit, principal) do
    query =
      from e in RoomEvent,
        where:
          e.room_id == ^room and e.timeline_visible == true and e.stream_id > ^since and
            e.stream_id <= ^high,
        order_by: [desc: e.stream_id],
        limit: ^limit

    Repo.all(visible_query(query, principal))
  end

  def visible_query(query, principal) do
    user = mxid(principal)
    history_key = Jason.encode!(["m.room.history_visibility", ""])
    member_key = Jason.encode!(["m.room.member", user])

    native =
      dynamic(
        [e],
        fragment(
          "EXISTS (SELECT 1 FROM matrix_protocol_rooms r WHERE r.local_room_id = ?)",
          e.room_id
        )
      )

    native_visible =
      dynamic(
        [e],
        fragment(
          """
          (SELECT CASE COALESCE(h.pdu->'content'->>'history_visibility', 'shared')
            WHEN 'world_readable' THEN TRUE
            WHEN 'joined' THEN COALESCE(m.pdu->'content'->>'membership', '') = 'join'
            WHEN 'invited' THEN COALESCE(m.pdu->'content'->>'membership', '') IN ('join','invite')
            ELSE COALESCE(m.pdu->'content'->>'membership', '') = 'join' OR EXISTS (
              SELECT 1 FROM matrix_state_changes c JOIN matrix_pdus j ON j.event_id = c.event_id
              WHERE c.local_room_id = ev.local_room_id AND c.type = 'm.room.member' AND c.state_key = ?
                AND c.stream_id >= ? AND j.pdu->'content'->>'membership' = 'join') END
           FROM matrix_pdus ev
           LEFT JOIN matrix_pdus h ON h.event_id = ev.state_before->>?
           LEFT JOIN matrix_pdus m ON m.event_id = ev.state_before->>?
           WHERE ev.event_id = ?)
          """,
          ^user,
          e.stream_id,
          ^history_key,
          ^member_key,
          e.event_id
        )
      )

    legacy_visible =
      dynamic(
        [e],
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
      )

    condition =
      dynamic(
        [e],
        (e.type == "m.room.member" and e.state_key == ^user) or
          (^native and ^native_visible) or (not (^native) and ^legacy_visible)
      )

    condition =
      dynamic(
        [e],
        ^condition and
          (not (^native) or e.type != "m.room.redaction" or
             fragment(
               "EXISTS (SELECT 1 FROM matrix_pdus r WHERE r.event_id = ? AND r.redaction_applied)",
               e.event_id
             ))
      )

    from e in query, where: ^condition
  end

  def state_at(room, high) do
    if LakehouseMatrix.Protocol.Graph.room(room) do
      ids = LakehouseMatrix.Protocol.Graph.state_at_stream(room, high) |> Map.values()

      Repo.all(
        from e in RoomEvent,
          where:
            e.event_id in ^ids and
              (e.type != "m.room.redaction" or
                 fragment(
                   "EXISTS (SELECT 1 FROM matrix_pdus r WHERE r.event_id = ? AND r.redaction_applied)",
                   e.event_id
                 )),
          order_by: [e.type, e.state_key]
      )
      |> Enum.map(&Events.to_client_event/1)
    else
      Repo.all(
        from e in RoomEvent,
          where: e.room_id == ^room and not is_nil(e.state_key) and e.stream_id <= ^high,
          distinct: [e.type, e.state_key],
          order_by: [e.type, e.state_key, desc: e.stream_id]
      )
      |> Enum.map(&Events.to_client_event/1)
    end
  end

  def state_position(room, id, high) do
    if LakehouseMatrix.Protocol.Graph.room(room),
      do: LakehouseMatrix.Protocol.Graph.state_position(room, id, high),
      else: event_position(id)
  end

  def stripped(room, high, principal) do
    case LakehouseMatrix.Federation.Invites.pending(room, mxid(principal)) do
      %{state: %{"events" => events}} ->
        events

      nil ->
        state_at(room, high)
        |> Enum.filter(
          &(&1["type"] in ~w(m.room.create m.room.name m.room.avatar m.room.topic m.room.join_rules m.room.canonical_alias m.room.member m.room.encryption))
        )
        |> Enum.filter(&(&1["type"] != "m.room.member" or &1["state_key"] == mxid(principal)))
        |> Enum.map(&Map.take(&1, ~w(type state_key content sender)))
    end
  end

  def history(principal, device, room, params) do
    with true <- Memberships.joined?(room, principal),
         {:ok, limit} <- integer(params["limit"], 10, 0, 100),
         true <- params["dir"] in [nil, "b", "f"],
         {:ok, from} <- history_cursor(params["from"], principal, device, room),
         {:ok, to} <- history_cursor(params["to"], principal, device, room) do
      direction = params["dir"] || "b"
      high = ClientStore.position()
      from = if params["from"], do: from, else: if(direction == "b", do: high + 1, else: 0)

      query =
        from e in RoomEvent,
          where: e.room_id == ^room and e.timeline_visible == true and e.stream_id <= ^high

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
        p["device_lists"]["changed"] == [] and p["device_lists"]["left"] == [] and
        p["presence"]["events"] == []

  defp room_empty?(p),
    do:
      p["timeline"]["events"] == [] and (p["state"] || p["state_after"])["events"] == [] and
        p["account_data"]["events"] == [] and p["ephemeral"]["events"] == []

  defp membership_changed?(principal, room, since, high) do
    query = membership_events(principal, room)
    Repo.exists?(from e in subquery(query), where: e.stream_id > ^since and e.stream_id <= ^high)
  end

  defp joined_since?(principal, room, since, high) do
    query = membership_events(principal, room)

    Repo.exists?(
      from e in subquery(query),
        where:
          e.stream_id > ^since and e.stream_id <= ^high and
            fragment("?->>'membership' = 'join'", e.content)
    )
  end

  defp last_membership(principal, room, high) do
    query = membership_events(principal, room)

    Repo.one(
      from e in subquery(query),
        where: e.stream_id <= ^high,
        order_by: [desc: e.stream_id],
        limit: 1
    )
  end

  defp membership_events(principal, room) do
    user = mxid(principal)

    if LakehouseMatrix.Protocol.Graph.room(room) do
      from c in "matrix_state_changes",
        join: p in LakehouseMatrix.Schema.Pdu,
        on: p.event_id == c.event_id,
        where:
          c.local_room_id == type(^room, :binary_id) and c.type == "m.room.member" and
            c.state_key == ^user,
        select: %{stream_id: c.stream_id, content: fragment("?->'content'", p.pdu)}
    else
      from e in RoomEvent,
        where: e.room_id == ^room and e.type == "m.room.member" and e.state_key == ^user,
        select: %{stream_id: e.stream_id, content: e.content}
    end
  end

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
    before = shared_users(principal, since)
    current = shared_users(principal, high)

    changed =
      Repo.all(
        from c in "matrix_device_changes",
          where:
            c.user_id in ^MapSet.to_list(current) and c.stream_id > ^since and
              c.stream_id <= ^high,
          distinct: c.user_id,
          select: c.user_id
      )
      |> MapSet.new()

    %{
      "changed" =>
        MapSet.union(changed, MapSet.difference(current, before))
        |> MapSet.to_list()
        |> Enum.sort(),
      "left" => MapSet.difference(before, current) |> MapSet.to_list() |> Enum.sort()
    }
  end

  defp shared_users(principal, position) do
    own = mxid(principal)

    rooms =
      Repo.all(
        from m in LakehouseMatrix.Schema.RoomMembership,
          where: m.principal_id == ^principal,
          select: m.room_id
      )

    Enum.reduce(rooms, MapSet.new([own]), fn room, users ->
      state = state_at(room, position)

      joined =
        Enum.any?(
          state,
          &(&1["type"] == "m.room.member" and &1["state_key"] == own and
              &1["content"]["membership"] == "join")
        )

      if joined do
        members =
          for e <- state,
              e["type"] == "m.room.member" and e["content"]["membership"] == "join",
              do: e["state_key"]

        MapSet.union(users, MapSet.new(members))
      else
        users
      end
    end)
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

    entries =
      Enum.map(entries, fn {event, type, username, data} ->
        {event, type, Identity.user_id(username), data}
      end)

    remote =
      Repo.all(
        from r in "matrix_remote_receipts",
          where:
            r.local_room_id == type(^room, :binary_id) and
              r.stream_id > ^since and r.stream_id <= ^high,
          select: {r.event_id, r.type, r.user_id, r.data}
      )

    entries = entries ++ remote

    content =
      Enum.reduce(entries, %{}, fn {event, type, user, data}, acc ->
        Map.update(acc, event, %{type => %{user => data}}, fn types ->
          Map.update(
            types,
            type,
            %{user => data},
            &Map.put(&1, user, data)
          )
        end)
      end)

    if entries == [], do: [], else: [%{"type" => "m.receipt", "content" => content}]
  end
end
