defmodule LakehouseMatrix.SlidingSync do
  @moduledoc "Native MSC4186 sliding windows over River's rooms, with durable per-device connection state."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientHistory, ClientStore, ClientSync, Cursor, Identity}
  alias LakehouseMatrix.Schema.RoomEvent

  def sync(principal, device, params, format \\ :msc4186) do
    with :ok <- validate(params),
         {:ok, previous} <- connection(principal, device, params),
         {:ok, timeout} <- ClientSync.integer(params["timeout"], 0, 0, 30_000) do
      format = request_format(format, params, previous)

      LakehouseMatrix.Ephemeral.set_presence(
        principal,
        %{"presence" => params["set_presence"] || "online"},
        true
      )

      LakehouseMatrix.Ephemeral.expire()
      deadline = System.monotonic_time(:millisecond) + if(previous, do: timeout, else: 0)

      request =
        if format == :msc4186,
          do: Map.merge((previous && previous.state["request"]) || %{}, params),
          else: params

      with {:ok, device_since} <-
             Cursor.decode(
               get_in(request, ["extensions", "to_device", "since"]),
               "to_device",
               principal,
               device
             ) do
        poll(
          principal,
          device,
          Map.put(request, "_to_device_since", device_since),
          previous,
          format,
          deadline
        )
      end
    end
  end

  # The unstable endpoint is also used by deployed clients with the older
  # tuple/ranges schema. Keep its connection semantics while accepting the
  # current proposal's schema on either endpoint.
  defp request_format(:v4, _, _), do: :v4

  defp request_format(_, params, previous) do
    configs =
      Map.values(params["lists"] || %{}) ++ Map.values(params["room_subscriptions"] || %{})

    current =
      Enum.any?(
        configs,
        &(is_map(&1) and (Map.has_key?(&1, "range") or is_map(&1["required_state"])))
      )

    if current or (previous && previous.state["format"] == "v4"), do: :v4, else: :msc4186
  end

  def position(token, principal, device) when is_binary(token) and byte_size(token) <= 2048 do
    case Repo.one(
           from c in "matrix_sync_connections",
             where:
               c.principal_id == type(^principal, :binary_id) and c.device_id == ^device and
                 c.token == ^token and c.expires_at > ^ClientStore.now(),
             select: c.position
         ) do
      nil -> {:error, :invalid_cursor}
      position -> {:ok, position}
    end
  end

  def position(_, _, _), do: {:error, :invalid_cursor}

  defp connection(_, _, %{"pos" => nil}), do: {:ok, nil}

  defp connection(principal, device, params) do
    if params["pos"] do
      row =
        Repo.one(
          from c in "matrix_sync_connections",
            where:
              c.principal_id == type(^principal, :binary_id) and
                c.device_id == ^device and c.conn_id == ^(params["conn_id"] || "") and
                c.token == ^params["pos"] and c.expires_at > ^ClientStore.now(),
            select: %{id: c.id, position: c.position, state: c.state}
        )

      if row, do: {:ok, row}, else: {:error, :unknown_pos}
    else
      {:ok, nil}
    end
  end

  defp poll(principal, device, params, previous, format, deadline) do
    with {:ok, {response, state, high}} <-
           Repo.transaction(fn -> build(principal, device, params, previous, format) end) do
      remaining = deadline - System.monotonic_time(:millisecond)

      if not is_nil(previous) and remaining > 0 and map_size(response["rooms"]) == 0 and
           extensions_empty?(response["extensions"]) and
           response["lists"] == (previous.state["lists"] || %{}) do
        Process.sleep(min(remaining, 200))
        poll(principal, device, params, previous, format, deadline)
      else
        token = ClientStore.random()

        Repo.transaction(fn ->
          ClientStore.lock!()
          LakehouseMatrix.AccountModeration.require!(principal, :read)

          Repo.delete_all(
            from c in "matrix_sync_connections", where: c.expires_at <= ^ClientStore.now()
          )

          # Keep the requested position for cancelled/retried requests. Older states
          # for this connection can be retired once the client acknowledges its pos.
          if previous do
            Repo.delete_all(
              from c in "matrix_sync_connections",
                where:
                  c.principal_id == type(^principal, :binary_id) and c.device_id == ^device and
                    c.conn_id == ^(params["conn_id"] || "") and c.id < ^previous.id
            )

            if get_in(params, ["extensions", "to_device", "enabled"]) == true do
              ClientStore.acknowledge(principal, device, params["_to_device_since"])
            end
          end

          Repo.insert_all("matrix_sync_connections", [
            %{
              principal_id: ClientStore.dump_id(principal),
              device_id: device,
              conn_id: params["conn_id"] || "",
              token: token,
              position: high,
              state: state,
              expires_at: DateTime.add(ClientStore.now(), 1800, :second)
            }
          ])

          Map.put(response, "pos", token)
        end)
      end
    end
  end

  defp build(principal, device, params, previous, format) do
    high = ClientStore.lock!()
    LakehouseMatrix.AccountModeration.require!(principal, :read)
    since = if previous, do: previous.position, else: 0
    known = (previous && previous.state["rooms"]) || %{}
    memberships = ClientSync.memberships_at(principal, high)
    joined = memberships.join
    invited = memberships.invite
    knocked = memberships.knock
    user = user_id(principal)

    departed =
      Enum.filter(memberships.leave, fn id ->
        membership = ClientSync.last_membership(principal, id, high)

        Map.has_key?(known, Identity.room_id(id)) or
          (membership.sender != user and ClientSync.ever_joined?(principal, id, high))
      end)

    listed = Enum.uniq(joined ++ invited ++ knocked ++ departed)

    available =
      Enum.uniq(
        listed ++ Enum.filter(memberships.leave, &ClientSync.ever_joined?(principal, &1, high))
      )

    activity =
      Repo.all(
        from e in RoomEvent,
          where: e.room_id in ^available and e.stream_id <= ^high,
          group_by: e.room_id,
          select: {e.room_id, max(e.stream_id)}
      )
      |> Map.new()
      |> Map.merge(LakehouseMatrix.Protocol.Graph.activity(available, high), fn _, event, state ->
        max(event, state)
      end)

    activity =
      Enum.reduce(memberships.leave, activity, fn id, acc ->
        Map.put(acc, id, ClientSync.last_membership(principal, id, high).stream_id)
      end)

    ordered = Enum.sort_by(listed, &{-(activity[&1] || 0), &1})
    direct = ClientStore.get_data(principal, "", "m.direct") || %{}
    direct_rooms = direct |> Map.values() |> Enum.filter(&is_list/1) |> List.flatten()

    {lists, configs, room_lists} =
      Enum.reduce(params["lists"] || %{}, {%{}, %{}, %{}}, fn {name, config},
                                                              {lists, configs, memberships} ->
        if is_nil(config) do
          {lists, configs, memberships}
        else
          ids =
            Enum.filter(
              ordered,
              &matches?(&1, config["filters"] || %{}, principal, direct_rooms, invited, high)
            )

          window =
            if not Map.has_key?(config, "range") and not Map.has_key?(config, "ranges") do
              ids
            else
              ranges(config)
              |> Enum.flat_map(fn [lo, hi] -> Enum.slice(ids, lo, hi - lo + 1) end)
              |> Enum.uniq()
            end

          configs =
            Enum.reduce(window, configs, &Map.update(&2, &1, [config], fn v -> [config | v] end))

          memberships =
            Enum.reduce(window, memberships, &Map.update(&2, &1, [name], fn v -> [name | v] end))

          {Map.put(lists, name, %{"count" => length(ids)}), configs, memberships}
        end
      end)

    configs =
      Enum.reduce(params["room_subscriptions"] || %{}, configs, fn {ref, config}, acc ->
        case Identity.parse_room_id(ref) do
          {:ok, id} ->
            if id in available and is_map(config),
              do: Map.update(acc, id, [config], &[config | &1]),
              else: acc

          _ ->
            acc
        end
      end)

    {rooms, known} =
      Enum.reduce(configs, {%{}, known}, fn {id, configs}, {rooms, known} ->
        ref = Identity.room_id(id)
        old = known[ref]

        config = %{
          "timeline_limit" => Enum.max(Enum.map(configs, &(&1["timeline_limit"] || 0))),
          "state" => Enum.map(configs, &(&1["required_state"] || []))
        }

        member = ClientSync.last_membership(principal, id, high)
        membership = member.content["membership"]
        initial = is_nil(old) or (membership == "join" and old["membership"] not in [nil, "join"])
        expanded = old && config["timeline_limit"] > old["config"]["timeline_limit"]
        changed_config = old && config != old["config"]
        last = if old, do: old["position"], else: 0
        data_changed = ClientStore.account_data(principal, "", since, high) != []

        if initial or expanded or changed_config or (activity[id] || 0) > last or data_changed or
             LakehouseMatrix.Notifications.changed?(principal, id, last, high) do
          payload =
            if membership in ["invite", "knock"] or
                 not ClientSync.ever_joined?(principal, id, high) do
              key =
                if format == :v4,
                  do: "stripped_state",
                  else: if(membership == "knock", do: "knock_state", else: "invite_state")

              %{
                key => ClientSync.stripped(id, high, principal),
                "membership" => membership,
                "initial" => initial
              }
            else
              lower = if initial or expanded, do: 0, else: last
              room_high = if membership in ["leave", "ban"], do: member.stream_id, else: high
              limit = config["timeline_limit"]
              rows = ClientSync.timeline(id, lower, room_high, limit + 1, principal)
              limited = length(rows) > limit
              rows = rows |> Enum.take(limit) |> Enum.reverse()
              timeline = Enum.map(rows, &LakehouseMatrix.Events.to_client_event/1)

              timeline =
                if limited,
                  do: LakehouseMatrix.ClientRelations.bundle(principal, id, timeline, room_high),
                  else: timeline

              state = ClientSync.state_at(id, room_high)

              required =
                Enum.filter(state, fn event ->
                  Enum.any?(config["state"], &required?(event, &1, principal, timeline)) or
                    (not limited and not initial and event["type"] == "m.room.member" and
                       Enum.any?(config["state"], &(is_map(&1) and &1["lazy_members"] == true)) and
                       ClientSync.state_position(id, event["event_id"], room_high) > last)
                end)

              required =
                if initial or changed_config,
                  do: required,
                  else:
                    Enum.filter(required, fn e ->
                      ClientSync.state_position(id, e["event_id"], room_high) > last or
                        (e["type"] == "m.room.member" and
                           Enum.any?(
                             timeline,
                             &(&1["sender"] == e["state_key"] or &1["state_key"] == e["state_key"])
                           ))
                    end)

              before = if rows == [], do: room_high, else: hd(rows).stream_id

              removed =
                removed_state(id, last, room_high, config["state"], principal, timeline, initial)

              %{
                "initial" => initial,
                "notification_count" =>
                  LakehouseMatrix.Notifications.counts(principal, id, room_high)[
                    "notification_count"
                  ],
                "highlight_count" =>
                  LakehouseMatrix.Notifications.counts(principal, id, room_high)[
                    "highlight_count"
                  ],
                "membership" => membership,
                "name" => state_content(state, "m.room.name")["name"],
                "avatar" => state_content(state, "m.room.avatar")["url"],
                "is_dm" => ref in direct_rooms,
                "joined_count" =>
                  Enum.count(
                    state,
                    &(&1["type"] == "m.room.member" and &1["content"]["membership"] == "join")
                  ),
                "invited_count" =>
                  Enum.count(
                    state,
                    &(&1["type"] == "m.room.member" and &1["content"]["membership"] == "invite")
                  ),
                "bump_stamp" => activity[id] || 0,
                "timeline" => timeline,
                "required_state" => required ++ removed,
                "limited" => limited,
                "num_live" =>
                  if(previous, do: Enum.count(rows, &(&1.stream_id > since)), else: 0),
                "prev_batch" =>
                  if(LakehouseMatrix.Protocol.Graph.room(id),
                    do:
                      if(rows == [],
                        do: ClientHistory.at_stream(principal, device, id, room_high),
                        else: ClientHistory.before(principal, device, id, hd(rows).event_id)
                      ),
                    else: Cursor.encode("history", principal, device, before, id)
                  )
              }
              |> then(fn p ->
                if expanded,
                  do:
                    Map.put(
                      p,
                      if(format == :v4,
                        do: "expanded_timeline",
                        else: "unstable_expanded_timeline"
                      ),
                      true
                    ),
                  else: p
              end)
            end

          payload =
            if room_lists[id], do: Map.put(payload, "lists", room_lists[id]), else: payload

          {Map.put(rooms, ref, payload),
           Map.put(known, ref, %{
             "position" => high,
             "config" => config,
             "membership" => membership
           })}
        else
          {rooms, known}
        end
      end)

    # Membership revocation must be delivered even after a room falls out of the
    # currently authorized window. Only the user's own leave event is included.
    rooms =
      Enum.reduce(known, rooms, fn {ref, _}, acc ->
        with {:ok, id} <- Identity.parse_room_id(ref),
             false <- id in listed,
             event when not is_nil(event) <-
               Repo.one(
                 from e in RoomEvent,
                   where:
                     e.room_id == ^id and e.type == "m.room.member" and
                       e.state_key == ^user_id(principal) and e.stream_id > ^since and
                       e.stream_id <= ^high,
                   order_by: [desc: e.stream_id],
                   limit: 1
               ),
             true <- event.content["membership"] in ["leave", "ban"] do
          if ClientStore.room_forgotten?(principal, id, high),
            do: acc,
            else:
              Map.put(acc, ref, %{
                "membership" => event.content["membership"],
                "timeline" => [LakehouseMatrix.Events.to_client_event(event)],
                "num_live" => 1
              })
        else
          _ -> acc
        end
      end)

    extensions =
      extensions(
        params["extensions"] || %{},
        principal,
        device,
        since,
        high,
        Enum.map(Map.keys(configs), &Identity.room_id/1),
        previous,
        params["_to_device_since"]
      )

    response = %{"rooms" => rooms, "lists" => lists, "extensions" => extensions}

    state = %{
      "rooms" => known,
      "lists" => lists,
      "format" => if(format == :v4, do: "v4", else: "msc4186"),
      "request" => Map.drop(params, ["pos", "timeout", "_to_device_since"])
    }

    {response, state, high}
  end

  defp removed_state(_, _, _, _, _, _, true), do: []

  defp removed_state(room, since, high, configs, principal, timeline, false) do
    if LakehouseMatrix.Protocol.Graph.room(room) do
      Repo.all(
        from c in "matrix_state_changes",
          where:
            c.local_room_id == type(^room, :binary_id) and c.stream_id > ^since and
              c.stream_id <= ^high,
          distinct: [c.type, c.state_key],
          order_by: [c.type, c.state_key, desc: c.stream_id],
          select: %{type: c.type, key: c.state_key, event: c.event_id}
      )
      |> Enum.filter(&is_nil(&1.event))
      |> Enum.map(&%{"type" => &1.type, "state_key" => &1.key})
      |> Enum.filter(fn stub -> Enum.any?(configs, &required?(stub, &1, principal, timeline)) end)
    else
      []
    end
  end

  defp extensions(config, principal, device, since, high, rooms, previous, device_since) do
    Enum.reduce(config, %{}, fn {name, options}, acc ->
      if is_map(options) and options["enabled"] == true do
        since =
          if previous &&
               get_in(previous.state, ["request", "extensions", name, "enabled"]) == true,
             do: since,
             else: 0

        value =
          case name do
            "to_device" ->
              {events, position} = ClientStore.device_batch(principal, device, device_since, high)

              %{
                "events" => events,
                "next_batch" => Cursor.encode("to_device", principal, device, position)
              }

            "e2ee" ->
              %{
                "device_lists" => ClientSync.device_lists(principal, since, high),
                "device_one_time_keys_count" =>
                  LakehouseMatrix.ClientKeys.counts(principal, device),
                "device_unused_fallback_key_types" =>
                  LakehouseMatrix.ClientKeys.unused_fallback(principal, device)
              }

            "account_data" ->
              %{
                "global" => ClientStore.account_data(principal, "", since, high),
                "rooms" =>
                  Map.new(rooms, &{&1, ClientStore.account_data(principal, &1, since, high)})
              }

            "typing" ->
              %{
                "rooms" =>
                  for(
                    ref <- rooms,
                    {:ok, id} <- [Identity.parse_room_id(ref)],
                    event <- LakehouseMatrix.Ephemeral.typing_events(id, since, high),
                    into: %{},
                    do: {ref, event}
                  )
              }

            "receipts" ->
              %{
                "rooms" =>
                  for(
                    ref <- rooms,
                    {:ok, id} <- [Identity.parse_room_id(ref)],
                    event <- ClientSync.receipts(principal, id, since, high),
                    into: %{},
                    do: {ref, event}
                  )
              }

            _ ->
              %{}
          end

        Map.put(acc, name, value)
      else
        acc
      end
    end)
  end

  defp extensions_empty?(extensions) do
    Enum.all?(extensions, fn
      {"to_device", p} ->
        p["events"] == []

      {"account_data", p} ->
        p["global"] == [] and Enum.all?(p["rooms"], fn {_, events} -> events == [] end)

      {"e2ee", p} ->
        p["device_lists"]["changed"] == [] and p["device_lists"]["left"] == []

      {name, p} when name in ["receipts", "typing"] ->
        p["rooms"] == %{}

      _ ->
        true
    end)
  end

  defp matches?(id, filters, principal, direct, invited, high) do
    state = ClientSync.state_at(id, high)
    type = state_content(state, "m.room.create")["type"]
    tags = (ClientStore.get_data(principal, Identity.room_id(id), "m.tag") || %{})["tags"] || %{}

    boolean_filter(filters, "is_dm", Identity.room_id(id) in direct) and
      boolean_filter(
        filters,
        "is_encrypted",
        Enum.any?(state, &(&1["type"] == "m.room.encryption"))
      ) and
      boolean_filter(
        filters,
        if(Map.has_key?(filters, "is_invited"), do: "is_invited", else: "is_invite"),
        id in invited
      ) and
      (is_nil(filters["room_types"]) or type in filters["room_types"]) and
      type not in (filters["not_room_types"] || []) and
      (is_nil(filters["tags"]) or Enum.any?(filters["tags"], &Map.has_key?(tags, &1))) and
      not Enum.any?(filters["not_tags"] || [], &Map.has_key?(tags, &1)) and
      (is_nil(filters["spaces"]) or
         Enum.any?(filters["spaces"], fn ref ->
           with {:ok, room} <- LakehouseMatrix.ClientRooms.readable(principal, ref),
                true <- LakehouseMatrix.Memberships.joined?(room.id, principal) do
             Enum.any?(
               ClientSync.state_at(room.id, high),
               &(&1["type"] == "m.space.child" and &1["state_key"] == Identity.room_id(id))
             )
           else
             _ -> false
           end
         end))
  end

  defp boolean_filter(filters, key, value),
    do: not Map.has_key?(filters, key) or filters[key] == value

  defp ranges(%{"range" => range}), do: [range]
  defp ranges(%{"ranges" => ranges}), do: ranges
  defp ranges(_), do: [[0, 999]]

  defp required?(event, config, principal, timeline) when is_list(config) do
    Enum.any?(config, fn
      [type, key] ->
        (type == "*" or type == event["type"]) and
          (key == "*" or key == event["state_key"] or
             (key == "$ME" and event["state_key"] == user_id(principal)) or
             (key == "$LAZY" and Enum.any?(timeline, &(&1["sender"] == event["state_key"]))))

      _ ->
        false
    end)
  end

  defp required?(event, config, _, timeline) when is_map(config) do
    includes = config["include"] || []

    exact_member =
      Enum.any?(
        includes,
        &(&1["type"] == "m.room.member" and &1["state_key"] == event["state_key"])
      )

    explicit =
      Enum.any?(includes, &state_match?(event, &1)) and
        not Enum.any?(config["exclude"] || [], &state_match?(event, &1)) and
        (config["lazy_members"] != true or event["type"] != "m.room.member" or exact_member)

    lazy =
      config["lazy_members"] == true and event["type"] == "m.room.member" and
        Enum.any?(
          timeline,
          &(&1["sender"] == event["state_key"] or &1["state_key"] == event["state_key"])
        )

    explicit or lazy
  end

  defp required?(_, _, _, _), do: false

  defp state_match?(event, match),
    do:
      is_map(match) and (is_nil(match["type"]) or match["type"] == event["type"]) and
        (is_nil(match["state_key"]) or match["state_key"] == event["state_key"])

  defp state_content(events, type),
    do: (Enum.find(events, &(&1["type"] == type)) || %{})["content"] || %{}

  defp user_id(principal),
    do: Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

  defp validate(params) do
    maps =
      Enum.all?(~w(lists room_subscriptions extensions), fn k ->
        is_nil(params[k]) or (is_map(params[k]) and map_size(params[k]) <= 100)
      end)

    conn = params["conn_id"] || ""

    valid =
      maps and is_binary(conn) and byte_size(conn) <= 255 and
        params["set_presence"] in [nil, "online", "offline", "unavailable"] and
        (is_nil(params["pos"]) or is_binary(params["pos"]))

    configs =
      if maps,
        do: Map.values(params["lists"] || %{}) ++ Map.values(params["room_subscriptions"] || %{}),
        else: []

    valid =
      valid and Enum.all?(configs, &valid_config?/1) and
        Enum.all?(Map.values(params["extensions"] || %{}), &is_map/1)

    if valid, do: :ok, else: {:error, :invalid_param}
  end

  defp valid_config?(nil), do: true

  defp valid_config?(c) when is_map(c) do
    windows = ranges(c)
    state = c["required_state"] || []
    filters = c["filters"] || %{}

    is_integer(c["timeline_limit"] || 0) and (c["timeline_limit"] || 0) in 0..100 and
      is_list(windows) and length(windows) <= 10 and
      Enum.all?(windows, fn
        [lo, hi] when is_integer(lo) and is_integer(hi) ->
          lo >= 0 and hi >= lo and hi - lo < 1000 and hi < 10_000

        _ ->
          false
      end) and valid_required?(state) and is_map(filters) and
      Enum.all?(
        ~w(is_dm is_encrypted is_invited is_invite),
        &(is_nil(filters[&1]) or is_boolean(filters[&1]))
      ) and
      Enum.all?(~w(room_types not_room_types spaces tags not_tags), fn field ->
        value = filters[field]

        is_nil(value) or
          (is_list(value) and length(value) <= 100 and
             Enum.all?(value, &(is_binary(&1) or is_nil(&1))))
      end)
  end

  defp valid_config?(_), do: false

  defp valid_required?(state) when is_list(state),
    do:
      length(state) <= 100 and
        Enum.all?(state, fn
          [type, key] -> is_binary(type) and is_binary(key)
          _ -> false
        end)

  defp valid_required?(state) when is_map(state) do
    Enum.all?(~w(include exclude), fn field ->
      value = state[field] || []

      is_list(value) and length(value) <= 100 and
        Enum.all?(value, fn match ->
          is_map(match) and (is_nil(match["type"]) or is_binary(match["type"])) and
            (is_nil(match["state_key"]) or is_binary(match["state_key"]))
        end)
    end) and state["lazy_members"] in [nil, true, false]
  end

  defp valid_required?(_), do: false
end
