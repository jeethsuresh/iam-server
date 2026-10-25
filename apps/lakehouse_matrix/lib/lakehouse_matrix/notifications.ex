defmodule LakehouseMatrix.Notifications do
  @moduledoc "Event-time notification decisions, receipt-aware unread counts and private bounded pagination."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}

  alias LakehouseMatrix.{
    ClientRooms,
    ClientStore,
    ClientSync,
    Cursor,
    Events,
    Identity,
    PushRules
  }

  alias LakehouseMatrix.Protocol.Graph
  alias LakehouseMatrix.Schema.{Pdu, RoomEvent}
  @maximum 9_007_199_254_740_991

  def record!(metadata, record) do
    ids = Map.values(record.state_after)

    state =
      Repo.all(from p in Pdu, where: p.event_id in ^ids)
      |> Map.new(fn p -> {{p.pdu["type"], p.pdu["state_key"]}, p.pdu} end)

    event =
      record.pdu |> Map.put("event_id", record.event_id) |> Map.put("room_id", metadata.room_id)

    projected = Repo.get_by!(RoomEvent, event_id: record.event_id)

    members =
      Enum.count(state, fn {{type, _}, e} ->
        type == "m.room.member" and e["content"]["membership"] == "join"
      end)

    users =
      for {{"m.room.member", user}, e} <- state,
          e["content"]["membership"] == "join" or
            (event["type"] == "m.room.member" and event["state_key"] == user and
               event["content"]["membership"] == "invite"),
          do: user

    for user <- users,
        user != event["sender"],
        {:ok, name} <- [Identity.parse_user_id(user)],
        {:ok, principal} <- [Accounts.fetch_user(name)],
        principal.active,
        not ignored?(principal.id, event) do
      context = %{
        members: members,
        state: state,
        version: metadata.version,
        displayname: get_in(state, [{"m.room.member", user}, "content", "displayname"])
      }

      notify!(metadata, projected, event, principal, context)
    end

    :ok
  end

  def invite!(metadata, principal, id) do
    projected = Repo.get_by!(RoomEvent, event_id: id)
    event = Events.to_client_event(projected) |> Map.put("room_id", metadata.room_id)

    if principal.active and not ignored?(principal.id, event),
      do:
        notify!(metadata, projected, event, principal, %{
          members: 0,
          state: %{},
          version: metadata.version
        })

    :ok
  end

  defp notify!(metadata, projected, event, principal, context) do
    actions = PushRules.evaluate(PushRules.get(principal.id), event, context)

    if "notify" in actions do
      {count, rows} =
        Repo.insert_all(
          "matrix_notifications",
          [
            %{
              principal_id: ClientStore.dump_id(principal.id),
              local_room_id: ClientStore.dump_id(metadata.local_room_id),
              event_id: event["event_id"],
              actions: actions,
              highlight: highlight?(actions),
              stream_id: projected.stream_id,
              ts: System.system_time(:millisecond)
            }
          ],
          on_conflict: :nothing,
          conflict_target: [:principal_id, :event_id],
          returning: [:id]
        )

      if count > 0, do: LakehouseMatrix.Pushers.queue!(principal.id, hd(rows).id)
    end
  end

  def highlight?(actions),
    do:
      Enum.any?(actions, fn
        %{"set_tweak" => "highlight"} = action -> Map.get(action, "value", true) == true
        _ -> false
      end)

  def counts(principal, room, high \\ nil) do
    high = high || ClientStore.position()

    if ClientStore.room_forgotten?(principal, room, high) or
         not LakehouseMatrix.RiverRtc.chat_allowed?(room, principal) or
         not LakehouseMatrix.RiverPublishing.reader_allowed?(room, principal) do
      %{"notification_count" => 0, "highlight_count" => 0}
    else
      receipts = read_states(principal, room, high)

      count_batches(
        query(principal, high) |> where([n], n.local_room_id == type(^room, :binary_id)),
        receipts,
        0,
        0,
        0
      )
    end
  end

  defp count_batches(query, receipts, after_id, count, highlighted) do
    rows =
      Repo.all(
        from [n, e, p] in query,
          where: n.id > ^after_id,
          order_by: [asc: n.id],
          limit: 500,
          select: %{
            id: n.id,
            event: e,
            depth: fragment("(?->>'depth')::bigint", p.pdu),
            highlight: n.highlight
          }
      )

    unread = Enum.reject(rows, &read?(&1.event, &1.depth, receipts))
    count = count + length(unread)
    highlighted = highlighted + Enum.count(unread, & &1.highlight)

    if length(rows) == 500,
      do: count_batches(query, receipts, List.last(rows).id, count, highlighted),
      else: %{"notification_count" => count, "highlight_count" => highlighted}
  end

  def page(principal, device, params) do
    with true <- params["only"] in [nil, "highlight"],
         {:ok, limit} <- ClientSync.integer(params["limit"], 20, 1, 100),
         {:ok, [upper, high]} <-
           page_cursor(params["from"], principal, device, params["only"] || "") do
      query = query(principal, high)
      query = if params["only"] == "highlight", do: where(query, [n], n.highlight), else: query

      {rows, next} =
        page_batches(
          query,
          principal,
          upper,
          limit,
          [],
          System.monotonic_time(:millisecond) + 3000
        )

      response = %{"notifications" => rows}

      {:ok,
       if(next,
         do:
           Map.put(
             response,
             "next_token",
             Cursor.encode("notifications", principal, device, [next, high], params["only"] || "")
           ),
         else: response
       )}
    else
      false -> {:error, :invalid_param}
      error -> error
    end
  end

  defp page_cursor(nil, _, _, _), do: {:ok, [@maximum, ClientStore.position()]}

  defp page_cursor(token, principal, device, filter),
    do: Cursor.decode(token, "notifications", principal, device, filter)

  defp page_batches(query, principal, upper, remaining, results, deadline) do
    rows =
      Repo.all(
        from [n, e, p] in query,
          where: n.id < ^upper,
          order_by: [desc: n.id],
          limit: 100,
          select: %{
            id: n.id,
            room: type(n.local_room_id, :binary_id),
            actions: n.actions,
            ts: n.ts,
            event: e,
            depth: fragment("(?->>'depth')::bigint", p.pdu)
          }
      )

    {results, remaining, last} =
      Enum.reduce_while(rows, {results, remaining, nil}, fn row, {acc, left, _} ->
        event = visible_event(principal, row.event)

        if event do
          found = %{
            "actions" => row.actions,
            "event" => Map.delete(event, "room_id"),
            "ts" => row.ts,
            "room_id" => Identity.room_id(row.room),
            "read" =>
              read?(
                row.event,
                row.depth,
                read_states(principal, row.room, ClientStore.position())
              )
          }

          next = {acc ++ [found], left - 1, row.id}
          if left == 1, do: {:halt, next}, else: {:cont, next}
        else
          {:cont, {acc, left, row.id}}
        end
      end)

    cond do
      remaining == 0 -> {results, last}
      length(rows) < 100 -> {results, nil}
      System.monotonic_time(:millisecond) >= deadline -> {results, last}
      true -> page_batches(query, principal, last, remaining, results, deadline)
    end
  end

  def visible_event(principal, event) do
    user = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

    cond do
      ClientStore.room_forgotten?(principal, event.room_id) ->
        nil

      ignored?(principal, Events.to_client_event(event)) ->
        nil

      event.type == "m.room.member" and event.state_key == user ->
        Events.to_client_event(event)

      true ->
        case ClientRooms.event(principal, Identity.room_id(event.room_id), event.event_id) do
          {:ok, found} -> found
          _ -> nil
        end
    end
  end

  defp query(principal, high) do
    ignored = ClientSync.ignored_users(principal)

    from n in "matrix_notifications",
      join: e in RoomEvent,
      on: n.event_id == e.event_id,
      left_join: p in Pdu,
      on: p.event_id == e.event_id,
      where:
        n.principal_id == type(^principal, :binary_id) and n.stream_id <= ^high and
          (e.sender not in ^ignored or
             (not is_nil(e.state_key) and
                not (e.type == "m.room.member" and
                       fragment("?->>'membership' = 'invite'", e.content)))) and
          (is_nil(p.event_id) or is_nil(p.redacted_by))
  end

  defp ignored?(principal, event),
    do:
      LakehouseMatrix.InvitePermission.suppressed?(principal, event) or
        (event["sender"] in ClientSync.ignored_users(principal) and
           (not Map.has_key?(event, "state_key") or
              (event["type"] == "m.room.member" and event["content"]["membership"] == "invite")))

  def read_states(principal, room, high) do
    # Keep each receipt's history because delivery can stop below the latest
    # committed position while draining an older to-device batch.
    rows =
      Repo.all(
        from r in "matrix_receipt_history",
          where:
            r.principal_id == type(^principal, :binary_id) and
              r.room_id == type(^room, :binary_id) and r.stream_id <= ^high,
          left_join: e in RoomEvent,
          on: e.event_id == r.event_id,
          left_join: p in Pdu,
          on: p.event_id == r.event_id,
          distinct: [r.type, r.thread_id],
          order_by: [asc: r.type, asc: r.thread_id, desc: r.stream_id],
          select: {r.thread_id, fragment("(?->>'depth')::bigint", p.pdu), e.stream_id, r.event_id}
      )

    Enum.reduce(rows, %{}, fn {thread, depth, stream, id}, acc ->
      Map.update(acc, thread, {depth || stream, id}, &max(&1, {depth || stream, id}))
    end)
  end

  def receipt_forward?(principal, room, type, thread, event) do
    previous =
      Repo.one(
        from r in "matrix_receipts",
          where:
            r.principal_id == type(^principal, :binary_id) and
              r.room_id == type(^room, :binary_id) and r.type == ^type and r.thread_id == ^thread,
          select: r.event_id
      )

    is_nil(previous) or rank(event) > rank(previous)
  end

  defp rank(id) do
    case Graph.event(id) do
      nil ->
        case Repo.get_by(RoomEvent, event_id: id) do
          nil -> {-1, id}
          event -> {event.stream_id, id}
        end

      pdu ->
        {pdu.pdu["depth"], id}
    end
  end

  def read?(event, depth, receipts) do
    relation = event.content["m.relates_to"] || %{}

    thread =
      if is_map(relation) and relation["rel_type"] == "m.thread",
        do: relation["event_id"],
        else: "main"

    threshold = max(receipts[""] || {-1, ""}, receipts[thread] || {-1, ""})
    {depth || event.stream_id, event.event_id} <= threshold
  end

  def changed?(principal, room, since, high) do
    Repo.exists?(
      from r in "matrix_receipt_history",
        where:
          r.principal_id == type(^principal, :binary_id) and
            r.room_id == type(^room, :binary_id) and r.stream_id > ^since and r.stream_id <= ^high
    ) or
      Enum.any?(
        ClientStore.account_data(principal, "", since, high),
        &(&1["type"] in ~w(m.ignored_user_list m.push_rules))
      )
  end
end
