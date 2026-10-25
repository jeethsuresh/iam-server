defmodule LakehouseMatrix.ClientRelations do
  @moduledoc "Visible event relationships, edit/reference/thread aggregations and thread pagination."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientHistory, ClientRooms, ClientStore, ClientSync, Cursor, Identity}
  alias LakehouseMatrix.Protocol.Graph
  alias LakehouseMatrix.Schema.{Pdu, RoomEvent}

  def page(principal, device, ref, target, params) do
    with {:ok, room, _} <- ClientRooms.history_access(principal, ref),
         metadata when not is_nil(metadata) <- Graph.room(room.id),
         {:ok, _} <- ClientHistory.event(principal, room.id, target),
         true <-
           params["dir"] in [nil, "b", "f"] and
             params["recurse"] in [nil, true, false, "true", "false"],
         {:ok, limit} <- ClientSync.integer(params["limit"], 20, 0, 100),
         {:ok, lower} <-
           ClientHistory.cursor(params["from"], principal, device, room.id, params["dir"] || "b"),
         {:ok, upper} <-
           ClientHistory.cursor(params["to"], principal, device, room.id, params["dir"] || "b") do
      depth = if params["recurse"] in [true, "true"], do: 3, else: 1
      query = related(room.id, target, depth, principal) |> not_ignored(principal)

      query =
        if params["relType"],
          do:
            from(p in query,
              where:
                fragment(
                  "?->'content'->'m.relates_to'->>'rel_type' = ?",
                  p.pdu,
                  ^params["relType"]
                )
            ),
          else: query

      query =
        if params["eventType"],
          do: from(p in query, where: fragment("?->>'type' = ?", p.pdu, ^params["eventType"])),
          else: query

      rows =
        ClientHistory.ordered(query, lower, if(params["to"], do: upper), params["dir"] || "b")

      selected =
        ClientHistory.visible(rows, metadata, principal)
        |> Enum.filter(&valid_relation?(&1, principal))

      chunk = Enum.take(selected, limit)

      response = %{
        "chunk" =>
          bundle(principal, room.id, Enum.map(chunk, &ClientHistory.client_event(&1, principal)))
      }

      more = length(selected) > limit or length(rows) == 1000
      last = List.last(chunk) || List.last(rows)

      response =
        if more and limit > 0 and last,
          do:
            Map.put(
              response,
              "next_batch",
              Cursor.encode("topology", principal, device, topo(last), room.id)
            ),
          else: response

      response =
        if params["from"] && chunk != [],
          do:
            Map.put(
              response,
              "prev_batch",
              Cursor.encode("topology", principal, device, topo(hd(chunk)), room.id)
            ),
          else: response

      {:ok,
       if(Map.has_key?(params, "recurse"),
         do: Map.put(response, "recursion_depth", depth),
         else: response
       )}
    else
      {:error, _} = error -> error
      nil -> {:error, :not_found}
      _ -> {:error, :invalid_param}
    end
  end

  def threads(principal, device, ref, params) do
    include = params["include"] || "all"

    with {:ok, room, _} <- ClientRooms.history_access(principal, ref),
         metadata when not is_nil(metadata) <- Graph.room(room.id),
         true <- include in ["all", "participated"],
         {:ok, limit} <- ClientSync.integer(params["limit"], 20, 1, 100),
         {:ok, boundary} <- thread_cursor(params["from"], principal, device, room.id, include) do
      me = user(principal)

      query =
        from p in ClientHistory.query(room.id, principal),
          where: fragment("?->'content'->'m.relates_to'->>'rel_type' = 'm.thread'", p.pdu)

      roots =
        scan(query |> not_ignored(principal), metadata, principal, %{}, fn child, roots ->
          relation = relation(child.pdu)
          root = relation["event_id"]

          if is_binary(root) do
            Map.update(
              roots,
              root,
              %{latest: topo(child), participated: child.pdu["sender"] == me},
              fn info ->
                %{
                  latest: max(info.latest, topo(child)),
                  participated: info.participated or child.pdu["sender"] == me
                }
              end
            )
          else
            roots
          end
        end)

      ordered =
        roots
        |> Enum.filter(fn {_, info} -> is_nil(boundary) or info.latest < boundary end)
        |> Enum.sort_by(fn {_, info} -> info.latest end, :desc)

      {chunk, more, last} =
        thread_page(ordered, room.id, metadata, principal, me, include, limit, [], nil)

      ignored = ignored(principal)

      events =
        Enum.map(chunk, fn record ->
          event = ClientHistory.client_event(record, principal)
          if event["sender"] in ignored, do: Map.put(event, "content", %{}), else: event
        end)

      response = %{"chunk" => bundle(principal, room.id, events)}

      {:ok,
       if(more and last,
         do:
           Map.put(
             response,
             "next_batch",
             Cursor.encode("threads", principal, device, last, room.id <> ":" <> include)
           ),
         else: response
       )}
    else
      {:error, _} = error -> error
      nil -> {:error, :not_found}
      _ -> {:error, :invalid_param}
    end
  end

  defp thread_cursor(nil, _, _, _, _), do: {:ok, nil}

  defp thread_cursor(token, principal, device, room, include),
    do: Cursor.decode(token, "threads", principal, device, room <> ":" <> include)

  defp thread_page([], _, _, _, _, _, _, result, last), do: {Enum.reverse(result), false, last}

  defp thread_page(rest, _, _, _, _, _, 0, result, last),
    do: {Enum.reverse(result), rest != [], last}

  defp thread_page(
         [{id, info} | rest],
         room,
         metadata,
         principal,
         me,
         include,
         remaining,
         result,
         last
       ) do
    record = Graph.event(id)

    valid =
      record && record.local_room_id == room && not record.outlier && not record.auth_rejected &&
        not record.state_rejected && not record.soft_failed &&
        relation(record.pdu)["rel_type"] == nil &&
        ClientHistory.visible([record], metadata, principal) != [] &&
        (include == "all" or info.participated or record.pdu["sender"] == me)

    if valid,
      do:
        thread_page(
          rest,
          room,
          metadata,
          principal,
          me,
          include,
          remaining - 1,
          [record | result],
          info.latest
        ),
      else: thread_page(rest, room, metadata, principal, me, include, remaining, result, last)
  end

  def bundle(principal, room, events, high \\ nil) do
    metadata = Graph.room(room)
    me = user(principal)

    roots =
      events
      |> Enum.reject(&Map.has_key?(&1, "state_key"))
      |> Map.new(
        &{&1["event_id"],
         %{
           root: &1,
           edit: nil,
           latest: nil,
           count: 0,
           participated: &1["sender"] == me,
           references: []
         }}
      )

    if is_nil(metadata) or map_size(roots) == 0 do
      events
    else
      ids = Map.keys(roots)
      cutoff = DateTime.utc_now()

      query =
        from p in ClientHistory.query(room, principal),
          left_join: e in RoomEvent,
          on: e.event_id == p.event_id,
          where:
            fragment("?->'content'->'m.relates_to'->>'event_id' = ANY(?)", p.pdu, ^ids) and
              p.received_at <= ^cutoff

      query =
        if high,
          do: from([p, e] in query, where: is_nil(e.stream_id) or e.stream_id <= ^high),
          else: query

      aggregates =
        scan(query |> not_ignored(principal), metadata, principal, roots, fn child, acc ->
          rel = relation(child.pdu)

          case acc[rel["event_id"]] do
            nil ->
              acc

            info ->
              info =
                case rel["rel_type"] do
                  "m.replace" ->
                    if valid_edit?(info.root, child.pdu) and
                         is_nil(get_in(info.root, ["unsigned", "redacted_because"])) and
                         (is_nil(info.edit) or edit_order(child) > edit_order(info.edit)),
                       do: %{info | edit: child},
                       else: info

                  "m.reference" ->
                    %{info | references: [%{"event_id" => child.event_id} | info.references]}

                  "m.thread" ->
                    if is_nil(relation(info.root)["rel_type"]),
                      do: %{
                        info
                        | count: info.count + 1,
                          latest:
                            if(is_nil(info.latest) or topo(child) > topo(info.latest),
                              do: child,
                              else: info.latest
                            ),
                          participated: info.participated or child.pdu["sender"] == me
                      },
                      else: info

                  _ ->
                    info
                end

              Map.put(acc, rel["event_id"], info)
          end
        end)

      Enum.map(events, fn event ->
        case aggregates[event["event_id"]] do
          nil ->
            event

          info ->
            relations = %{}

            relations =
              if info.edit,
                do:
                  Map.put(
                    relations,
                    "m.replace",
                    ClientHistory.client_event(info.edit, principal)
                  ),
                else: relations

            relations =
              if info.references != [],
                do:
                  Map.put(relations, "m.reference", %{
                    "chunk" => Enum.sort_by(info.references, & &1["event_id"])
                  }),
                else: relations

            relations =
              if info.latest,
                do:
                  Map.put(relations, "m.thread", %{
                    "latest_event" => bundle_latest(principal, room, info.latest, high),
                    "count" => info.count,
                    "current_user_participated" => info.participated
                  }),
                else: relations

            if relations == %{},
              do: event,
              else:
                Map.put(
                  event,
                  "unsigned",
                  Map.put(event["unsigned"] || %{}, "m.relations", relations)
                )
        end
      end)
    end
  end

  # A thread child cannot be a thread root. Its edit/reference aggregates still
  # need including, without recursively following a hostile federation cycle.
  defp bundle_latest(principal, room, record, high) do
    event = ClientHistory.client_event(record, principal)

    if relation(event)["rel_type"] == "m.thread",
      do: hd(bundle(principal, room, [event], high)),
      else: event
  end

  defp scan(query, metadata, principal, acc, reduce, after_id \\ "") do
    batch =
      Repo.all(
        from p in query, where: p.event_id > ^after_id, order_by: [asc: p.event_id], limit: 500
      )

    next = batch |> ClientHistory.visible(metadata, principal) |> Enum.reduce(acc, reduce)

    if length(batch) == 500,
      do: scan(query, metadata, principal, next, reduce, List.last(batch).event_id),
      else: next
  end

  defp related(room, target, 1, principal),
    do:
      from(p in ClientHistory.query(room, principal),
        where:
          fragment(
            "?->'content'->'m.relates_to'->>'event_id' = ? AND jsonb_typeof(?->'content'->'m.relates_to'->'rel_type') = 'string'",
            p.pdu,
            ^target,
            p.pdu
          )
      )

  defp related(room, target, 3, principal) do
    from p in ClientHistory.query(room, principal),
      where:
        fragment(
          """
          ? IN (WITH RECURSIVE source AS (
            SELECT r.event_id, matrix_view_pdu(r.event_id, ?) AS pdu FROM matrix_pdus r WHERE r.local_room_id = ?
          ), related(event_id, level) AS (
            SELECT r.event_id, 1 FROM source r WHERE r.pdu->'content'->'m.relates_to'->>'event_id' = ? AND jsonb_typeof(r.pdu->'content'->'m.relates_to'->'rel_type') = 'string'
            UNION SELECT r.event_id, related.level + 1 FROM source r JOIN related ON r.pdu->'content'->'m.relates_to'->>'event_id' = related.event_id WHERE related.level < 3 AND jsonb_typeof(r.pdu->'content'->'m.relates_to'->'rel_type') = 'string'
          ) SELECT event_id FROM related)
          """,
          p.event_id,
          type(^principal, :binary_id),
          type(^room, :binary_id),
          ^target
        )
  end

  defp not_ignored(query, principal) do
    ignored = ignored(principal)
    from p in query, where: fragment("?->>'sender'", p.pdu) not in ^ignored
  end

  defp ignored(principal) do
    value = (ClientStore.get_data(principal, "", "m.ignored_user_list") || %{})["ignored_users"]
    if is_map(value), do: Map.keys(value), else: []
  end

  defp valid_relation?(record, principal) do
    rel = relation(record.pdu)

    case Graph.event(rel["event_id"]) do
      %Pdu{local_room_id: room} = parent when room == record.local_room_id ->
        parent = LakehouseMatrix.Erasure.pdu(parent, principal)

        case rel["rel_type"] do
          "m.replace" ->
            valid_edit?(parent.pdu, record.pdu)

          "m.annotation" ->
            is_binary(rel["key"]) and
              relation(parent.pdu)["rel_type"] not in ["m.annotation", "m.replace"]

          "m.thread" ->
            is_nil(relation(parent.pdu)["rel_type"])

          type ->
            is_binary(type)
        end

      _ ->
        false
    end
  end

  def validate_send(room, sender, type, content) do
    rel = relation(%{"content" => content})

    case rel["rel_type"] do
      "m.thread" ->
        case Graph.event(rel["event_id"]) do
          %Pdu{local_room_id: ^room} = parent ->
            if relation(parent.pdu)["rel_type"], do: {:error, :invalid_param}, else: :ok

          _ ->
            :ok
        end

      "m.annotation" ->
        key = rel["key"]

        if is_binary(key) and is_binary(rel["event_id"]) and
             Repo.exists?(
               from p in ClientHistory.query(room),
                 where:
                   fragment(
                     "?->>'sender' = ? AND ?->>'type' = ? AND ?->'content'->'m.relates_to'->>'rel_type' = 'm.annotation' AND ?->'content'->'m.relates_to'->>'event_id' = ? AND ?->'content'->'m.relates_to'->>'key' = ?",
                     p.pdu,
                     ^sender,
                     p.pdu,
                     ^type,
                     p.pdu,
                     p.pdu,
                     ^rel["event_id"],
                     p.pdu,
                     ^key
                   )
             ),
           do: {:error, :duplicate_annotation},
           else: :ok

      _ ->
        :ok
    end
  end

  defp valid_edit?(parent, child),
    do:
      parent["sender"] == child["sender"] and parent["type"] == child["type"] and
        not Map.has_key?(parent, "state_key") and not Map.has_key?(child, "state_key") and
        relation(parent)["rel_type"] != "m.replace" and
        (child["type"] == "m.room.encrypted" or is_map(child["content"]["m.new_content"]))

  defp relation(event) do
    value = (event["content"] || %{})["m.relates_to"]
    if is_map(value), do: value, else: %{}
  end

  defp topo(record), do: [record.pdu["depth"], record.event_id]
  defp edit_order(record), do: {record.pdu["origin_server_ts"], record.event_id}

  defp user(principal),
    do: Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()
end
