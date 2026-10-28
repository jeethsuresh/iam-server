defmodule LakehouseMatrix.Erasure do
  @moduledoc "Erased event views, with original copies available only to prior room members. Canonical room authorization remains intact."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, Identity}
  alias LakehouseMatrix.Protocol.{Event, Graph}
  alias LakehouseMatrix.Schema.{Pdu, Room, RoomEvent, RoomState}

  # Called inside the account's authenticated deactivation transaction. The
  # ordinary client projections and derived room metadata are pruned. Canonical
  # PDUs and internal policy state remain intact: erasure is not a redaction.
  def erase!(principal) do
    unless Repo.in_transaction?(),
      do: raise(ArgumentError, "erasure requires the account transaction")

    high = ClientStore.lock!()
    account = Repo.get!(LakehouseIam.Schema.Principal, principal)
    user = Identity.user_id(account.username)

    Repo.insert_all(
      "matrix_erased_users",
      [%{principal_id: ClientStore.dump_id(principal), user_id: user, stream_id: high}],
      on_conflict: :nothing
    )

    records = Repo.all(from e in RoomEvent, where: e.sender == ^user)
    projected = MapSet.new(records, & &1.event_id)

    for record <- records do
      metadata = Graph.room(record.room_id)
      pdu = if metadata, do: Graph.event(record.event_id)
      archive!(principal, record.event_id, record.room_id, record.content, pdu && pdu.pdu)
      wire = if pdu, do: pdu.pdu, else: %{"type" => record.type, "content" => record.content}
      pruned = Event.redact(wire, (metadata && metadata.version) || "11")

      Repo.update_all(from(e in RoomEvent, where: e.id == ^record.id),
        set: [content: pruned["content"]]
      )

      current_state =
        Repo.exists?(
          from s in RoomState,
            where:
              s.room_id == ^record.room_id and
                fragment("?->>'_event_id' = ?", s.content, ^record.event_id)
        )

      if current_state do
        attributes =
          case record.type do
            "m.room.name" -> [name: ""]
            "m.room.topic" -> [topic: ""]
            "m.room.avatar" -> [avatar_url: nil]
            _ -> []
          end

        if attributes != [],
          do: Repo.update_all(from(r in Room, where: r.id == ^record.room_id), set: attributes)
      end
    end

    # Auth-chain and stripped-state outliers may have no River projection.
    for record <- Repo.all(from p in Pdu, where: fragment("?->>'sender'", p.pdu) == ^user),
        not MapSet.member?(projected, record.event_id) do
      archive!(
        principal,
        record.event_id,
        record.local_room_id,
        record.pdu["content"],
        record.pdu
      )
    end

    :ok
  end

  defp archive!(principal, id, room, content, pdu) do
    type =
      if pdu,
        do: pdu["type"],
        else: Repo.one(from e in RoomEvent, where: e.event_id == ^id, select: e.type)

    pruned = if pdu, do: Event.redact(pdu, Graph.room(room).version)
    content = if pdu, do: pdu["content"], else: content

    conflict =
      if pdu,
        do: {:replace, [:original_content, :original_pdu, :pruned_pdu, :event_type]},
        else: :nothing

    Repo.insert_all(
      "matrix_erased_events",
      [
        %{
          event_id: id,
          local_room_id: ClientStore.dump_id(room),
          principal_id: ClientStore.dump_id(principal),
          event_type: type,
          original_content: content,
          original_pdu: pdu,
          pruned_pdu: pruned
        }
      ],
      on_conflict: conflict,
      conflict_target: [:event_id]
    )
  end

  def capture_pdus!(ids) do
    records =
      Repo.all(
        from p in Pdu,
          join: erased in "matrix_erased_users",
          on: erased.user_id == fragment("?->>'sender'", p.pdu),
          where: p.event_id in ^ids,
          select: {p, type(erased.principal_id, :binary_id)}
      )

    for {record, principal} <- records,
        do:
          archive!(
            principal,
            record.event_id,
            record.local_room_id,
            record.pdu["content"],
            record.pdu
          )

    :ok
  end

  def capture_projection(%RoomEvent{} = record) do
    case Repo.one(
           from erased in "matrix_erased_users",
             where: erased.user_id == ^record.sender,
             select: type(erased.principal_id, :binary_id)
         ) do
      nil ->
        record

      principal ->
        pdu = Graph.event(record.event_id)
        archive!(principal, record.event_id, record.room_id, record.content, pdu && pdu.pdu)
        wire = if pdu, do: pdu.pdu, else: %{"type" => record.type, "content" => record.content}

        content =
          Event.redact(
            wire,
            (Graph.room(record.room_id) && Graph.room(record.room_id).version) || "11"
          )["content"]

        record |> Ecto.Changeset.change(content: content) |> Repo.update!()
    end
  end

  def client(event, principal) when is_map(event) do
    # A real redaction always takes precedence over an archived original.
    if get_in(event, ["unsigned", "redacted_because"]) do
      Map.put(event, "content", Event.redact(event, "11")["content"])
    else
      case client_snapshot(event["event_id"], if(is_binary(principal), do: principal)) do
        nil ->
          event

        %{allowed: true, content: content} ->
          Map.put(event, "content", content)

        _ ->
          event
          |> Map.put("content", Event.redact(event, "11")["content"])
          |> pruned_unsigned()
      end
    end
  end

  def client(event, _), do: event

  defp pruned_unsigned(event) do
    safe = Map.take(event["unsigned"] || %{}, ["replaces_state"])
    if safe == %{}, do: Map.delete(event, "unsigned"), else: Map.put(event, "unsigned", safe)
  end

  def record(%RoomEvent{} = record, principal) do
    case client_snapshot(record.event_id, principal) do
      nil ->
        record

      %{allowed: true, content: content} ->
        %{record | content: content}

      _ ->
        %{
          record
          | content:
              Event.redact(%{"type" => record.type, "content" => record.content}, "11")["content"]
        }
    end
  end

  def federation(id, server, fallback) do
    record = Graph.event(id)

    if record && is_binary(record.redacted_by) do
      record.pdu
    else
      case original(id, {:server, server}) do
        %{pdu: pdu} when is_map(pdu) ->
          Map.put(pdu, "signatures", (record && record.pdu["signatures"]) || pdu["signatures"])

        _ ->
          Repo.one(
            from a in "matrix_erased_events", where: a.event_id == ^id, select: a.pruned_pdu
          ) || (record && record.pdu) || fallback
      end
    end
  end

  def outbox(%{kind: "pdu"} = item) do
    Map.update!(item.payload, "pdus", fn events ->
      Enum.map(events, &federation(item.event_id, item.destination, &1))
    end)
  end

  def outbox(%{kind: "leave"} = item),
    do: federation(item.event_id, item.destination, item.payload)

  def outbox(%{kind: "invite"} = item) do
    record = Graph.event(item.event_id)

    item.payload
    |> Map.update!("event", &federation(item.event_id, item.destination, &1))
    |> Map.update!(
      "invite_room_state",
      fn events ->
        version = Graph.room(record.local_room_id).version

        Enum.map(events, fn event ->
          if Event.validate(event, version) == :ok do
            federation(Event.id(event, version), item.destination, event)
          else
            # Read older queued previews defensively; new invitations always
            # contain full room-version PDUs, including the create event.
            hd(stripped([event], record.local_room_id, {:server, item.destination}, version))
          end
        end)
      end
    )
  end

  def outbox(item), do: item.payload

  def stripped(events, room, viewer, version) do
    Enum.map(events, fn event ->
      cutoff =
        if is_binary(event["sender"]),
          do:
            Repo.one(
              from e in "matrix_erased_users",
                where: e.user_id == ^event["sender"],
                select: e.stream_id
            )

      if is_nil(cutoff) or prior?(room, viewer, cutoff),
        do: event,
        else: Map.take(Event.redact(event, version), ~w(type state_key sender content))
    end)
  end

  defp prior?(room, {:user, principal}, cutoff) do
    account = Repo.get(LakehouseIam.Schema.Principal, principal)

    if account do
      user = Identity.user_id(account.username)

      Repo.exists?(
        from m in RoomEvent,
          where:
            m.room_id == ^room and m.type == "m.room.member" and m.state_key == ^user and
              m.stream_id <= ^cutoff and fragment("?->>'membership'", m.content) == "join"
      )
    else
      false
    end
  end

  defp prior?(room, {:server, server}, cutoff),
    do:
      Repo.exists?(
        from m in RoomEvent,
          where:
            m.room_id == ^room and m.type == "m.room.member" and m.stream_id <= ^cutoff and
              fragment("?->>'membership'", m.content) == "join" and
              fragment("substring(? FROM position(':' IN ?) + 1)", m.state_key, m.state_key) ==
                ^server
      )

  def original(id, viewer) when is_binary(id) do
    query =
      from a in "matrix_erased_events",
        as: :archive,
        join: erased in "matrix_erased_users",
        on: erased.principal_id == a.principal_id,
        left_join: p in Pdu,
        on: p.event_id == a.event_id,
        where: a.event_id == ^id and is_nil(p.redacted_by),
        where:
          not exists(
            from r in RoomEvent,
              where:
                r.room_id == parent_as(:archive).local_room_id and r.type == "m.room.redaction" and
                  fragment("?->>'redacts'", r.content) == ^id
          ),
        select: %{content: a.original_content, pdu: a.original_pdu}

    query =
      case viewer do
        {:user, principal} when is_binary(principal) ->
          from [a, erased, p] in query,
            where:
              fragment(
                """
                EXISTS (SELECT 1 FROM room_events m JOIN principals viewer ON viewer.id = ?
                  WHERE m.room_id = ? AND m.type = 'm.room.member'
                    AND m.state_key = '@' || viewer.username || ':' || ?
                    AND m.content->>'membership' = 'join' AND m.stream_id <= ?)
                """,
                type(^principal, :binary_id),
                a.local_room_id,
                ^Identity.homeserver_domain(),
                erased.stream_id
              )

        {:server, server} when is_binary(server) ->
          from [a, erased, p] in query,
            where:
              fragment(
                """
                EXISTS (SELECT 1 FROM room_events m WHERE m.room_id = ? AND m.type = 'm.room.member'
                  AND substring(m.state_key FROM position(':' IN m.state_key) + 1) = ?
                  AND m.content->>'membership' = 'join' AND m.stream_id <= ?)
                """,
                a.local_room_id,
                ^server,
                erased.stream_id
              )

        _ ->
          from a in query, where: false
      end

    Repo.one(query)
  end

  def original(_, _), do: nil

  def event_query(principal) do
    base =
      from e in RoomEvent,
        select_merge: %{
          content: fragment("matrix_view_content(?, ?)", e.event_id, type(^principal, :binary_id))
        }

    from(e in subquery(base))
  end

  def pdu_query(principal) do
    base =
      from p in Pdu,
        select_merge: %{
          pdu: fragment("matrix_view_pdu(?, ?)", p.event_id, type(^principal, :binary_id))
        }

    from(p in subquery(base))
  end

  def pdu(%Pdu{} = record, principal) do
    Repo.one(from p in pdu_query(principal), where: p.event_id == ^record.event_id) || record
  end

  defp client_snapshot(id, principal) when is_binary(id),
    do:
      LakehouseMatrix.ReadSnapshot.fetch({:erasure_view, id, principal}, fn ->
        Repo.one(
          from a in "matrix_erased_events",
            where: a.event_id == ^id,
            select: %{
              content: a.original_content,
              allowed:
                fragment("matrix_erasure_access(?, ?)", a.event_id, type(^principal, :binary_id))
            }
        )
      end)

  defp client_snapshot(_, _), do: nil
end
