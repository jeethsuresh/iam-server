defmodule LakehouseMatrix.Events do
  @moduledoc """
  Matrix event persistence and queries.
  """
  import Ecto.Query

  alias LakehouseIam.Repo
  alias LakehouseMatrix.Events.Context
  alias LakehouseMatrix.Schema.RoomEvent

  @spec persist(Context.t(), map()) :: {:ok, RoomEvent.t()} | {:error, Ecto.Changeset.t()}
  def persist(%Context{} = ctx, event_map) do
    if LakehouseMatrix.Protocol.Graph.room(ctx.room_id) do
      persist_record(ctx, event_map)
    else
      Repo.transaction(fn ->
        LakehouseMatrix.ClientStore.lock!()

        case LakehouseMatrix.AccountModeration.event(
               ctx.sender,
               ctx.room_id,
               ctx.type,
               event_map["content"] || ctx.content,
               ctx.state_key
             ) do
          :ok -> :ok
          {:error, reason} -> Repo.rollback(reason)
        end

        case persist_record(ctx, event_map) do
          {:ok, record} -> record
          {:error, reason} -> Repo.rollback(reason)
        end
      end)
    end
  end

  defp persist_record(ctx, event_map) do
    %RoomEvent{}
    |> RoomEvent.changeset(%{
      room_id: ctx.room_id,
      event_id: ctx.event_id,
      type: ctx.type,
      content: event_map["content"] || ctx.content,
      sender: ctx.sender,
      principal_id: ctx.principal_id,
      origin_server_ts: ctx.origin_server_ts,
      state_key: ctx.state_key,
      sticky_duration_ms: ctx.sticky_duration_ms,
      timeline_visible: Map.get(event_map, "timeline_visible", true)
    })
    |> Repo.insert()
    |> then(fn
      {:ok, record} -> {:ok, LakehouseMatrix.Erasure.capture_projection(record)}
      error -> error
    end)
    |> tap(fn
      {:ok, e} ->
        if is_nil(LakehouseMatrix.Protocol.Graph.room(e.room_id)),
          do: LakehouseMatrix.MediaReferences.capture!(e, nil)

        LakehouseIam.Changes.notify(%{
          "room_id" => e.room_id,
          "member" => if(e.type == "m.room.member", do: e.state_key)
        })

      _ ->
        :ok
    end)
  end

  @spec list_timeline(Ecto.UUID.t(), keyword()) :: [map()]
  def list_timeline(room_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    from_ts = Keyword.get(opts, :from_ts)
    to_ts = Keyword.get(opts, :to_ts)

    query =
      from e in LakehouseMatrix.Erasure.event_query(opts[:principal]),
        where: e.room_id == ^room_id and e.type == "m.room.message",
        order_by: [desc: e.origin_server_ts],
        limit: ^limit

    query =
      if from_ts,
        do: from(e in query, where: e.origin_server_ts < ^from_ts),
        else: query

    query =
      if to_ts,
        do: from(e in query, where: e.origin_server_ts > ^to_ts),
        else: query

    query
    |> Repo.all()
    |> Enum.reverse()
    |> Enum.map(&to_client_event(&1, opts[:principal]))
  end

  def list_all_timeline(room_id, limit \\ 100, principal \\ nil) do
    Repo.all(
      from e in LakehouseMatrix.Erasure.event_query(principal),
        where: e.room_id == ^room_id and is_nil(e.state_key),
        order_by: [desc: e.inserted_at, desc: e.id],
        limit: ^limit
    )
    |> Enum.reverse()
    |> Enum.map(&to_client_event(&1, principal))
  end

  @doc """
  Timeline messages that are file or image attachments (newest first).
  """
  @spec list_file_messages(Ecto.UUID.t(), keyword()) :: [map()]
  def list_file_messages(room_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    from(e in LakehouseMatrix.Erasure.event_query(opts[:principal]),
      where: e.room_id == ^room_id and e.type == "m.room.message",
      where: fragment("?->>'msgtype' IN ('m.file', 'm.image')", e.content),
      order_by: [desc: e.origin_server_ts],
      limit: ^limit
    )
    |> Repo.all()
    |> Enum.map(&to_client_event(&1, opts[:principal]))
  end

  @spec list_since(integer() | nil, keyword()) :: [RoomEvent.t()]
  def list_since(since_ts, opts \\ []) do
    room_ids = Keyword.get(opts, :room_ids)

    query =
      from e in RoomEvent,
        where: e.origin_server_ts > ^coalesce_since(since_ts),
        order_by: [asc: e.origin_server_ts]

    query =
      if room_ids do
        from e in query, where: e.room_id in ^room_ids
      else
        query
      end

    Repo.all(query)
  end

  @spec to_client_event(RoomEvent.t() | map()) :: map()
  def to_client_event(event, principal),
    do: event |> to_client_event() |> LakehouseMatrix.Erasure.client(principal)

  def to_client_event(%RoomEvent{} = e) do
    base = %{
      "event_id" => e.event_id,
      "type" => e.type,
      "sender" => e.sender,
      "origin_server_ts" => e.origin_server_ts,
      "content" => e.content
    }

    base = if e.state_key, do: Map.put(base, "state_key", e.state_key), else: base

    base =
      if e.type == "m.room.redaction",
        do: Map.put(base, "redacts", e.content["redacts"]),
        else: base

    base = redact_client_event(base, e)

    if is_integer(e.sticky_duration_ms) and e.sticky_duration_ms > 0 do
      duration = min(e.sticky_duration_ms, 3_600_000)

      remaining =
        min(e.origin_server_ts, DateTime.to_unix(e.inserted_at, :millisecond)) + duration -
          System.system_time(:millisecond)

      base = Map.put(base, "sticky", %{"duration_ms" => duration})

      if remaining > 0,
        do:
          Map.update(
            base,
            "unsigned",
            %{"sticky_duration_remaining_ms" => remaining},
            &Map.put(&1, "sticky_duration_remaining_ms", remaining)
          ),
        else: base
    else
      base
    end
  end

  defp redact_client_event(base, e) do
    case LakehouseIam.Repo.get(LakehouseMatrix.Schema.Pdu, e.event_id) do
      %{redacted_by: id} when is_binary(id) ->
        redaction = LakehouseIam.Repo.get_by!(RoomEvent, event_id: id)

        because = %{
          "event_id" => redaction.event_id,
          "type" => redaction.type,
          "sender" => redaction.sender,
          "origin_server_ts" => redaction.origin_server_ts,
          "content" => redaction.content,
          "redacts" => redaction.content["redacts"]
        }

        Map.put(base, "unsigned", %{"redacted_because" => because})

      %{} ->
        base

      nil ->
        redaction =
          LakehouseIam.Repo.one(
            from r in RoomEvent,
              where:
                r.room_id == ^e.room_id and r.type == "m.room.redaction" and
                  fragment("?->>'redacts' = ?", r.content, ^e.event_id),
              order_by: [desc: r.stream_id],
              limit: 1
          )

        if redaction && e.type != "m.room.redaction" do
          base
          |> Map.put("content", %{})
          |> Map.put("unsigned", %{"redacted_because" => to_client_event(redaction)})
        else
          base
        end
    end
  end

  defp coalesce_since(nil), do: 0
  defp coalesce_since(ts) when is_integer(ts), do: ts
end
