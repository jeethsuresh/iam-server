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
    %RoomEvent{}
    |> RoomEvent.changeset(%{
      room_id: ctx.room_id,
      event_id: ctx.event_id,
      type: ctx.type,
      content: event_map["content"] || ctx.content,
      sender: ctx.sender,
      principal_id: ctx.principal_id,
      origin_server_ts: ctx.origin_server_ts,
      state_key: ctx.state_key
    })
    |> Repo.insert()
  end

  @spec list_timeline(Ecto.UUID.t(), keyword()) :: [map()]
  def list_timeline(room_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    from_ts = Keyword.get(opts, :from_ts)
    to_ts = Keyword.get(opts, :to_ts)

    query =
      from e in RoomEvent,
        where: e.room_id == ^room_id and e.type == "m.room.message",
        order_by: [desc: e.origin_server_ts],
        limit: ^limit

    query =
      if from_ts,
        do: (from e in query, where: e.origin_server_ts < ^from_ts),
        else: query

    query =
      if to_ts,
        do: (from e in query, where: e.origin_server_ts > ^to_ts),
        else: query

    query
    |> Repo.all()
    |> Enum.reverse()
    |> Enum.map(&to_client_event/1)
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
  def to_client_event(%RoomEvent{} = e) do
    base = %{
      "event_id" => e.event_id,
      "type" => e.type,
      "sender" => e.sender,
      "origin_server_ts" => e.origin_server_ts,
      "content" => e.content
    }

    if e.state_key do
      Map.put(base, "state_key", e.state_key)
    else
      base
    end
  end

  defp coalesce_since(nil), do: 0
  defp coalesce_since(ts) when is_integer(ts), do: ts
end
