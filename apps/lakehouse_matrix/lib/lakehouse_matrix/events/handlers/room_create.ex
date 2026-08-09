defmodule LakehouseMatrix.Events.Handlers.RoomCreate do
  @moduledoc false
  @behaviour LakehouseMatrix.Events.Handler

  alias LakehouseMatrix.Events.Context
  alias LakehouseMatrix.State

  @impl true
  def handle(%Context{} = ctx) do
    _ = State.upsert(ctx.room_id, "", ctx.type, ctx.content, ctx.event_id, ctx.origin_server_ts)
    {:ok, to_event_map(ctx)}
  end

  defp to_event_map(ctx) do
    %{
      "event_id" => ctx.event_id,
      "type" => ctx.type,
      "sender" => ctx.sender,
      "origin_server_ts" => ctx.origin_server_ts,
      "content" => ctx.content,
      "state_key" => ""
    }
  end
end
