defmodule LakehouseMatrix.Events.Handlers.RoomMessage do
  @moduledoc false
  @behaviour LakehouseMatrix.Events.Handler

  alias LakehouseMatrix.Events.Context

  @impl true
  def handle(%Context{} = ctx) do
    body = Map.get(ctx.content, "body", "") |> to_string() |> String.trim()

    if body == "" do
      {:error, :empty_message}
    else
      content = Map.put(ctx.content, "msgtype", Map.get(ctx.content, "msgtype", "m.text"))

      {:ok,
       %{
         "event_id" => ctx.event_id,
         "type" => ctx.type,
         "sender" => ctx.sender,
         "origin_server_ts" => ctx.origin_server_ts,
         "content" => content
       }}
    end
  end
end
