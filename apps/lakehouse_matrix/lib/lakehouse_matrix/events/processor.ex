defmodule LakehouseMatrix.Events.Processor do
  @moduledoc """
  Dispatches Matrix events to registered handlers. Add new event types by
  implementing `LakehouseMatrix.Events.Handler` and registering here.
  """
  alias LakehouseMatrix.Events.Context
  alias LakehouseMatrix.Events.Handlers.{
    RoomCreate,
    RoomMember,
    RoomMessage,
    RoomName,
    RoomTopic
  }

  alias LakehouseMatrix.{Events, RoomServer}

  @handlers %{
    "m.room.create" => RoomCreate,
    "m.room.member" => RoomMember,
    "m.room.message" => RoomMessage,
    "m.room.name" => RoomName,
    "m.room.topic" => RoomTopic
  }

  @spec supported_types() :: [String.t()]
  def supported_types, do: Map.keys(@handlers)

  @spec process(Context.t()) :: {:ok, map()} | {:error, term()}
  def process(%Context{} = ctx) do
    with {:ok, event_map} <- dispatch(ctx),
         {:ok, _record} <- Events.persist(ctx, event_map) do
      RoomServer.broadcast_event(ctx.room_id, event_map)
      {:ok, event_map}
    end
  end

  defp dispatch(%Context{type: type} = ctx) do
    case Map.get(@handlers, type) do
      nil -> {:error, {:unsupported_event, type}}
      handler when is_atom(handler) -> handler.handle(ctx)
    end
  end
end
