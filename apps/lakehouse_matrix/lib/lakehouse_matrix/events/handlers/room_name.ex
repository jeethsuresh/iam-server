defmodule LakehouseMatrix.Events.Handlers.RoomName do
  @moduledoc false
  @behaviour LakehouseMatrix.Events.Handler

  alias LakehouseIam.Repo
  alias LakehouseMatrix.Events.Context
  alias LakehouseMatrix.Schema.Room
  alias LakehouseMatrix.State

  @impl true
  def handle(%Context{} = ctx) do
    name = Map.get(ctx.content, "name")

    with :ok <- maybe_update_room_name(ctx.room_id, name),
         :ok <-
           State.upsert(ctx.room_id, "", ctx.type, ctx.content, ctx.event_id, ctx.origin_server_ts) do
      {:ok, to_event_map(ctx)}
    end
  end

  defp maybe_update_room_name(room_id, name) when is_binary(name) and name != "" do
    case Repo.get(Room, room_id) do
      nil ->
        {:error, :room_not_found}

      room ->
        room
        |> Room.changeset(%{name: name})
        |> Repo.update()
        |> case do
          {:ok, _} -> :ok
          {:error, cs} -> {:error, cs}
        end
    end
  end

  defp maybe_update_room_name(_, _), do: {:error, :invalid_name}

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
