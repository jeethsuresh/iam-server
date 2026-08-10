defmodule LakehouseMatrix.Events.Handlers.RoomAvatar do
  @moduledoc false
  @behaviour LakehouseMatrix.Events.Handler

  alias LakehouseIam.Repo
  alias LakehouseMatrix.Events.Context
  alias LakehouseMatrix.Schema.Room
  alias LakehouseMatrix.State

  @impl true
  def handle(%Context{} = ctx) do
    url = Map.get(ctx.content, "url")

    with :ok <- maybe_update_room_avatar(ctx.room_id, url),
         :ok <-
           State.upsert(ctx.room_id, "", ctx.type, ctx.content, ctx.event_id, ctx.origin_server_ts) do
      {:ok, to_event_map(ctx)}
    end
  end

  defp maybe_update_room_avatar(room_id, url) when is_binary(url) and url != "" do
    case Repo.get(Room, room_id) do
      nil ->
        {:error, :room_not_found}

      room ->
        room
        |> Room.changeset(%{avatar_url: url})
        |> Repo.update()
        |> case do
          {:ok, _} -> :ok
          {:error, cs} -> {:error, cs}
        end
    end
  end

  defp maybe_update_room_avatar(_, _), do: {:error, :invalid_avatar}

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
