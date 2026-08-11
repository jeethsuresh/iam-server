defmodule LakehouseMatrix.State do
  @moduledoc """
  Current room state events (m.room.name, m.room.member, etc.).
  """
  import Ecto.Query

  alias LakehouseIam.Repo
  alias LakehouseMatrix.Schema.RoomState

  @spec upsert(Ecto.UUID.t(), String.t(), String.t(), map(), String.t(), integer()) :: :ok
  def upsert(room_id, state_key, type, content, event_id, origin_server_ts) do
    attrs = %{
      room_id: room_id,
      state_key: state_key,
      type: type,
      content:
        Map.merge(content, %{
          "_event_id" => event_id,
          "_origin_server_ts" => origin_server_ts
        })
    }

    case Repo.one(
           from s in RoomState,
             where: s.room_id == ^room_id and s.state_key == ^state_key and s.type == ^type
         ) do
      nil ->
        %RoomState{}
        |> RoomState.changeset(attrs)
        |> Repo.insert!()

      existing ->
        existing
        |> RoomState.changeset(attrs)
        |> Repo.update!()
    end

    :ok
  end

  @spec get(Ecto.UUID.t(), String.t(), String.t()) :: map() | nil
  def get(room_id, type, state_key \\ "") do
    case Repo.one(
           from s in RoomState,
             where: s.room_id == ^room_id and s.type == ^type and s.state_key == ^state_key
         ) do
      nil -> nil
      row -> to_client_event(row)
    end
  end

  @spec list_for_room(Ecto.UUID.t()) :: [map()]
  def list_for_room(room_id) do
    Repo.all(from s in RoomState, where: s.room_id == ^room_id, order_by: [asc: s.inserted_at])
    |> Enum.map(&to_client_event/1)
  end

  defp to_client_event(%RoomState{} = s) do
    %{
      "type" => s.type,
      "state_key" => s.state_key,
      "content" => Map.drop(s.content, ["_event_id", "_origin_server_ts"]),
      "event_id" => Map.get(s.content, "_event_id"),
      "origin_server_ts" => Map.get(s.content, "_origin_server_ts")
    }
  end
end
