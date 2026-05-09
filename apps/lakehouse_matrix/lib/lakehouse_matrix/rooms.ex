defmodule LakehouseMatrix.Rooms do
  @moduledoc """
  Matrix-style room persistence + process orchestration.
  """
  import Ecto.Query

  alias LakehouseIam.Repo
  alias LakehouseMatrix.RoomServer
  alias LakehouseMatrix.Schema.Room
  alias LakehouseMatrix.RoomSupervisor

  @spec list_rooms() :: [Room.t()]
  def list_rooms do
    Repo.all(from r in Room, order_by: [desc: r.inserted_at])
  end

  @spec get_room(Ecto.UUID.t()) :: Room.t() | nil
  def get_room(id), do: Repo.get(Room, id)

  @spec create_room(map()) :: {:ok, Room.t()} | {:error, Ecto.Changeset.t()}
  def create_room(attrs) do
    cs = Room.changeset(%Room{}, attrs)

    case Repo.insert(cs) do
      {:ok, room} ->
        _ = ensure_started(room.id)
        {:ok, room}

      err ->
        err
    end
  end

  @doc """
  Ensures a `LakehouseMatrix.RoomServer` is running for the given room id.
  """
  @spec ensure_started(Ecto.UUID.t()) :: {:ok, pid()} | {:error, term()}
  def ensure_started(room_id) do
    case Registry.lookup(LakehouseMatrix.RoomRegistry, room_id) do
      [{pid, _}] -> {:ok, pid}
      [] -> RoomSupervisor.start_room(room_id)
    end
  end

  defdelegate broadcast(room_id, msg), to: RoomServer
end
