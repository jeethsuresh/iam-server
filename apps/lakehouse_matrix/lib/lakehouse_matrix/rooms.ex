defmodule LakehouseMatrix.Rooms do
  @moduledoc """
  Matrix-style room persistence + process orchestration.
  """
  import Ecto.Query

  alias LakehouseIam.Repo
  alias LakehouseMatrix.{Memberships, RoomServer, RoomSupervisor}
  alias LakehouseMatrix.Schema.Room

  @spec list_rooms() :: [Room.t()]
  def list_rooms do
    Repo.all(from r in Room, order_by: [desc: r.inserted_at])
  end

  @spec list_rooms_for(Ecto.UUID.t()) :: [Room.t()]
  def list_rooms_for(principal_id) do
    Memberships.list_joined_rooms(principal_id)
  end

  @spec get_room(Ecto.UUID.t()) :: Room.t() | nil
  def get_room(id), do: Repo.get(Room, id)

  @spec get_room_by_alias(String.t()) :: {:ok, Room.t()} | {:error, :room_not_found}
  def get_room_by_alias(alias_name) do
    case Repo.one(from r in Room, where: r.alias == ^alias_name) do
      nil -> {:error, :room_not_found}
      room -> {:ok, room}
    end
  end

  @spec create_room(map()) :: {:ok, Room.t()} | {:error, Ecto.Changeset.t()}
  def create_room(attrs) do
    case create_room_record(attrs) do
      {:ok, room} ->
        _ = ensure_started(room.id)
        {:ok, room}

      err ->
        err
    end
  end

  @spec create_room_record(map()) :: {:ok, Room.t()} | {:error, Ecto.Changeset.t()}
  def create_room_record(attrs) do
    Repo.insert(Room.changeset(%Room{}, attrs))
  end

  @doc """
  Ensures a `LakehouseMatrix.RoomServer` is running for the given room id.
  """
  @spec ensure_started(Ecto.UUID.t()) :: {:ok, pid()} | {:error, term()}
  def ensure_started(room_id) do
    case Registry.lookup(LakehouseMatrix.RoomRegistry, room_id) do
      [{pid, _}] ->
        allow_sandbox(pid)
        {:ok, pid}

      [] ->
        case RoomSupervisor.start_room(room_id) do
          {:ok, pid} ->
            allow_sandbox(pid)
            RoomServer.load_caches(room_id)
            {:ok, pid}

          other ->
            other
        end
    end
  end

  defp allow_sandbox(pid) do
    try do
      Ecto.Adapters.SQL.Sandbox.allow(LakehouseIam.Repo, self(), pid)
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end

  defdelegate broadcast(room_id, msg), to: RoomServer, as: :broadcast_event
end
