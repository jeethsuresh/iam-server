defmodule LakehouseMatrix.RoomSupervisor do
  @moduledoc false

  @spec start_room(Ecto.UUID.t()) :: DynamicSupervisor.on_start_child_result()
  def start_room(room_id) do
    spec = {LakehouseMatrix.RoomServer, room_id}

    case DynamicSupervisor.start_child(LakehouseMatrix.RoomDynamicSupervisor, spec) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      err -> err
    end
  end
end
