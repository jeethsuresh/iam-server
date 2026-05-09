defmodule LakehouseMatrix.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Registry, keys: :unique, name: LakehouseMatrix.RoomRegistry},
      {DynamicSupervisor, strategy: :one_for_one, name: LakehouseMatrix.RoomDynamicSupervisor}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: LakehouseMatrix.Supervisor)
  end
end
