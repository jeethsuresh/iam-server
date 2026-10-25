defmodule LakehouseMatrix.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Registry, keys: :unique, name: LakehouseMatrix.RoomRegistry},
      {DynamicSupervisor, strategy: :one_for_one, name: LakehouseMatrix.RoomDynamicSupervisor}
    ]

    children =
      if Application.get_env(:lakehouse_matrix, :federation_enabled, false),
        do: children ++ [LakehouseMatrix.Federation.Outbox, LakehouseMatrix.Federation.Inbox],
        else: children

    children =
      if LakehouseMatrix.Protocol.Rooms.enabled?(),
        do: children ++ [LakehouseMatrix.Ephemeral],
        else: children

    Supervisor.start_link(children, strategy: :one_for_one, name: LakehouseMatrix.Supervisor)
  end
end
