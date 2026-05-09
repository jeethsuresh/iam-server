defmodule LakehouseWeb.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      LakehouseWeb.Telemetry,
      {Phoenix.PubSub, name: LakehouseWeb.PubSub},
      LakehouseWeb.Presence,
      LakehouseWeb.Endpoint
    ]

    opts = [strategy: :one_for_one, name: LakehouseWeb.Supervisor]
    Supervisor.start_link(children, opts)
  end

  @impl true
  def config_change(changed, _new, removed) do
    LakehouseWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
