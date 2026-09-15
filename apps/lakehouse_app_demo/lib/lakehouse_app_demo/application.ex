defmodule LakehouseAppDemo.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children =
      if Application.get_env(:lakehouse_app_demo, :enabled, false) do
        [LakehouseAppDemo.Endpoint]
      else
        []
      end

    opts = [strategy: :one_for_one, name: LakehouseAppDemo.Supervisor]
    Supervisor.start_link(children, opts)
  end

  @impl true
  def config_change(changed, _new, removed) do
    if Process.whereis(LakehouseAppDemo.Endpoint) do
      LakehouseAppDemo.Endpoint.config_change(changed, removed)
    end

    :ok
  end
end
