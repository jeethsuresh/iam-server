defmodule LakehouseIam.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      LakehouseIam.Repo,
      LakehouseIam.Federated
    ]

    opts = [strategy: :one_for_one, name: LakehouseIam.Supervisor]

    case Supervisor.start_link(children, opts) do
      {:ok, pid} ->
        _ = LakehouseIam.Bootstrap.run()
        {:ok, pid}

      err ->
        err
    end
  end
end
