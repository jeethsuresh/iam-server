defmodule LakehouseIam.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      LakehouseIam.Repo
    ]

    opts = [strategy: :one_for_one, name: LakehouseIam.Supervisor]

    case Supervisor.start_link(children, opts) do
      {:ok, pid} ->
        if Application.get_env(:lakehouse_iam, :bootstrap_on_start, true) do
          _ = LakehouseIam.Bootstrap.run()
        end

        {:ok, pid}

      err ->
        err
    end
  end
end
