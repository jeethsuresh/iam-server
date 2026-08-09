defmodule LakehouseIam.DataCase do
  @moduledoc false
  use ExUnit.CaseTemplate

  using do
    quote do
      alias LakehouseIam.Repo

      import Ecto
      import Ecto.Changeset
      import Ecto.Query
    end
  end

  setup tags do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(LakehouseIam.Repo)

    unless tags[:async] do
      Ecto.Adapters.SQL.Sandbox.mode(LakehouseIam.Repo, {:shared, self()})
    end

    :ok
  end
end
