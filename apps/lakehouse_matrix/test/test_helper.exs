ExUnit.start()
Ecto.Adapters.SQL.Sandbox.mode(LakehouseIam.Repo, :manual)
{:ok, _} = Application.ensure_all_started(:lakehouse_matrix)
