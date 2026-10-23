defmodule LakehouseIam.Release do
  @moduledoc "Explicit release tasks; application startup never creates or migrates a production database."

  def migrate do
    Application.load(:lakehouse_iam)

    {:ok, _, _} =
      Ecto.Migrator.with_repo(LakehouseIam.Repo, fn repo ->
        Ecto.Migrator.run(repo, :up, all: true)
      end)
  end

  def bootstrap do
    {:ok, _} = Application.ensure_all_started(:lakehouse_iam)
    Code.eval_file(Application.app_dir(:lakehouse_iam, "priv/repo/seeds.exs"))
    LakehouseIam.Bootstrap.run()
  end
end
