defmodule LakehouseIam.Repo.Migrations.AppSessionLogout do
  use Ecto.Migration

  def change do
    alter table(:app_tokens) do
      add(:session_id, references(:iam_sessions, type: :binary_id, on_delete: :delete_all))
    end

    create(index(:app_tokens, [:session_id]))
  end
end
