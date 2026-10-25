defmodule LakehouseIam.Repo.Migrations.MatrixPresence do
  use Ecto.Migration

  def change do
    create table(:matrix_user_presence, primary_key: false) do
      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        primary_key: true
      )

      add(:content, :map, null: false)
      add(:updated_at, :utc_datetime_usec, null: false)
    end

    create(index(:matrix_ephemeral_events, [:expires_at]))
  end
end
