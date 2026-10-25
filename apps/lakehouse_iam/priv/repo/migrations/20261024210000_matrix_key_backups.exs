defmodule LakehouseIam.Repo.Migrations.MatrixKeyBackups do
  use Ecto.Migration

  def change do
    create table(:matrix_key_backups, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:algorithm, :text, null: false)
      add(:auth_data, :map, null: false)
      add(:etag, :bigint, null: false, default: 0)
    end

    create(index(:matrix_key_backups, [:principal_id, :id]))

    create table(:matrix_backup_sessions, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:backup_id, references(:matrix_key_backups, type: :bigint, on_delete: :delete_all),
        null: false
      )

      add(:room_id, :text, null: false)
      add(:session_id, :text, null: false)
      add(:data, :map, null: false)
    end

    create(unique_index(:matrix_backup_sessions, [:backup_id, :room_id, :session_id]))
  end
end
