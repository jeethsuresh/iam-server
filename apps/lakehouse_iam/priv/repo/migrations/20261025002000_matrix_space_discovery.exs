defmodule LakehouseIam.Repo.Migrations.MatrixSpaceDiscovery do
  use Ecto.Migration

  def change do
    create table(:matrix_hierarchy_cache, primary_key: false) do
      add(:server, :text, primary_key: true)
      add(:room_id, :text, primary_key: true)
      add(:suggested, :boolean, primary_key: true)
      add(:response, :map, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
    end

    create(index(:matrix_hierarchy_cache, [:expires_at]))

    create table(:matrix_hierarchy_cursors, primary_key: false) do
      add(:token, :text, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:device_id, :text, null: false)
      add(:root, :text, null: false)
      add(:state, :map, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
    end

    create(index(:matrix_hierarchy_cursors, [:principal_id, :device_id]))
    create(index(:matrix_hierarchy_cursors, [:expires_at]))
  end
end
