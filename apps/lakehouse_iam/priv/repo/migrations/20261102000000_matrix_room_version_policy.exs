defmodule LakehouseIam.Repo.Migrations.MatrixRoomVersionPolicy do
  use Ecto.Migration

  def change do
    create table(:matrix_peer_room_versions, primary_key: false) do
      add(:server_name, :text, primary_key: true)
      add(:versions, {:array, :text}, null: false, default: [])
      add(:confirmed_at, :utc_datetime_usec)
      add(:retry_at, :utc_datetime_usec, null: false)
      add(:source, :text, null: false)
    end

    create table(:matrix_room_version_checks, primary_key: false) do
      add(:room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        primary_key: true
      )

      add(:next_check_at, :utc_datetime_usec, null: false)
      add(:status, :text, null: false)
      add(:target_version, :text)
    end

    create(index(:matrix_room_version_checks, [:next_check_at]))
  end
end
