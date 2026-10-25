defmodule LakehouseIam.Repo.Migrations.MatrixRoomUpgrades do
  use Ecto.Migration

  def change do
    create table(:matrix_room_upgrades, primary_key: false) do
      add(:old_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        primary_key: true
      )

      add(:new_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all), null: false)

      add(
        :tombstone_id,
        references(:matrix_pdus, column: :event_id, type: :text, on_delete: :delete_all),
        null: false
      )
    end

    create(unique_index(:matrix_room_upgrades, [:new_room_id]))
  end
end
