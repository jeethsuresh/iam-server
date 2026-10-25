defmodule LakehouseIam.Repo.Migrations.MatrixRoomDirectory do
  use Ecto.Migration

  def change do
    alter table(:rooms) do
      add(:visibility, :string, null: false, default: "private")
    end

    create table(:matrix_room_aliases, primary_key: false) do
      add(:name, :text, primary_key: true)

      add(:local_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:creator_id, references(:principals, type: :binary_id, on_delete: :nilify_all))
    end

    create(index(:matrix_room_aliases, [:local_room_id]))

    execute(
      "INSERT INTO matrix_room_aliases (name, local_room_id) SELECT alias, id FROM rooms WHERE alias IS NOT NULL",
      "DELETE FROM matrix_room_aliases"
    )
  end
end
