defmodule LakehouseIam.Repo.Migrations.MatrixForgetting do
  use Ecto.Migration

  def change do
    create table(:matrix_room_forgetting, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:local_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:forgotten, :boolean, null: false)
      add(:stream_id, :bigint, null: false)
    end

    create(index(:matrix_room_forgetting, [:principal_id, :local_room_id, :stream_id]))

    execute(
      "CREATE TRIGGER matrix_stream_trigger BEFORE INSERT ON matrix_room_forgetting FOR EACH ROW EXECUTE FUNCTION matrix_stream_position()",
      "DROP TRIGGER matrix_stream_trigger ON matrix_room_forgetting"
    )
  end
end
