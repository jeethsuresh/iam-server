defmodule LakehouseIam.Repo.Migrations.MatrixRiverRequests do
  use Ecto.Migration

  def change do
    create table(:matrix_river_requests, primary_key: false) do
      add(:request_id, :text, primary_key: true)
      add(:event_id, :text, null: false)

      add(:local_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        null: false
      )
    end
  end
end
