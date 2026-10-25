defmodule LakehouseIam.Repo.Migrations.MatrixPrivateMediaRefs do
  use Ecto.Migration

  def change do
    create table(:matrix_private_media_refs, primary_key: false) do
      add(:media_id, references(:media_objects, type: :binary_id, on_delete: :delete_all),
        primary_key: true
      )

      add(:event_id, references(:room_events, type: :binary_id, on_delete: :delete_all),
        primary_key: true
      )

      add(:room_id, references(:rooms, type: :binary_id, on_delete: :delete_all), null: false)
    end

    create(index(:matrix_private_media_refs, [:room_id]))
  end
end
