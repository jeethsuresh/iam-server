defmodule LakehouseIam.Repo.Migrations.MediaAndRoomAvatar do
  use Ecto.Migration

  def change do
    create table(:media_objects, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :uploader_id, references(:principals, type: :binary_id, on_delete: :nilify_all)
      add :filename, :string
      add :content_type, :string, null: false
      add :byte_size, :integer, null: false
      add :thumbnail_id, :binary_id
      add :kind, :string, null: false, default: "file"

      timestamps(type: :utc_datetime_usec)
    end

    create index(:media_objects, [:uploader_id])
    create index(:media_objects, [:thumbnail_id])

    alter table(:rooms) do
      add :avatar_url, :string
    end
  end
end
