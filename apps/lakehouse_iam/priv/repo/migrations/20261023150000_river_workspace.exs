defmodule LakehouseIam.Repo.Migrations.RiverWorkspace do
  use Ecto.Migration
  def change do
    alter table(:room_events) do
      add :sticky_duration_ms, :integer
    end
    create table(:river_rtc_members, primary_key: false) do
      add :id, :text, primary_key: true
      add :room_id, references(:rooms, type: :uuid, on_delete: :delete_all), null: false
      add :principal_id, references(:principals, type: :uuid, on_delete: :delete_all), null: false
      add :app_origin, :text, null: false
      add :token_id, references(:app_tokens, type: :uuid, on_delete: :delete_all), null: false
      add :expires_at, :utc_datetime_usec, null: false
    end
    create index(:river_rtc_members, [:room_id, :expires_at])
    create table(:river_files, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :room_id, references(:rooms, type: :uuid, on_delete: :delete_all), null: false
      add :uploader_id, references(:principals, type: :uuid, on_delete: :delete_all), null: false
      add :event_id, :text, null: false
      add :manifest, :map, null: false
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end
    create index(:river_files, [:room_id, :inserted_at, :id])
    create table(:river_entry_reads, primary_key: false) do
      add :principal_id, references(:principals, type: :uuid, on_delete: :delete_all), primary_key: true
      add :event_id, :text, primary_key: true
    end
  end
end
