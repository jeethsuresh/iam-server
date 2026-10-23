defmodule LakehouseIam.Repo.Migrations.RiverChannelsAndSocial do
  use Ecto.Migration

  def change do
    create table(:river_channels, primary_key: false) do
      add :id, references(:rooms, type: :uuid, on_delete: :delete_all), primary_key: true
      add :space_id, references(:rooms, type: :uuid, on_delete: :delete_all), null: false
      add :kind, :string, null: false
      timestamps(type: :utc_datetime_usec)
    end
    create index(:river_channels, [:space_id])
    create constraint(:river_channels, :distinct_channel_parent, check: "id <> space_id")
    create constraint(:river_channels, :channel_kind, check: "kind IN ('text', 'drop_in')")

    create table(:river_directs, primary_key: false) do
      add :id, references(:rooms, type: :uuid, on_delete: :delete_all), primary_key: true
      add :low_id, references(:principals, type: :uuid, on_delete: :delete_all), null: false
      add :high_id, references(:principals, type: :uuid, on_delete: :delete_all), null: false
    end
    create unique_index(:river_directs, [:low_id, :high_id])
    create constraint(:river_directs, :ordered_direct_pair, check: "low_id < high_id")

    create table(:river_friendships, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :low_id, references(:principals, type: :uuid, on_delete: :delete_all), null: false
      add :high_id, references(:principals, type: :uuid, on_delete: :delete_all), null: false
      add :requested_by, references(:principals, type: :uuid, on_delete: :delete_all), null: false
      add :status, :string, null: false
      timestamps(type: :utc_datetime_usec)
    end
    create unique_index(:river_friendships, [:low_id, :high_id])
    create index(:river_friendships, [:high_id])
    create constraint(:river_friendships, :ordered_friend_pair, check: "low_id < high_id")
    create constraint(:river_friendships, :friend_status, check: "status IN ('pending', 'accepted', 'none')")

    create table(:river_friend_blocks, primary_key: false) do
      add :owner_id, references(:principals, type: :uuid, on_delete: :delete_all), primary_key: true
      add :target_id, references(:principals, type: :uuid, on_delete: :delete_all), primary_key: true
    end
    create constraint(:river_friend_blocks, :no_self_block, check: "owner_id <> target_id")

    # Private account events, never broadcast to a group's timeline or roster.
    create table(:river_social_events, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :actor_id, references(:principals, type: :uuid, on_delete: :delete_all), null: false
      add :target_id, references(:principals, type: :uuid, on_delete: :delete_all), null: false
      add :app_origin, :string, null: false
      add :txn_id, :string, null: false
      add :action, :string, null: false
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end
    create unique_index(:river_social_events, [:actor_id, :app_origin, :txn_id])
    create index(:river_social_events, [:target_id, :inserted_at])

    create table(:river_room_reads, primary_key: false) do
      add :principal_id, references(:principals, type: :uuid, on_delete: :delete_all), primary_key: true
      add :room_id, references(:rooms, type: :uuid, on_delete: :delete_all), primary_key: true
      add :event_id, references(:room_events, type: :uuid, on_delete: :delete_all), null: false
      timestamps(type: :utc_datetime_usec)
    end
  end
end
