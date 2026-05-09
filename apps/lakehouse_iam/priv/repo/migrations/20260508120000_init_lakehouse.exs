defmodule LakehouseIam.Repo.Migrations.InitLakehouse do
  use Ecto.Migration

  def up do
    execute("CREATE EXTENSION IF NOT EXISTS citext", "")

    create table(:principals, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :type, :string, null: false
      add :username, :citext
      add :active, :boolean, null: false, default: false
      add :meta, :map, null: false, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:principals, [:username], where: "username IS NOT NULL")

    create table(:credentials, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :principal_id, references(:principals, type: :binary_id, on_delete: :delete_all), null: false
      add :kind, :string, null: false
      add :secret_hash, :text, null: false
      add :meta, :map, null: false, default: %{}

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:credentials, [:principal_id])

    create table(:roles, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:roles, [:name])

    create table(:permissions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:permissions, [:name])

    create table(:role_permissions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :role_id, references(:roles, type: :binary_id, on_delete: :delete_all), null: false
      add :permission_id, references(:permissions, type: :binary_id, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:role_permissions, [:role_id, :permission_id])

    create table(:resources, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :arn, :text, null: false

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:resources, [:arn])

    create table(:grants, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :principal_id, references(:principals, type: :binary_id, on_delete: :delete_all), null: false
      add :role_id, references(:roles, type: :binary_id, on_delete: :delete_all), null: false

      add :resource_id, references(:resources, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:grants, [:principal_id])

    create unique_index(:grants, [:principal_id, :role_id],
             where: "resource_id IS NULL",
             name: :grants_principal_role_global_unique
           )

    create unique_index(:grants, [:principal_id, :role_id, :resource_id],
             where: "resource_id IS NOT NULL",
             name: :grants_principal_role_resource_unique
           )

    create table(:rooms, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alias, :string
      add :name, :string, null: false
      add :topic, :text

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:rooms, [:alias], where: "alias IS NOT NULL")

    create table(:room_memberships, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :room_id, references(:rooms, type: :binary_id, on_delete: :delete_all), null: false
      add :principal_id, references(:principals, type: :binary_id, on_delete: :delete_all), null: false
      add :membership_state, :map, null: false, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:room_memberships, [:room_id, :principal_id])

    create table(:room_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :room_id, references(:rooms, type: :binary_id, on_delete: :delete_all), null: false
      add :event_id, :string, null: false
      add :type, :string, null: false
      add :content, :map, null: false, default: %{}

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:room_events, [:room_id])

    create table(:room_state, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :room_id, references(:rooms, type: :binary_id, on_delete: :delete_all), null: false
      add :state_key, :string, null: false
      add :type, :string, null: false
      add :content, :map, null: false, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:room_state, [:room_id, :state_key, :type])

    create table(:call_sessions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :room_id, references(:rooms, type: :binary_id, on_delete: :nilify_all)
      add :status, :string, null: false, default: "pending"
      add :meta, :map, null: false, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create table(:webrtc_peers, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :call_session_id, references(:call_sessions, type: :binary_id, on_delete: :delete_all), null: false
      add :principal_id, references(:principals, type: :binary_id, on_delete: :nilify_all)
      add :meta, :map, null: false, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create index(:webrtc_peers, [:call_session_id])
  end

  def down do
    drop table(:webrtc_peers)
    drop table(:call_sessions)
    drop table(:room_state)
    drop table(:room_events)
    drop table(:room_memberships)
    drop table(:rooms)
    drop table(:grants)
    drop table(:resources)
    drop table(:role_permissions)
    drop table(:permissions)
    drop table(:roles)
    drop table(:credentials)
    drop table(:principals)
  end
end
