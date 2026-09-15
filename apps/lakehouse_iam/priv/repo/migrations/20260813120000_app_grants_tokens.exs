defmodule LakehouseIam.Repo.Migrations.AppGrantsTokens do
  use Ecto.Migration

  def change do
    create table(:app_grants, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :principal_id, references(:principals, type: :binary_id, on_delete: :delete_all), null: false
      add :app_origin, :text, null: false
      add :scopes, {:array, :string}, null: false, default: []
      add :room_mode, :string, null: false, default: "selected"
      add :room_ids, {:array, :binary_id}, null: false, default: []

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:app_grants, [:principal_id, :app_origin])

    create table(:app_tokens, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :grant_id, references(:app_grants, type: :binary_id, on_delete: :delete_all), null: false
      add :token_hash, :text, null: false
      add :kind, :string, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :revoked_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create unique_index(:app_tokens, [:token_hash])
    create index(:app_tokens, [:grant_id])
  end
end
