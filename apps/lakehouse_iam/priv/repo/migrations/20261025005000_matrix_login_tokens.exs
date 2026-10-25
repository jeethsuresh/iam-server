defmodule LakehouseIam.Repo.Migrations.MatrixLoginTokens do
  use Ecto.Migration

  def change do
    alter table(:matrix_sessions) do
      add(:refresh_hash, :binary)
    end

    create(unique_index(:matrix_sessions, [:refresh_hash]))

    create table(:matrix_login_tokens, primary_key: false) do
      add(:token_hash, :binary, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:source_device, :text)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:used_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create(index(:matrix_login_tokens, [:principal_id, :inserted_at]))

    create table(:matrix_sso_requests, primary_key: false) do
      add(:id, :text, primary_key: true)
      add(:redirect_url, :text, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
    end
  end
end
