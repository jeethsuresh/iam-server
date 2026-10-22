defmodule LakehouseIam.Repo.Migrations.RenewableSessions do
  use Ecto.Migration

  def change do
    create table(:iam_sessions, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:kind, :string, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:revoked_at, :utc_datetime_usec)
      timestamps(type: :utc_datetime_usec)
    end

    create(index(:iam_sessions, [:principal_id]))
    create(index(:iam_sessions, [:expires_at]))

    create table(:iam_refresh_tokens, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:session_id, references(:iam_sessions, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:token_hash, :text, null: false)
      add(:used_at, :utc_datetime_usec)
      add(:replacement_hash, :text)
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create(unique_index(:iam_refresh_tokens, [:token_hash]))
    create(index(:iam_refresh_tokens, [:session_id]))
  end
end
