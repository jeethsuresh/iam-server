defmodule LakehouseIam.Repo.Migrations.MatrixOpenidReports do
  use Ecto.Migration

  def change do
    create table(:matrix_openid_tokens, primary_key: false) do
      add(:token_hash, :binary, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:expires_at, :utc_datetime_usec, null: false)
    end

    create(index(:matrix_openid_tokens, [:expires_at]))

    create table(:matrix_reports, primary_key: false) do
      add(:id, :uuid, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:kind, :text, null: false)
      add(:room_ref, :text)
      add(:event_id, :text)
      add(:user_id, :text)
      add(:reason, :text, null: false)
      add(:inserted_at, :utc_datetime_usec, null: false)
    end

    create(index(:matrix_reports, [:principal_id, :inserted_at]))
    create(index(:matrix_reports, [:inserted_at]))
  end
end
