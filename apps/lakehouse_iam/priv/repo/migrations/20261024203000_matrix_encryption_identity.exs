defmodule LakehouseIam.Repo.Migrations.MatrixEncryptionIdentity do
  use Ecto.Migration

  def change do
    create table(:matrix_cross_signing, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:usage, :text, null: false)
      add(:key, :map, null: false)
    end

    create(unique_index(:matrix_cross_signing, [:principal_id, :usage]))

    create table(:matrix_key_signatures, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:target_user, :text, null: false)
      add(:target_key, :text, null: false)
      add(:signatures, :map, null: false)
    end

    create(unique_index(:matrix_key_signatures, [:principal_id, :target_user, :target_key]))

    create table(:matrix_uia_sessions, primary_key: false) do
      add(:id, :text, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:device_id, :text, null: false)
      add(:action, :text, null: false)
      add(:request_hash, :binary, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
    end
  end
end
