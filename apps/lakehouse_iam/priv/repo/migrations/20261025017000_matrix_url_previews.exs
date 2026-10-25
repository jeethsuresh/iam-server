defmodule LakehouseIam.Repo.Migrations.MatrixUrlPreviews do
  use Ecto.Migration

  def change do
    create table(:matrix_url_previews, primary_key: false) do
      add(:url_hash, :binary, primary_key: true)
      add(:response, :map, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
    end

    create(index(:matrix_url_previews, [:expires_at]))

    create table(:matrix_preview_requests, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:requested_at, :utc_datetime_usec, null: false)
    end

    create(index(:matrix_preview_requests, [:principal_id, :requested_at]))
  end
end
