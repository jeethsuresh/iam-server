defmodule LakehouseIam.Repo.Migrations.MatrixMediaReservations do
  use Ecto.Migration

  def change do
    create table(:matrix_media_reservations, primary_key: false) do
      add(:media_id, :uuid, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:created_at, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:completed_at, :utc_datetime_usec)
    end

    create(index(:matrix_media_reservations, [:principal_id, :expires_at]))
  end
end
