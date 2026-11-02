defmodule LakehouseIam.Repo.Migrations.MatrixAppstorePush do
  use Ecto.Migration

  def change do
    create table(:matrix_appstore_outbox, primary_key: false) do
      add(
        :notification_id,
        references(:matrix_notifications, type: :bigint, on_delete: :delete_all),
        primary_key: true
      )

      add(:available_at, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:lease_until, :utc_datetime_usec)
      add(:attempts, :integer, null: false, default: 0)
    end

    create(index(:matrix_appstore_outbox, [:available_at]))
    create(index(:matrix_appstore_outbox, [:expires_at]))
  end
end
