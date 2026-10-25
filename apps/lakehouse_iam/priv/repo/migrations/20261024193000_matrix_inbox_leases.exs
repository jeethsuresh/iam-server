defmodule LakehouseIam.Repo.Migrations.MatrixInboxLeases do
  use Ecto.Migration

  def change do
    alter table(:matrix_federation_inbox) do
      add(:lease_until, :utc_datetime_usec)
      add(:failed_at, :utc_datetime_usec)
    end
  end
end
