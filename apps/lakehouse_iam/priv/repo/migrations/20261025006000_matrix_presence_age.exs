defmodule LakehouseIam.Repo.Migrations.MatrixPresenceAge do
  use Ecto.Migration

  def change do
    alter table(:matrix_ephemeral_events) do
      add(:received_at, :utc_datetime_usec, null: false, default: fragment("now()"))
    end
  end
end
