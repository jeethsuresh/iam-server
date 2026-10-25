defmodule LakehouseIam.Repo.Migrations.MatrixDeactivationLeases do
  use Ecto.Migration

  def change do
    alter table(:matrix_deactivation_jobs) do
      add(:lease_token, :uuid)
      add(:after_room_id, :uuid)
    end
  end
end
