defmodule LakehouseIam.Repo.Migrations.MatrixPolicySoftFailures do
  use Ecto.Migration

  def change do
    alter table(:matrix_pdus) do
      add(:policy_rejected, :boolean, null: false, default: false)
    end
  end
end
