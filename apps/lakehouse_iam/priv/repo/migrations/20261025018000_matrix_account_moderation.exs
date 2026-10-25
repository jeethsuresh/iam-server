defmodule LakehouseIam.Repo.Migrations.MatrixAccountModeration do
  use Ecto.Migration

  def change do
    alter table(:principals) do
      add(:matrix_locked, :boolean, null: false, default: false)
      add(:matrix_suspended, :boolean, null: false, default: false)
    end
  end
end
