defmodule LakehouseIam.Repo.Migrations.MatrixMediaVisibility do
  use Ecto.Migration

  def change do
    alter table(:media_objects) do
      add(:matrix_public, :boolean, null: false, default: false)
    end
  end
end
