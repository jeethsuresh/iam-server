defmodule LakehouseIam.Repo.Migrations.MatrixStateProjection do
  use Ecto.Migration

  def change do
    alter table(:room_events) do
      add(:timeline_visible, :boolean, null: false, default: true)
    end
  end
end
