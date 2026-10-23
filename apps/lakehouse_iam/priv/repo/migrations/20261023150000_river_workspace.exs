defmodule LakehouseIam.Repo.Migrations.RiverWorkspace do
  use Ecto.Migration
  def change do
    create table(:river_entry_reads, primary_key: false) do
      add :principal_id, references(:principals, type: :uuid, on_delete: :delete_all), primary_key: true
      add :event_id, :text, primary_key: true
    end
  end
end
