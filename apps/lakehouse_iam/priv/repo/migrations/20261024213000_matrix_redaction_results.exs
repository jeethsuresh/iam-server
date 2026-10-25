defmodule LakehouseIam.Repo.Migrations.MatrixRedactionResults do
  use Ecto.Migration

  def change do
    alter table(:matrix_pdus) do
      add(:redacted_by, :text)
      add(:redaction_applied, :boolean, null: false, default: false)
    end

    create(index(:matrix_pdus, [:local_room_id, :redacted_by]))
  end
end
