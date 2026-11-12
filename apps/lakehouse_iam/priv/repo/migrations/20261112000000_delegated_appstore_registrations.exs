defmodule LakehouseIam.Repo.Migrations.DelegatedAppstoreRegistrations do
  use Ecto.Migration

  def up do
    alter table(:protocol_registrations) do
      add(:provider_origin, :text, null: false, default: "")
    end

    drop(unique_index(:protocol_registrations, [:grant_id, :spec_id]))
    create(unique_index(:protocol_registrations, [:grant_id, :spec_id, :provider_origin]))
  end

  def down do
    execute("DELETE FROM protocol_registrations WHERE provider_origin <> ''")
    drop(unique_index(:protocol_registrations, [:grant_id, :spec_id, :provider_origin]))
    create(unique_index(:protocol_registrations, [:grant_id, :spec_id]))

    alter table(:protocol_registrations) do
      remove(:provider_origin)
    end
  end
end
