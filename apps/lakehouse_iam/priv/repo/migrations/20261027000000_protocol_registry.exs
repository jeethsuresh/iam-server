defmodule LakehouseIam.Repo.Migrations.ProtocolRegistry do
  use Ecto.Migration

  def change do
    create table(:protocol_specs, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:protocol, :text, null: false)
      add(:version, :text, null: false)
      add(:owner, :text, null: false)
      add(:specification, :map, null: false)
    end

    create(unique_index(:protocol_specs, [:protocol, :version]))

    create table(:protocol_registrations, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:grant_id, references(:app_grants, type: :uuid, on_delete: :delete_all), null: false)
      add(:spec_id, references(:protocol_specs, type: :uuid, on_delete: :delete_all), null: false)
    end

    create(unique_index(:protocol_registrations, [:grant_id, :spec_id]))

    create table(:protocol_invocations, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:sender, :text, null: false)
      add(:request_id, :text, null: false)
      add(:digest, :text, null: false)
      add(:created_at, :utc_datetime_usec, null: false)
    end

    create(unique_index(:protocol_invocations, [:sender, :request_id]))
    create(index(:protocol_invocations, [:created_at]))

    create table(:protocol_deliveries, primary_key: false) do
      add(:id, :uuid, primary_key: true)

      add(:invocation_id, references(:protocol_invocations, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(
        :registration_id,
        references(:protocol_registrations, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(:envelope, :map, null: false)
      add(:attempts, :integer, null: false, default: 0)
      add(:available_at, :utc_datetime_usec, null: false)
      add(:lease, :uuid)
    end

    create(index(:protocol_deliveries, [:available_at]))
  end
end
