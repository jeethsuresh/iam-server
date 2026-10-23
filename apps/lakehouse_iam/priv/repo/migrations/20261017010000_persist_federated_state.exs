defmodule LakehouseIam.Repo.Migrations.PersistFederatedState do
  use Ecto.Migration

  def change do
    create table(:iam_federated_entries, primary_key: false) do
      add(:key, :text, primary_key: true)
      add(:kind, :text, null: false)
      add(:data, :map, null: false)
      add(:expires_at, :bigint, null: false)
    end

    create(index(:iam_federated_entries, [:expires_at]))
  end
end
