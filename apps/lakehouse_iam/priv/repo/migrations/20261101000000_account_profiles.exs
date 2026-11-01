defmodule LakehouseIam.Repo.Migrations.AccountProfiles do
  use Ecto.Migration

  def change do
    alter table(:principals) do
      add(:full_name, :string, size: 120)
      add(:picture, :text)
      add(:picture_key, :uuid)
    end

    create(unique_index(:principals, [:picture_key]))
  end
end
