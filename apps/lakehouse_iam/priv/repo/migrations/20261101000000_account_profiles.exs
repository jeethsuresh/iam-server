defmodule LakehouseIam.Repo.Migrations.AccountProfiles do
  use Ecto.Migration

  def change do
    alter table(:principals) do
      add(:full_name, :text)
      add(:picture_key, :uuid)
    end

    create(unique_index(:principals, [:picture_key]))

    create table(:profile_pictures, primary_key: false) do
      add(:id, :uuid, primary_key: true)

      add(:principal_id, references(:principals, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(:content_type, :string, null: false)
      add(:data, :binary, null: false)
    end

    create(unique_index(:profile_pictures, [:principal_id]))
  end
end
