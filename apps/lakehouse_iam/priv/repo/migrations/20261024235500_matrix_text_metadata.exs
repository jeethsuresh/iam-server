defmodule LakehouseIam.Repo.Migrations.MatrixTextMetadata do
  use Ecto.Migration

  def change do
    alter table(:rooms) do
      modify(:name, :text, from: :string)
      modify(:avatar_url, :text, from: :string)
    end

    alter table(:media_objects) do
      modify(:filename, :text, from: :string)
    end
  end
end
