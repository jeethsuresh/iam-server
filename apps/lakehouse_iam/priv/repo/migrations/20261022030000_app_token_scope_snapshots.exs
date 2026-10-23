defmodule LakehouseIam.Repo.Migrations.AppTokenScopeSnapshots do
  use Ecto.Migration

  def change do
    alter table(:app_tokens) do
      # NULL identifies pre-snapshot credentials. They retain ordinary legacy
      # permissions, but can never acquire the native broker capability.
      add(:scopes, {:array, :string})
    end
  end
end
