defmodule LakehouseIam.Repo.Migrations.GravitasContacts do
  use Ecto.Migration
  def change do
    # Preserve historical event identities/types and compatibility with older
    # writers. New contact actions explicitly use cool.gravitas.contact.v1.
    alter table(:river_social_events) do
      add :type, :string, null: false, default: "cool.gravitas.river.friend.v1"
    end
  end
end
