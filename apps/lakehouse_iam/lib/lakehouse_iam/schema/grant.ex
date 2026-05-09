defmodule LakehouseIam.Schema.Grant do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "grants" do
    belongs_to :principal, LakehouseIam.Schema.Principal
    belongs_to :role, LakehouseIam.Schema.Role
    belongs_to :resource, LakehouseIam.Schema.Resource

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(g, attrs) do
    g
    |> cast(attrs, [:principal_id, :role_id, :resource_id])
    |> validate_required([:principal_id, :role_id])
    |> foreign_key_constraint(:principal_id)
    |> foreign_key_constraint(:role_id)
    |> foreign_key_constraint(:resource_id)
  end
end
