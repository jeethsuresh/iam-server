defmodule LakehouseIam.Schema.RolePermission do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "role_permissions" do
    belongs_to :role, LakehouseIam.Schema.Role
    belongs_to :permission, LakehouseIam.Schema.Permission

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(rp, attrs) do
    rp
    |> cast(attrs, [:role_id, :permission_id])
    |> validate_required([:role_id, :permission_id])
    |> unique_constraint([:role_id, :permission_id])
  end
end
