defmodule LakehouseMatrix.Schema.RoomMembership do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "room_memberships" do
    field :membership_state, :map, default: %{}

    belongs_to :room, LakehouseMatrix.Schema.Room
    belongs_to :principal, LakehouseIam.Schema.Principal

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(membership, attrs) do
    membership
    |> cast(attrs, [:room_id, :principal_id, :membership_state])
    |> validate_required([:room_id, :principal_id, :membership_state])
    |> unique_constraint([:room_id, :principal_id])
  end
end
