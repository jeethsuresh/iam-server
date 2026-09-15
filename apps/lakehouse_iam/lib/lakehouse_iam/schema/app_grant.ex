defmodule LakehouseIam.Schema.AppGrant do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "app_grants" do
    field :app_origin, :string
    field :scopes, {:array, :string}, default: []
    field :room_mode, Ecto.Enum, values: [:all, :selected], default: :selected
    field :room_ids, {:array, :binary_id}, default: []

    belongs_to :principal, LakehouseIam.Schema.Principal
    has_many :tokens, LakehouseIam.Schema.AppToken, foreign_key: :grant_id

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(grant, attrs) do
    grant
    |> cast(attrs, [:principal_id, :app_origin, :scopes, :room_mode, :room_ids])
    |> validate_required([:principal_id, :app_origin, :scopes, :room_mode])
    |> validate_inclusion(:room_mode, [:all, :selected])
    |> unique_constraint([:principal_id, :app_origin])
  end
end
