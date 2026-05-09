defmodule LakehouseIam.Schema.Credential do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "credentials" do
    field :kind, Ecto.Enum, values: [:password, :api_key, :oauth, :mtls]
    field :secret_hash, :string
    field :meta, :map, default: %{}

    belongs_to :principal, LakehouseIam.Schema.Principal

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(c, attrs) do
    c
    |> cast(attrs, [:kind, :secret_hash, :meta, :principal_id])
    |> validate_required([:kind, :secret_hash, :principal_id])
  end
end
