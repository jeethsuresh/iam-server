defmodule LakehouseIam.Schema.AppToken do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "app_tokens" do
    field :token_hash, :string
    field :kind, Ecto.Enum, values: [:access, :refresh]
    field :expires_at, :utc_datetime_usec
    field :revoked_at, :utc_datetime_usec

    belongs_to :grant, LakehouseIam.Schema.AppGrant

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(token, attrs) do
    token
    |> cast(attrs, [:grant_id, :token_hash, :kind, :expires_at, :revoked_at])
    |> validate_required([:grant_id, :token_hash, :kind, :expires_at])
    |> validate_inclusion(:kind, [:access, :refresh])
    |> unique_constraint(:token_hash)
  end
end
