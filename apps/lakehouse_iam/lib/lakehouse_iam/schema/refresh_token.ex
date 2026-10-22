defmodule LakehouseIam.Schema.RefreshToken do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "iam_refresh_tokens" do
    belongs_to :session, LakehouseIam.Schema.Session
    field :token_hash, :string
    field :used_at, :utc_datetime_usec
    field :replacement_hash, :string
    timestamps(type: :utc_datetime_usec, updated_at: false)
  end
end
