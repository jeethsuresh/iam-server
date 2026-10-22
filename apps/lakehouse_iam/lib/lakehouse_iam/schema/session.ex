defmodule LakehouseIam.Schema.Session do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "iam_sessions" do
    belongs_to :principal, LakehouseIam.Schema.Principal
    field :kind, Ecto.Enum, values: [:browser, :api]
    field :expires_at, :utc_datetime_usec
    field :revoked_at, :utc_datetime_usec
    timestamps(type: :utc_datetime_usec)
  end
end
