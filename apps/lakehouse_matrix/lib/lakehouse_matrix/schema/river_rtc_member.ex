defmodule LakehouseMatrix.Schema.RiverRtcMember do
  use Ecto.Schema
  @primary_key {:id, :string, autogenerate: false}
  schema "river_rtc_members" do
    field :room_id, :binary_id
    field :principal_id, :binary_id
    field :app_origin, :string
    field :token_id, :binary_id
    field :expires_at, :utc_datetime_usec
  end
end
