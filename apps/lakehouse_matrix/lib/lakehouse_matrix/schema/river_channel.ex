defmodule LakehouseMatrix.Schema.RiverChannel do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id
  schema "river_channels" do
    field :space_id, :binary_id
    field :kind, :string
    timestamps(type: :utc_datetime_usec)
  end
end

defmodule LakehouseMatrix.Schema.RiverDirect do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: false}
  schema "river_directs" do
    field :low_id, :binary_id
    field :high_id, :binary_id
  end
end
