defmodule LakehouseMatrix.Schema.RiverFile do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: false}
  schema "river_files" do
    field :room_id, :binary_id
    field :uploader_id, :binary_id
    field :event_id, :string
    field :manifest, :map
    timestamps(type: :utc_datetime_usec, updated_at: false)
  end
end
