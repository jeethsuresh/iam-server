defmodule LakehouseMatrix.Schema.RiverEntryRead do
  use Ecto.Schema
  @primary_key false
  schema "river_entry_reads" do
    field :principal_id, Ecto.UUID, primary_key: true
    field :event_id, :string, primary_key: true
  end
end
