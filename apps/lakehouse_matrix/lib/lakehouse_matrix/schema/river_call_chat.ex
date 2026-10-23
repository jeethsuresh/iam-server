defmodule LakehouseMatrix.Schema.RiverCallChat do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: false}
  schema "river_call_chats" do
    field :parent_id, :binary_id
  end
end
