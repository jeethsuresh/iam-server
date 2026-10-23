defmodule LakehouseMatrix.Schema.RiverPublication do
  use Ecto.Schema
  @primary_key {:id, :string, autogenerate: false}
  schema "river_publications" do
    field :space_id, :binary_id
    field :author_id, :binary_id
    field :thread_id, :binary_id
    field :anchor_id, :string
    field :visibility, :string, default: "members"
    field :comments_policy, :string, default: "members"
  end
end
