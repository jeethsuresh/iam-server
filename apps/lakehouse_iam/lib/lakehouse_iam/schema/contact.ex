# Keep the original table names for lossless, rolling-compatible adoption of
# existing River relationships. Gravitas owns this shared graph, not an app.
defmodule LakehouseIam.Schema.Contact do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "river_friendships" do
    field :low_id, :binary_id
    field :high_id, :binary_id
    field :requested_by, :binary_id
    field :status, :string
    timestamps(type: :utc_datetime_usec)
  end
end

defmodule LakehouseIam.Schema.ContactBlock do
  use Ecto.Schema
  @primary_key false
  schema "river_friend_blocks" do
    field :owner_id, :binary_id, primary_key: true
    field :target_id, :binary_id, primary_key: true
  end
end

defmodule LakehouseIam.Schema.ContactEvent do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "river_social_events" do
    field :actor_id, :binary_id
    field :target_id, :binary_id
    field :app_origin, :string
    field :txn_id, :string
    field :action, :string
    field :type, :string
    timestamps(type: :utc_datetime_usec, updated_at: false)
  end
end
