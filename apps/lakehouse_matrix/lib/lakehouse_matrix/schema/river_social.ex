defmodule LakehouseMatrix.Schema.RiverFriendship do
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

defmodule LakehouseMatrix.Schema.RiverFriendBlock do
  use Ecto.Schema
  @primary_key false
  schema "river_friend_blocks" do
    field :owner_id, :binary_id, primary_key: true
    field :target_id, :binary_id, primary_key: true
  end
end

defmodule LakehouseMatrix.Schema.RiverSocialEvent do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "river_social_events" do
    field :actor_id, :binary_id
    field :target_id, :binary_id
    field :app_origin, :string
    field :txn_id, :string
    field :action, :string
    timestamps(type: :utc_datetime_usec, updated_at: false)
  end
end

defmodule LakehouseMatrix.Schema.RiverRoomRead do
  use Ecto.Schema
  @primary_key false
  schema "river_room_reads" do
    field :principal_id, :binary_id, primary_key: true
    field :room_id, :binary_id, primary_key: true
    field :event_id, :binary_id
    timestamps(type: :utc_datetime_usec)
  end
end
