defmodule LakehouseMatrix.Schema.RoomEvent do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "room_events" do
    field :event_id, :string
    field :type, :string
    field :content, :map, default: %{}
    field :sender, :string
    field :origin_server_ts, :integer
    field :state_key, :string

    belongs_to :room, LakehouseMatrix.Schema.Room
    belongs_to :principal, LakehouseIam.Schema.Principal

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(event, attrs) do
    event
    |> cast(attrs, [
      :room_id,
      :event_id,
      :type,
      :content,
      :sender,
      :principal_id,
      :origin_server_ts,
      :state_key
    ], empty_values: [])
    |> validate_required([:room_id, :event_id, :type, :content, :sender, :origin_server_ts])
    |> unique_constraint(:event_id)
  end
end
