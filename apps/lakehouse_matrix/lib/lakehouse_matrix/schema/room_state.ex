defmodule LakehouseMatrix.Schema.RoomState do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "room_state" do
    field :state_key, :string
    field :type, :string
    field :content, :map, default: %{}

    belongs_to :room, LakehouseMatrix.Schema.Room

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(state, attrs) do
    state
    |> cast(attrs, [:room_id, :state_key, :type, :content])
    |> validate_required([:room_id, :type, :content])
    |> put_default_state_key()
    |> unique_constraint([:room_id, :state_key, :type])
  end

  defp put_default_state_key(changeset) do
    case get_field(changeset, :state_key) do
      nil -> put_change(changeset, :state_key, "")
      _ -> changeset
    end
  end
end
