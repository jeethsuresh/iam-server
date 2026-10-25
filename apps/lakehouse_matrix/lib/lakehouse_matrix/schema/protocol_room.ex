defmodule LakehouseMatrix.Schema.ProtocolRoom do
  use Ecto.Schema
  @primary_key {:local_room_id, :binary_id, autogenerate: false}
  schema "matrix_protocol_rooms" do
    field :room_id, :string
    field :version, :string
    field :create_id, :string
    field :current_state, :map, default: %{}
    field :extremities, {:array, :string}, default: []
  end
end
