defmodule LakehouseMatrix.Schema.Room do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "rooms" do
    field :alias, :string
    field :name, :string
    field :topic, :string
    field :avatar_url, :string

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(room, attrs) do
    room
    |> cast(attrs, [:alias, :name, :topic, :avatar_url])
    |> validate_required([:name])
    |> unique_constraint(:alias)
  end
end
