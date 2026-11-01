defmodule LakehouseIam.Schema.ProfilePicture do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "profile_pictures" do
    belongs_to :principal, LakehouseIam.Schema.Principal
    field :content_type, :string
    field :data, :binary
  end
end
