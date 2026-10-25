defmodule LakehouseMatrix.Schema.MediaObject do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "media_objects" do
    field :filename, :string
    field :content_type, :string
    field :byte_size, :integer
    field :thumbnail_id, :binary_id
    field :kind, :string, default: "file"
    field :uploader_id, :binary_id
    field :matrix_public, :boolean, default: false

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(media, attrs) do
    media
    |> cast(attrs, [
      :filename,
      :content_type,
      :byte_size,
      :thumbnail_id,
      :kind,
      :uploader_id,
      :matrix_public
    ])
    |> validate_required([:content_type, :byte_size, :kind])
  end
end
