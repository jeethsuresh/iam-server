defmodule LakehouseIam.Schema.Principal do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "principals" do
    field :type, Ecto.Enum, values: [:user, :service, :bot, :agent]
    field :username, :string
    field :active, :boolean, default: false
    field :matrix_locked, :boolean, default: false
    field :matrix_suspended, :boolean, default: false
    field :matrix_deactivated, :boolean, default: false
    field :meta, :map, default: %{}

    has_many :credentials, LakehouseIam.Schema.Credential

    timestamps(type: :utc_datetime_usec)
  end

  def registration_changeset(principal, attrs) do
    principal
    |> cast(attrs, [:type, :username, :active, :meta])
    |> validate_required([:type])
    |> validate_username_if_user()
    |> unique_constraint(:username, name: :principals_username_index, message: "already taken")
  end

  defp validate_username_if_user(changeset) do
    case get_field(changeset, :type) do
      :user ->
        changeset
        |> validate_required([:username])
        |> validate_length(:username, max: 20)

      _ ->
        changeset
    end
  end
end
