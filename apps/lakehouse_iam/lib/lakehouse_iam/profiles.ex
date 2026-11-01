defmodule LakehouseIam.Profiles do
  @moduledoc "Account profile details. Picture bytes are stored separately from frequently read account records."
  import Ecto.Changeset
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseIam.Schema.{Principal, ProfilePicture}

  @max_picture_bytes 256 * 1024

  # Replacing or removing a picture invalidates its unguessable link.
  def picture_url(%Principal{picture_key: nil}), do: nil

  def picture_url(%Principal{picture_key: key}),
    do: LakehouseIam.Discovery.public_url() <> "/profile/pictures/" <> key

  def update(principal_id, params) do
    with {:ok, picture} <- picture_change(params) do
      Repo.transaction(fn ->
        principal =
          Repo.one(
            from p in Principal,
              where: p.id == ^principal_id and p.type == :user,
              lock: "FOR UPDATE"
          ) ||
            Repo.rollback(:not_found)

        changeset =
          principal
          |> cast(Map.take(params, ["full_name"]), [:full_name])
          |> update_change(:full_name, fn value ->
            if is_binary(value), do: String.trim(value), else: value
          end)
          |> validate_length(:full_name, max: 120)
          |> validate_change(:full_name, fn :full_name, value ->
            if is_binary(value) and byte_size(value) > 1024,
              do: [full_name: "is too long"],
              else: []
          end)

        unless changeset.valid?, do: Repo.rollback(changeset)

        changeset =
          case picture do
            :keep ->
              changeset

            change ->
              Repo.delete_all(from p in ProfilePicture, where: p.principal_id == ^principal.id)

              key =
                case change do
                  :remove ->
                    nil

                  {bytes, type} ->
                    Repo.insert!(%ProfilePicture{
                      principal_id: principal.id,
                      data: bytes,
                      content_type: type
                    }).id
                end

              put_change(changeset, :picture_key, key)
          end

        case Repo.update(changeset) do
          {:ok, updated} -> updated
          {:error, error} -> Repo.rollback(error)
        end
      end)
    end
  end

  defp picture_change(%{"remove_picture" => value}) when value in ["true", "on", "1"],
    do: {:ok, :remove}

  defp picture_change(%{"picture" => %{__struct__: Plug.Upload, path: path}}) do
    with {:ok, file} <- File.open(path, [:read, :binary]) do
      data = IO.binread(file, @max_picture_bytes + 1)
      File.close(file)

      case data do
        bytes when is_binary(bytes) and byte_size(bytes) <= @max_picture_bytes ->
          case mime(bytes) do
            nil -> {:error, :invalid_picture}
            type -> {:ok, {bytes, type}}
          end

        _ ->
          {:error, :invalid_picture}
      end
    end
  end

  defp picture_change(%{"picture" => value}) when value not in [nil, ""],
    do: {:error, :invalid_picture}

  defp picture_change(_), do: {:ok, :keep}

  defp mime(<<137, 80, 78, 71, 13, 10, 26, 10, _::binary>>), do: "image/png"
  defp mime(<<255, 216, 255, _::binary>>), do: "image/jpeg"
  defp mime(<<"RIFF", _::binary-size(4), "WEBP", _::binary>>), do: "image/webp"
  defp mime(_), do: nil
end
