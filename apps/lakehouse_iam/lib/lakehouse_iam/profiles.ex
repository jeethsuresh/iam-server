defmodule LakehouseIam.Profiles do
  @moduledoc "Account profile details. Pictures use opaque links shared with apps only by consent."
  import Ecto.Changeset
  alias LakehouseIam.{Repo, Schema.Principal}

  @max_picture_bytes 256 * 1024

  # The unguessable link can be copied like the picture itself. Replacing or
  # removing the picture invalidates the old link, without exposing an account ID.
  def picture_url(%Principal{picture_key: nil}), do: nil

  def picture_url(%Principal{picture_key: key}),
    do: LakehouseIam.Discovery.public_url() <> "/profile/pictures/" <> key

  def update(principal_id, params) do
    with %Principal{type: :user} = principal <- Repo.get(Principal, principal_id),
         {:ok, picture} <- picture_change(params) do
      attrs = Map.take(params, ["full_name"]) |> Map.merge(picture)

      principal
      |> cast(attrs, [:full_name, :picture, :picture_key])
      |> update_change(:full_name, fn value ->
        if is_binary(value), do: String.trim(value), else: value
      end)
      |> validate_length(:full_name, max: 120)
      |> Repo.update()
    else
      nil -> {:error, :not_found}
      error -> error
    end
  end

  defp picture_change(%{"remove_picture" => value}) when value in ["true", "on", "1"],
    do: {:ok, %{"picture" => nil, "picture_key" => nil}}

  defp picture_change(%{"picture" => %{__struct__: Plug.Upload, path: path}}) do
    # Bound the read independently of multipart request limits and ignore the supplied MIME type.
    with {:ok, file} <- File.open(path, [:read, :binary]) do
      data = IO.binread(file, @max_picture_bytes + 1)
      File.close(file)

      case data do
        bytes when is_binary(bytes) and byte_size(bytes) <= @max_picture_bytes ->
          case mime(bytes) do
            nil ->
              {:error, :invalid_picture}

            type ->
              {:ok,
               %{
                 "picture" => "data:#{type};base64," <> Base.encode64(bytes),
                 "picture_key" => Ecto.UUID.generate()
               }}
          end

        _ ->
          {:error, :invalid_picture}
      end
    end
  end

  defp picture_change(%{"picture" => value}) when value not in [nil, ""],
    do: {:error, :invalid_picture}

  defp picture_change(_), do: {:ok, %{}}

  defp mime(<<137, 80, 78, 71, 13, 10, 26, 10, _::binary>>), do: "image/png"
  defp mime(<<255, 216, 255, _::binary>>), do: "image/jpeg"
  defp mime(<<"RIFF", _::binary-size(4), "WEBP", _::binary>>), do: "image/webp"
  defp mime(_), do: nil
end
