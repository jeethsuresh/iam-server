defmodule LakehouseMatrix.Media.Store.Local do
  @moduledoc """
  Filesystem media store under `Application.get_env(:lakehouse_matrix, :media_root)`.
  """
  @behaviour LakehouseMatrix.Media.Store

  @impl true
  def put(media_id, body, _opts \\ []) when is_binary(media_id) and is_binary(body) do
    path = path_for(media_id)

    with :ok <- File.mkdir_p(Path.dirname(path)),
         :ok <- File.write(path, body) do
      :ok
    end
  end

  @impl true
  def get(media_id, _opts \\ []) when is_binary(media_id) do
    path = path_for(media_id)

    case File.read(path) do
      {:ok, body} -> {:ok, body}
      {:error, :enoent} -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def delete(media_id, _opts \\ []) when is_binary(media_id) do
    path = path_for(media_id)

    case File.rm(path) do
      :ok -> :ok
      {:error, :enoent} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp path_for(media_id) do
    root = Application.get_env(:lakehouse_matrix, :media_root) || default_root()
    # Shard by first two chars of id for shallow directory fan-out.
    shard =
      media_id
      |> String.replace("-", "")
      |> String.slice(0, 2)
      |> case do
        <<a, b>> -> <<a, b>>
        other -> other || "00"
      end

    Path.join([root, shard, media_id])
  end

  defp default_root do
    Path.join([:code.priv_dir(:lakehouse_matrix), "media"])
  end
end
