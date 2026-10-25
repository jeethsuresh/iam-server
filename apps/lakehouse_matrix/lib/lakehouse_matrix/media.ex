defmodule LakehouseMatrix.Media do
  @moduledoc """
  Media upload/download. Blobs live in `Media.Store`; metadata in `media_objects`.
  """
  import Ecto.Query

  alias LakehouseIam.Repo
  alias LakehouseMatrix.Identity
  alias LakehouseMatrix.Media.Image
  alias LakehouseMatrix.Schema.{MediaObject, RoomEvent, RoomMembership}

  @max_bytes 10 * 1024 * 1024

  @type upload_result :: %{
          media_id: String.t(),
          content_uri: String.t(),
          info: map()
        }

  @spec upload(Ecto.UUID.t(), binary(), keyword()) ::
          {:ok, upload_result()} | {:error, term()}
  def upload(uploader_id, body, opts \\ []) when is_binary(body) do
    filename = Keyword.get(opts, :filename) || "upload.bin"

    content_type =
      LakehouseMatrix.Federation.Media.safe_type(
        Keyword.get(opts, :content_type) || guess_content_type(body, filename)
      )

    cond do
      not is_binary(filename) or not String.valid?(filename) or byte_size(filename) > 1024 ->
        {:error, :invalid_upload}

      body == "" ->
        {:error, :invalid_upload}

      byte_size(body) > @max_bytes ->
        {:error, :too_large}

      true ->
        do_upload(
          uploader_id,
          body,
          filename,
          content_type,
          Keyword.get(opts, :matrix_public, false) == true
        )
    end
  end

  @spec download(Ecto.UUID.t(), String.t(), String.t()) ::
          {:ok, %{body: binary(), content_type: String.t(), filename: String.t() | nil}}
          | {:error, term()}
  def download(principal_id, server, media_id) do
    cond do
      not LakehouseMatrix.Federation.Media.valid_id?(media_id) ->
        {:error, :not_found}

      server != Identity.homeserver_domain() ->
        LakehouseMatrix.Federation.Media.download(server, media_id)

      true ->
        local_download(principal_id, media_id)
    end
  end

  def federation_download(media_id) do
    with true <- LakehouseMatrix.Federation.Media.valid_id?(media_id),
         {:ok, record} <- fetch_record(media_id),
         true <- record.matrix_public do
      local_download(record.uploader_id, media_id)
    else
      _ -> {:error, :not_found}
    end
  end

  def thumbnail(principal, server, id, params) do
    with {:ok, dimensions} <- thumbnail_params(params) do
      if server != Identity.homeserver_domain() do
        LakehouseMatrix.Federation.Media.download(server, id, dimensions)
      else
        with {:ok, original} <- local_download(principal, id),
             {:ok, body} <-
               Image.thumbnail(
                 original.body,
                 dimensions["width"],
                 dimensions["height"],
                 dimensions["method"]
               ) do
          {:ok, %{body: body, content_type: "image/jpeg", filename: "thumbnail.jpg"}}
        end
      end
    end
  end

  def federation_thumbnail(id, params) do
    with {:ok, original} <- federation_download(id),
         {:ok, dimensions} <- thumbnail_params(params),
         {:ok, body} <-
           Image.thumbnail(
             original.body,
             dimensions["width"],
             dimensions["height"],
             dimensions["method"]
           ) do
      {:ok, %{body: body, content_type: "image/jpeg", filename: "thumbnail.jpg"}}
    end
  end

  defp thumbnail_params(params) do
    with {:ok, width} <- LakehouseMatrix.ClientSync.integer(params["width"], nil, 1, 4096),
         {:ok, height} <- LakehouseMatrix.ClientSync.integer(params["height"], nil, 1, 4096),
         true <-
           is_integer(width) and is_integer(height) and
             (params["method"] || "scale") in ~w(scale crop) do
      {:ok, %{"width" => width, "height" => height, "method" => params["method"] || "scale"}}
    else
      _ -> {:error, :invalid_param}
    end
  end

  defp local_download(principal_id, media_id) do
    with {:ok, record} <- fetch_record(media_id),
         :ok <- authorize_download(principal_id, record),
         {:ok, body} <- store().get(media_id, []) do
      {:ok, %{body: body, content_type: record.content_type, filename: record.filename}}
    end
  end

  @spec content_uri(String.t()) :: String.t()
  def content_uri(media_id) when is_binary(media_id) do
    "mxc://#{Identity.homeserver_domain()}/#{media_id}"
  end

  @spec media_id_from_uri(String.t()) :: String.t() | nil
  def media_id_from_uri("mxc://" <> rest) do
    case String.split(rest, "/", parts: 2) do
      [_server, id] when id != "" -> id
      _ -> nil
    end
  end

  def media_id_from_uri(_), do: nil

  @spec get_record(String.t()) :: MediaObject.t() | nil
  def get_record(media_id), do: Repo.get(MediaObject, media_id)

  defp do_upload(uploader_id, body, filename, content_type, matrix_public) do
    media_id = Ecto.UUID.generate()
    image? = String.starts_with?(content_type, "image/")

    with :ok <- store().put(media_id, body, []),
         {:ok, thumb} <- maybe_thumbnail(image?, body, uploader_id, matrix_public),
         {:ok, record} <-
           insert_record(%{
             id: media_id,
             uploader_id: uploader_id,
             matrix_public: matrix_public,
             filename: filename,
             content_type: content_type,
             byte_size: byte_size(body),
             thumbnail_id: thumb && thumb.id,
             kind: if(image?, do: "image", else: "file")
           }) do
      info = %{
        "mimetype" => content_type,
        "size" => record.byte_size
      }

      info =
        if thumb do
          info
          |> Map.put("thumbnail_url", content_uri(thumb.id))
          |> Map.put("thumbnail_info", %{
            "mimetype" => thumb.content_type,
            "size" => thumb.byte_size
          })
        else
          info
        end

      {:ok,
       %{
         media_id: media_id,
         content_uri: content_uri(media_id),
         info: info
       }}
    end
  end

  defp maybe_thumbnail(false, _body, _uploader_id, _public), do: {:ok, nil}

  defp maybe_thumbnail(true, body, uploader_id, matrix_public) do
    case Image.compress(body) do
      {:ok, jpeg} ->
        thumb_id = Ecto.UUID.generate()

        with :ok <- store().put(thumb_id, jpeg, []),
             {:ok, record} <-
               insert_record(%{
                 id: thumb_id,
                 uploader_id: uploader_id,
                 matrix_public: matrix_public,
                 filename: "thumb.jpg",
                 content_type: "image/jpeg",
                 byte_size: byte_size(jpeg),
                 thumbnail_id: nil,
                 kind: "thumbnail"
               }) do
          {:ok, record}
        end

      {:error, _reason} ->
        # Spec: if decode/compress fails, continue without thumbnail.
        {:ok, nil}
    end
  end

  defp insert_record(attrs) do
    id = Map.fetch!(attrs, :id)

    %MediaObject{id: id}
    |> MediaObject.changeset(Map.delete(attrs, :id))
    |> Repo.insert()
  end

  defp fetch_record(media_id) do
    record =
      case Ecto.UUID.cast(media_id) do
        {:ok, id} -> Repo.get(MediaObject, id)
        _ -> nil
      end

    case record do
      nil -> {:error, :not_found}
      record -> {:ok, record}
    end
  end

  defp authorize_download(principal_id, %MediaObject{} = record) do
    cond do
      record.matrix_public ->
        :ok

      record.uploader_id == principal_id ->
        :ok

      referenced_in_joined_room?(principal_id, record.id) ->
        :ok

      true ->
        {:error, :forbidden}
    end
  end

  defp referenced_in_joined_room?(principal_id, media_id) do
    needle = "%#{media_id}%"

    room_ids =
      from(m in RoomMembership,
        where:
          m.principal_id == ^principal_id and
            fragment("?->>'membership' = 'join'", m.membership_state),
        select: m.room_id
      )
      |> Repo.all()

    if room_ids == [] do
      false
    else
      from(e in RoomEvent,
        where: e.room_id in ^room_ids,
        where: fragment("(?)::text LIKE ?", e.content, ^needle),
        select: e.id,
        limit: 1
      )
      |> Repo.one()
      |> is_binary()
    end
  end

  defp store do
    Application.get_env(:lakehouse_matrix, :media_store, LakehouseMatrix.Media.Store.Local)
  end

  defp guess_content_type(<<0x89, "PNG", 0x0D, 0x0A, 0x1A, 0x0A, _::binary>>, _), do: "image/png"
  defp guess_content_type(<<0xFF, 0xD8, 0xFF, _::binary>>, _), do: "image/jpeg"
  defp guess_content_type(<<"GIF8", _::binary>>, _), do: "image/gif"
  defp guess_content_type(<<"RIFF", _::binary-size(4), "WEBP", _::binary>>, _), do: "image/webp"

  defp guess_content_type(_body, filename) do
    case Path.extname(filename) |> String.downcase() do
      ".png" -> "image/png"
      ".jpg" -> "image/jpeg"
      ".jpeg" -> "image/jpeg"
      ".gif" -> "image/gif"
      ".webp" -> "image/webp"
      ".pdf" -> "application/pdf"
      ".txt" -> "text/plain"
      _ -> "application/octet-stream"
    end
  end
end
