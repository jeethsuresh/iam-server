defmodule LakehouseWeb.Matrix.MediaController do
  use LakehouseWeb, :controller

  alias LakehouseMatrix.Media

  def create(conn, _),
    do:
      LakehouseWeb.Matrix.ProtocolController.respond(
        conn,
        LakehouseMatrix.AsyncMedia.create(conn.assigns.principal_id)
      )

  def upload_reserved(conn, %{"serverName" => server, "mediaId" => id} = params) do
    filename = params["filename"] || "upload.bin"
    {body, type} = extract_upload(conn, params, filename)

    if body == :too_large do
      matrix_error(conn, 413, "M_TOO_LARGE", "File exceeds 10MB limit")
    else
      result =
        LakehouseMatrix.AsyncMedia.put(conn.assigns.principal_id, server, id, body,
          filename: filename,
          content_type: type
        )

      case result do
        {:error, :too_large} ->
          matrix_error(conn, 413, "M_TOO_LARGE", "File exceeds 10MB limit")

        {:error, :invalid_upload} ->
          matrix_error(conn, 400, "M_BAD_JSON", "Invalid upload")

        {:error, :cannot_overwrite_media} ->
          matrix_error(conn, 409, "M_CANNOT_OVERWRITE_MEDIA", "Media already uploaded")

        other ->
          LakehouseWeb.Matrix.ProtocolController.respond(conn, other)
      end
    end
  end

  def upload(conn, params) do
    filename = Map.get(params, "filename") || conn.query_params["filename"] || "upload.bin"

    {body, content_type} = extract_upload(conn, params, filename)

    opts =
      [filename: filename, matrix_public: conn.assigns.matrix_device_id != "legacy"]
      |> then(fn o ->
        if content_type, do: Keyword.put(o, :content_type, content_type), else: o
      end)

    case body do
      :too_large ->
        matrix_error(conn, 413, "M_TOO_LARGE", "File exceeds 10MB limit")

      body when is_binary(body) ->
        case Media.upload(conn.assigns.principal_id, body, opts) do
          {:ok, result} ->
            json(conn, %{
              "content_uri" => result.content_uri,
              "info" => result.info
            })

          {:error, :too_large} ->
            matrix_error(conn, 413, "M_TOO_LARGE", "File exceeds 10MB limit")

          {:error, :invalid_upload} ->
            matrix_error(conn, 400, "M_BAD_JSON", "Empty upload")

          {:error, _} ->
            matrix_error(conn, 500, "M_UNKNOWN", "Upload failed")
        end
    end
  end

  defp extract_upload(conn, params, filename) do
    cond do
      match?(%Plug.Upload{}, params["file"]) ->
        upload = params["file"]
        {File.read!(upload.path), upload.content_type || guess_from_name(filename)}

      is_binary(params["base64"]) ->
        case Base.decode64(params["base64"]) do
          {:ok, bin} -> {bin, params["content_type"] || guess_from_name(filename)}
          :error -> {"", nil}
        end

      true ->
        header_type =
          get_req_header(conn, "content-type")
          |> List.first()
          |> case do
            nil -> nil
            type -> type |> String.split(";", parts: 2) |> hd() |> String.trim()
          end

        body =
          case conn.assigns[:raw_body] do
            bin when is_binary(bin) -> bin
            _ -> read_body_bytes(conn)
          end

        type =
          if is_nil(header_type) or
               (conn.assigns.matrix_device_id == "legacy" and
                  header_type in ["application/json", "application/x-www-form-urlencoded"]),
             do: guess_from_name(filename),
             else: header_type

        {body, type}
    end
  end

  defp guess_from_name(filename) do
    case Path.extname(filename) |> String.downcase() do
      ".png" -> "image/png"
      ".jpg" -> "image/jpeg"
      ".jpeg" -> "image/jpeg"
      ".gif" -> "image/gif"
      ".txt" -> "text/plain"
      _ -> "application/octet-stream"
    end
  end

  def download(conn, %{"serverName" => server, "mediaId" => id} = params) do
    result =
      LakehouseMatrix.AsyncMedia.fetch(server, id, params, fn ->
        Media.download(conn.assigns.principal_id, server, id)
      end)

    result =
      case result do
        {:ok, media} ->
          {:ok, if(params["fileName"], do: %{media | filename: params["fileName"]}, else: media)}

        error ->
          error
      end

    serve(conn, result)
  end

  def thumbnail(conn, %{"serverName" => server, "mediaId" => id} = params),
    do:
      serve(
        conn,
        LakehouseMatrix.AsyncMedia.fetch(server, id, params, fn ->
          Media.thumbnail(conn.assigns.principal_id, server, id, params)
        end)
      )

  def federation(conn, %{"mediaId" => id} = params) do
    result =
      LakehouseMatrix.AsyncMedia.fetch(
        LakehouseMatrix.Identity.homeserver_domain(),
        id,
        params,
        fn ->
          if String.contains?(conn.request_path, "/thumbnail/"),
            do: Media.federation_thumbnail(id, params),
            else: Media.federation_download(id)
        end
      )

    case result do
      {:ok, media} ->
        {type, body} = LakehouseMatrix.Federation.Media.encode(media)
        conn |> put_resp_header("content-type", type) |> send_resp(200, body)

      error ->
        serve(conn, error)
    end
  end

  defp serve(conn, {:ok, media}) do
    type = LakehouseMatrix.Federation.Media.safe_type(media.content_type)

    conn
    |> put_resp_header("content-type", type)
    |> put_resp_header(
      "content-disposition",
      LakehouseMatrix.Federation.Media.disposition(type, media.filename)
    )
    |> put_resp_header(
      "content-security-policy",
      "sandbox; default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; object-src 'self'"
    )
    |> put_resp_header("x-content-type-options", "nosniff")
    |> put_resp_header("cross-origin-resource-policy", "cross-origin")
    |> send_resp(200, media.body)
  end

  defp serve(conn, {:error, :not_found}),
    do: matrix_error(conn, 404, "M_NOT_FOUND", "Media not found")

  defp serve(conn, {:error, :not_yet_uploaded}),
    do: matrix_error(conn, 504, "M_NOT_YET_UPLOADED", "Content has not yet been uploaded")

  defp serve(conn, {:error, :invalid_param}),
    do: matrix_error(conn, 400, "M_INVALID_PARAM", "Invalid media parameter")

  defp serve(conn, {:error, :forbidden}),
    do: matrix_error(conn, 403, "M_FORBIDDEN", "You cannot access this media")

  defp serve(conn, {:error, :too_large}),
    do: matrix_error(conn, 502, "M_TOO_LARGE", "Remote media exceeds the server limit")

  defp serve(conn, {:error, _}),
    do: matrix_error(conn, 400, "M_UNKNOWN", "Cannot retrieve this media")

  defp read_body_bytes(conn) do
    case Plug.Conn.read_body(conn, length: 11 * 1024 * 1024) do
      {:ok, body, _conn} -> body
      {:more, _, _} -> :too_large
      {:error, _} -> ""
    end
  end

  defp matrix_error(conn, status, errcode, error) do
    conn
    |> put_status(status)
    |> json(%{"errcode" => errcode, "error" => error})
  end
end
