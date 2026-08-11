defmodule LakehouseWeb.Matrix.MediaController do
  use LakehouseWeb, :controller

  alias LakehouseMatrix.Media

  def upload(conn, params) do
    filename = Map.get(params, "filename") || conn.query_params["filename"] || "upload.bin"

    {body, content_type} = extract_upload(conn, params, filename)

    opts =
      [filename: filename]
      |> then(fn o -> if content_type, do: Keyword.put(o, :content_type, content_type), else: o end)

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
          if header_type in [nil, "application/json", "application/x-www-form-urlencoded"],
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

  def download(conn, %{"serverName" => server, "mediaId" => media_id}) do
    case Media.download(conn.assigns.principal_id, server, media_id) do
      {:ok, %{body: body, content_type: type, filename: filename}} ->
        conn
        |> put_resp_content_type(type)
        |> maybe_disposition(filename)
        |> send_resp(200, body)

      {:error, :not_found} ->
        matrix_error(conn, 404, "M_NOT_FOUND", "Media not found")

      {:error, :forbidden} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "You cannot access this media")

      {:error, _} ->
        matrix_error(conn, 400, "M_UNKNOWN", "Download failed")
    end
  end

  defp read_body_bytes(conn) do
    case Plug.Conn.read_body(conn, length: 11 * 1024 * 1024) do
      {:ok, body, _conn} -> body
      {:more, _, _} -> :too_large
      {:error, _} -> ""
    end
  end

  defp maybe_disposition(conn, nil), do: conn

  defp maybe_disposition(conn, filename) do
    put_resp_header(conn, "content-disposition", ~s(inline; filename="#{filename}"))
  end

  defp matrix_error(conn, status, errcode, error) do
    conn
    |> put_status(status)
    |> json(%{"errcode" => errcode, "error" => error})
  end
end
