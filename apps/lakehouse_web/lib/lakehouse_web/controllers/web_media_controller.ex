defmodule LakehouseWeb.WebMediaController do
  use LakehouseWeb, :controller

  alias LakehouseMatrix.Media

  def show(conn, %{"serverName" => server, "mediaId" => media_id}) do
    case Media.download(conn.assigns.principal_id, server, media_id) do
      {:ok, %{body: body, content_type: type, filename: filename}} ->
        conn
        |> put_resp_content_type(type)
        |> put_resp_header("cache-control", "private, max-age=3600")
        |> maybe_disposition(filename)
        |> send_resp(200, body)

      {:error, :not_found} ->
        send_resp(conn, 404, "Not found")

      {:error, :forbidden} ->
        send_resp(conn, 403, "Forbidden")

      {:error, _} ->
        send_resp(conn, 400, "Bad request")
    end
  end

  defp maybe_disposition(conn, nil), do: conn

  defp maybe_disposition(conn, filename) do
    put_resp_header(conn, "content-disposition", ~s(inline; filename="#{filename}"))
  end
end
