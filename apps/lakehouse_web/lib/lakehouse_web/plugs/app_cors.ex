defmodule LakehouseWeb.Plugs.AppCors do
  @moduledoc "CORS for public discovery and bearer/PKCE app APIs; never enables cookie credentials."
  import Plug.Conn
  def init(opts), do: opts

  def call(conn, _opts) do
    if public_api?(conn.request_path) do
      conn =
        conn
        |> put_resp_header("access-control-allow-origin", "*")
        |> put_resp_header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS")
        |> put_resp_header("access-control-allow-headers", "authorization, content-type")
        |> put_resp_header("access-control-max-age", "600")

      if conn.method == "OPTIONS", do: conn |> send_resp(204, "") |> halt(), else: conn
    else
      conn
    end
  end

  defp public_api?("/_matrix/" <> _), do: true
  defp public_api?("/.well-known/" <> _), do: true
  defp public_api?("/app/v1/" <> _), do: true
  defp public_api?(path), do: path in ["/backend/register", "/oauth/token"]
end
