defmodule LakehouseWeb.DiscoveryController do
  use LakehouseWeb, :controller
  alias LakehouseIam.Discovery

  def configuration(conn, _params), do: public(conn) |> json(Discovery.configuration())

  def webfinger(conn, %{"resource" => resource}) do
    rels =
      URI.query_decoder(conn.query_string)
      |> Enum.filter(fn {key, _} -> key == "rel" end)
      |> Enum.map(&elem(&1, 1))

    case Discovery.webfinger(resource, rels) do
      {:ok, body} ->
        public(conn)
        |> put_resp_content_type("application/jrd+json")
        |> send_resp(200, Jason.encode!(body))

      {:error, _} ->
        conn |> put_status(404) |> json(%{error: "not_found"})
    end
  end

  def webfinger(conn, _), do: conn |> put_status(400) |> json(%{error: "resource required"})

  def matrix_client(conn, _),
    do: public(conn) |> json(%{"m.homeserver" => %{"base_url" => Discovery.public_url()}})

  def health(conn, _), do: json(conn, %{status: "ok"})

  def ready(conn, _) do
    case Ecto.Adapters.SQL.query(LakehouseIam.Repo, "SELECT 1", [], timeout: 3_000) do
      {:ok, _} -> json(conn, %{status: "ok"})
      _ -> conn |> put_status(503) |> json(%{status: "unavailable"})
    end
  end

  defp public(conn),
    do:
      conn
      |> put_resp_header("access-control-allow-origin", "*")
      |> put_resp_header("cache-control", "public, max-age=300")
end
