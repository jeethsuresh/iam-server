defmodule LakehouseWeb.NativeBrokerController do
  use LakehouseWeb, :controller

  def authorize(conn, params) do
    raw =
      case get_req_header(conn, "authorization") do
        ["Bearer " <> raw] -> raw
        _ -> nil
      end

    conn = put_resp_header(conn, "cache-control", "no-store")

    case LakehouseIam.NativeBroker.authorize(raw, params) do
      {:ok, result} -> json(conn, result)
      {:error, :invalid_token} -> error(conn, 401, "invalid_token")
      {:error, :insufficient_scope} -> error(conn, 403, "insufficient_scope")
      {:error, :consent_required} -> error(conn, 403, "consent_required")
      {:error, :invalid_request} -> error(conn, 400, "invalid_request")
      {:error, _} -> error(conn, 503, "temporarily_unavailable")
    end
  rescue
    _error in [DBConnection.ConnectionError, Postgrex.Error] ->
      conn
      |> put_resp_header("cache-control", "no-store")
      |> error(503, "temporarily_unavailable")
  end

  defp error(conn, status, name), do: conn |> put_status(status) |> json(%{error: name})
end
