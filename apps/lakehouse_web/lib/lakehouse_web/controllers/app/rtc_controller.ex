defmodule LakehouseWeb.App.RtcController do
  use LakehouseWeb, :controller
  alias LakehouseMatrix.RiverRtc
  def index(conn, _), do: respond(conn, RiverRtc.list(conn.assigns.app_grant))
  def update(conn, %{"id" => id} = p), do: respond(conn, RiverRtc.update(conn.assigns.app_grant, conn.assigns.app_token, id, p))
  def lease(conn, %{"id" => id}), do: conn |> put_resp_header("cache-control", "no-store") |> json(%{active: RiverRtc.lease_active?(id)})
  defp respond(conn, {:ok, body}), do: json(conn, body)
  defp respond(conn, {:error, reason}) do
    status = cond do
      reason in [:forbidden, :insufficient_scope] -> 403
      reason == :rtc_unavailable -> 503
      reason in [:membership_expired, :too_many_connections] -> 409
      true -> 400
    end
    conn |> put_status(status) |> json(%{error: to_string(reason)})
  end
end
