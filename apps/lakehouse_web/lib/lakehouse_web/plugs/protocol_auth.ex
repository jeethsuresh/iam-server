defmodule LakehouseWeb.Plugs.ProtocolAuth do
  import Plug.Conn
  alias LakehouseIam.Protocols
  def init(opts), do: opts

  def call(conn, _) do
    conn = put_resp_header(conn, "cache-control", "no-store")

    sender =
      case get_req_header(conn, "authorization") do
        ["Bearer " <> raw] -> Protocols.authenticate(raw)
        _ -> nil
      end

    if sender do
      assign(conn, :protocol_sender, Map.put(sender, :service, true))
    else
      conn = LakehouseWeb.Plugs.AppTokenAuth.call(conn, [])

      if conn.halted do
        conn
      else
        assign(conn, :protocol_sender, %{
          origin: conn.assigns.app_origin,
          permissions: conn.assigns.app_grant.scopes,
          service: false
        })
      end
    end
  end
end
