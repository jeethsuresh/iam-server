defmodule LakehouseWeb.Plugs.RenewBrowserSession do
  def init(opts), do: opts

  def call(conn, _opts) do
    if conn.request_path in ["/logout", "/web/logout"] or
         Plug.Conn.get_req_header(conn, "authorization") != [],
       do: conn,
       else: LakehouseWeb.BrowserSession.renew(conn)
  end
end
