defmodule LakehouseWeb.Matrix.AdminController do
  use LakehouseWeb, :controller
  alias LakehouseMatrix.AccountModeration
  alias LakehouseWeb.Matrix.ProtocolController

  def whois(conn, %{"userId" => user}),
    do: ProtocolController.respond(conn, AccountModeration.whois(conn.assigns.principal_id, user))

  def locked(conn, params), do: status(conn, params, :matrix_locked, "locked")
  def suspended(conn, params), do: status(conn, params, :matrix_suspended, "suspended")

  defp status(conn, %{"userId" => user} = params, field, key) do
    value = if conn.method == "GET", do: :get, else: Map.get(params, key)

    ProtocolController.respond(
      conn,
      AccountModeration.admin(conn.assigns.principal_id, user, field, value)
    )
  end
end
