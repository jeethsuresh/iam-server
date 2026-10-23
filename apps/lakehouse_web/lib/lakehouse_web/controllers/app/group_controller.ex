defmodule LakehouseWeb.App.GroupController do
  use LakehouseWeb, :controller
  alias LakehouseMatrix.DelegatedGroups, as: Groups

  def index(conn, _) do
    if "chats.list" in conn.assigns.app_grant.scopes,
      do: json(conn, %{groups: Groups.list(conn.assigns.app_grant)}),
      else: respond(conn, {:error, :insufficient_scope})
  end
  def create(conn, p), do: respond(conn, Groups.create(conn.assigns.app_grant, p))
  def update(conn, %{"id" => id} = p), do: respond(conn, Groups.update(conn.assigns.app_grant, id, p))
  def membership(conn, %{"id" => id} = p), do: respond(conn, Groups.membership(conn.assigns.app_grant, id, p))
  def events(conn, %{"id" => id} = p), do: respond(conn, Groups.timeline(conn.assigns.app_grant, id, p))
  def send_event(conn, %{"id" => id, "type" => type, "txn_id" => txn} = p),
    do: respond(conn, Groups.send(conn.assigns.app_grant, id, type, txn, p["content"]))

  defp respond(conn, {:ok, body}), do: json(conn, body)
  defp respond(conn, {:error, reason}) do
    status = case reason do
      r when r in [:forbidden, :insufficient_scope] -> 403
      :transaction_conflict -> 409
      _ -> 400
    end
    conn |> put_status(status) |> json(%{error: to_string(reason)})
  end
end
