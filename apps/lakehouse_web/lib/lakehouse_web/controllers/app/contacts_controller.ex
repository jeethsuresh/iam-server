defmodule LakehouseWeb.App.ContactsController do
  use LakehouseWeb, :controller
  alias LakehouseIam.Contacts
  def index(conn, _), do: respond(conn, Contacts.list(conn.assigns.app_grant))
  def events(conn, _), do: respond(conn, Contacts.events(conn.assigns.app_grant))
  def mutate(conn, p), do: respond(conn, Contacts.act(conn.assigns.app_grant, p))
  defp respond(conn, {:ok, body}), do: json(conn, body)
  defp respond(conn, {:error, reason}) do
    status = case reason do
      r when r in [:forbidden, :insufficient_scope] -> 403
      :transaction_conflict -> 409
      :too_many_requests -> 429
      _ -> 400
    end
    conn |> put_status(status) |> json(%{error: to_string(reason)})
  end
end
