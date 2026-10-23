defmodule LakehouseWeb.ContactsController do
  use LakehouseWeb, :controller
  alias LakehouseIam.Contacts
  plug :put_layout, html: {LakehouseWeb.Layouts, :dashboard}

  def index(conn, _) do
    {:ok, data} = Contacts.owner_list(conn.assigns.principal_id)
    render(conn, :index, contacts: data, active_page: :contacts)
  end

  def mutate(conn, params) do
    case Contacts.owner_act(conn.assigns.principal_id, params) do
      {:ok, _} -> conn |> put_flash(:info, "Contacts updated.") |> redirect(to: ~p"/contacts")
      {:error, reason} ->
        message = case reason do
          :too_many_requests -> "Too many requests. Try again later."
          :invalid_membership -> "This request has changed. Refresh and try again."
          :transaction_conflict -> "This action has changed. Refresh and try again."
          _ -> "Unable to update this contact. Check the username and request."
        end
        conn |> put_flash(:error, message) |> redirect(to: ~p"/contacts")
    end
  end
end
