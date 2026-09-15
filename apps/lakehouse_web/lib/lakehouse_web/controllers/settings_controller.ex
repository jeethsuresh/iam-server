defmodule LakehouseWeb.SettingsController do
  use LakehouseWeb, :controller

  plug :put_layout, html: {LakehouseWeb.Layouts, :settings}

  alias LakehouseIam.Accounts
  alias LakehouseIam.Apps.{Grants, Tokens}

  def index(conn, _params) do
    flash = Map.get(conn.assigns, :flash)

    pending =
      if Map.get(conn.assigns, :current_user_is_admin, false),
        do: Accounts.list_pending_users(),
        else: []

    connected_apps = Grants.list_for_principal(conn.assigns.principal_id)

    render(conn, :index,
      username: conn.assigns.username,
      current_user_is_admin: Map.get(conn.assigns, :current_user_is_admin, false),
      pending_users: pending,
      connected_apps: connected_apps,
      flash_info: flash && Phoenix.Flash.get(flash, :info),
      flash_error: flash && Phoenix.Flash.get(flash, :error)
    )
  end

  def revoke_app(conn, %{"origin" => origin}) do
    case Tokens.revoke_app(conn.assigns.principal_id, origin) do
      :ok ->
        conn
        |> put_flash(:info, "Revoked access for #{origin}.")
        |> redirect(to: ~p"/settings")

      {:error, :not_found} ->
        conn
        |> put_flash(:error, "App not found.")
        |> redirect(to: ~p"/settings")
    end
  end

  def redirect_legacy(conn, _params) do
    redirect(conn, to: ~p"/settings")
  end
end
