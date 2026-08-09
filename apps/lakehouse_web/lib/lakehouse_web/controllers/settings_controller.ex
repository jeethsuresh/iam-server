defmodule LakehouseWeb.SettingsController do
  use LakehouseWeb, :controller

  plug :put_layout, html: {LakehouseWeb.Layouts, :settings}

  alias LakehouseIam.Accounts

  def index(conn, _params) do
    flash = Map.get(conn.assigns, :flash)

    pending =
      if Map.get(conn.assigns, :current_user_is_admin, false),
        do: Accounts.list_pending_users(),
        else: []

    render(conn, :index,
      username: conn.assigns.username,
      current_user_is_admin: Map.get(conn.assigns, :current_user_is_admin, false),
      pending_users: pending,
      flash_info: flash && Phoenix.Flash.get(flash, :info),
      flash_error: flash && Phoenix.Flash.get(flash, :error)
    )
  end

  def redirect_legacy(conn, _params) do
    redirect(conn, to: ~p"/settings")
  end
end
