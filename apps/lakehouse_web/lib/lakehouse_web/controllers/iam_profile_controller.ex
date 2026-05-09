defmodule LakehouseWeb.IamProfileController do
  use LakehouseWeb, :controller

  def show(conn, _params) do
    case get_format(conn) do
      "html" ->
        render(conn, :show,
          username: conn.assigns.username,
          current_user_is_admin: Map.get(conn.assigns, :current_user_is_admin, false)
        )

      _ ->
        json(conn, %{username: conn.assigns.username})
    end
  end
end
