defmodule LakehouseWeb.IamProfileController do
  use LakehouseWeb, :controller

  def show(conn, _params) do
    case get_format(conn) do
      "html" ->
        redirect(conn, to: ~p"/settings")

      _ ->
        json(conn, %{username: conn.assigns.username})
    end
  end
end
