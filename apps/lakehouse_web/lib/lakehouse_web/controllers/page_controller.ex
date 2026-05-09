defmodule LakehouseWeb.PageController do
  use LakehouseWeb, :controller

  def home(conn, params) do
    flash = Map.get(conn.assigns, :flash)

    render(conn, :home,
      error: flash && Phoenix.Flash.get(flash, :error),
      info: flash && Phoenix.Flash.get(flash, :info),
      username: params["username"] || "",
      session_id: params["sessionID"] || ""
    )
  end

  def register(conn, _params) do
    flash = Map.get(conn.assigns, :flash)

    render(conn, :register,
      error: flash && Phoenix.Flash.get(flash, :error),
      info: flash && Phoenix.Flash.get(flash, :info)
    )
  end
end
