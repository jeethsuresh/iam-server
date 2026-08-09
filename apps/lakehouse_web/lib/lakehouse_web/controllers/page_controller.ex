defmodule LakehouseWeb.PageController do
  use LakehouseWeb, :controller

  def home(conn, params) do
    case get_session(conn, :user_jwt) do
      token when is_binary(token) and token != "" ->
        case LakehouseIam.Auth.Token.verify(token) do
          {:ok, _} ->
            redirect(conn, to: ~p"/rooms")

          :error ->
            render_home(conn, params)
        end

      _ ->
        render_home(conn, params)
    end
  end

  def register(conn, _params) do
    flash = Map.get(conn.assigns, :flash)

    render(conn, :register,
      error: flash && Phoenix.Flash.get(flash, :error),
      info: flash && Phoenix.Flash.get(flash, :info)
    )
  end

  defp render_home(conn, params) do
    flash = Map.get(conn.assigns, :flash)

    render(conn, :home,
      error: flash && Phoenix.Flash.get(flash, :error),
      info: flash && Phoenix.Flash.get(flash, :info),
      username: params["username"] || "",
      session_id: params["sessionID"] || ""
    )
  end
end
