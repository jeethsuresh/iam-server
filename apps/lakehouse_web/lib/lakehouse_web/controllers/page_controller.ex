defmodule LakehouseWeb.PageController do
  use LakehouseWeb, :controller

  def home(conn, params) do
    case get_session(conn, :user_jwt) do
      token when is_binary(token) and token != "" ->
        case LakehouseIam.Auth.Token.verify(token) do
          {:ok, %{"username" => username}} when not is_map_key(params, "sessionID") ->
            case LakehouseIam.Accounts.fetch_user(username) do
              {:ok, %{active: true}} -> redirect(conn, to: ~p"/dashboard")
              _ -> conn |> delete_session(:user_jwt) |> render_home(params)
            end

          :error ->
            conn
            |> delete_session(:user_jwt)
            |> put_flash(:error, "Please sign in again to continue.")
            |> render_home(params)

          _ ->
            render_home(conn, params)
        end

      _ ->
        render_home(conn, params)
    end
  end

  def register(conn, params) do
    flash = Map.get(conn.assigns, :flash)
    {session_id, username} = login_context(params)

    render(conn, :register,
      error: flash && Phoenix.Flash.get(flash, :error),
      info: flash && Phoenix.Flash.get(flash, :info),
      session_id: session_id,
      username: username
    )
  end

  defp render_home(conn, params) do
    flash = Map.get(conn.assigns, :flash)
    {session_id, username} = login_context(params)

    render(conn, :home,
      error: flash && Phoenix.Flash.get(flash, :error),
      info: flash && Phoenix.Flash.get(flash, :info),
      username: username,
      session_id: session_id
    )
  end

  defp login_context(params) do
    session_id = params["sessionID"]

    case LakehouseIam.Federated.fetch(session_id) do
      nil -> {"", if(is_binary(params["username"]), do: params["username"], else: "")}
      session -> {session_id, session.username || params["username"] || ""}
    end
  end
end
