defmodule LakehouseWeb.WebAuthController do
  use LakehouseWeb, :controller

  alias LakehouseWeb.IamAuth

  def login(conn, params) do
    username = params["username"]
    password = params["password"]
    session_id = params["sessionID"]

    result =
      if session_id not in [nil, ""] do
        IamAuth.federated_login(username, password, session_id)
      else
        IamAuth.standard_login(username, password)
      end

    case result do
      {:ok, token} when is_binary(token) ->
        {conn, destination} = LakehouseWeb.SessionReturn.consume(conn)

        finish_browser_login(conn, token, destination, false)

      {:ok, %{redirect: "/" <> _ = path, user_jwt: jwt}} ->
        finish_browser_login(conn, jwt, path, false)

      {:ok, %{redirect: url, user_jwt: jwt}} ->
        finish_browser_login(conn, jwt, url, true)

      {:ok, %{redirect: url}} ->
        conn |> delete_session(:return_to) |> redirect(external: url)

      {:error, _status, body} ->
        conn
        |> put_flash(:error, humanize_error(body))
        |> redirect(to: IamAuth.login_path(username, session_id))
    end
  end

  defp finish_browser_login(conn, jwt, destination, external?) do
    case LakehouseWeb.BrowserSession.sign_in(conn, jwt) do
      {:ok, conn} ->
        conn = conn |> delete_session(:return_to) |> put_flash(:info, "Signed in.")

        if external?,
          do: redirect(conn, external: destination),
          else: redirect(conn, to: destination)

      {:error, conn} ->
        conn
        |> put_flash(:error, "Could not create your session. Please sign in again.")
        |> redirect(to: ~p"/")
    end
  end

  def register(conn, params) do
    session_id = params["sessionID"]

    result =
      with :ok <- IamAuth.registration_session(session_id, params["username"]) do
        IamAuth.register(params["username"], params["password"], params["registration_key"])
      end

    case result do
      {:ok, principal} ->
        msg =
          if principal.active do
            "Your account is active. You can sign in."
          else
            "Registration received. An administrator must approve your account before you can sign in."
          end

        if session_id in [nil, ""] do
          conn |> put_flash(:info, msg) |> redirect(to: ~p"/")
        else
          case LakehouseIam.Federated.bind_user(session_id, principal.username) do
            {:ok, _} ->
              conn
              |> put_flash(:info, msg)
              |> redirect(to: IamAuth.login_path(principal.username, session_id))

            {:error, _} ->
              conn
              |> put_flash(:info, msg <> " Start sign-in again from your app.")
              |> redirect(to: ~p"/")
          end
        end

      {:error, _status, body} ->
        conn
        |> put_flash(:error, humanize_error(body))
        |> redirect(to: IamAuth.registration_path(session_id))
    end
  end

  defp humanize_error(%{error: "user_not_found"}), do: "No such user. Register first."
  defp humanize_error(body) when is_map(body), do: inspect(body)
  defp humanize_error(body), do: to_string(body)
end
