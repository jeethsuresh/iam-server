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

        conn
        |> put_session(:user_jwt, token)
        |> put_flash(:info, "Signed in.")
        |> redirect(to: destination)

      {:ok, %{redirect: "/" <> _ = path, user_jwt: jwt}} ->
        conn
        |> put_session(:user_jwt, jwt)
        |> delete_session(:return_to)
        |> redirect(to: path)

      {:ok, %{redirect: url, user_jwt: jwt}} ->
        conn
        |> put_session(:user_jwt, jwt)
        |> delete_session(:return_to)
        |> redirect(external: url)

      {:ok, %{redirect: url}} ->
        conn |> delete_session(:return_to) |> redirect(external: url)

      {:error, _status, body} ->
        conn
        |> put_flash(:error, humanize_error(body))
        |> redirect(to: IamAuth.login_path(username, session_id))
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
