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
        conn
        |> put_session(:user_jwt, token)
        |> put_flash(:info, "Signed in.")
        |> redirect(to: ~p"/dashboard")

      {:ok, %{redirect: "/" <> _ = path, user_jwt: jwt}} ->
        conn
        |> put_session(:user_jwt, jwt)
        |> redirect(to: path)

      {:ok, %{redirect: url, user_jwt: jwt}} ->
        conn
        |> put_session(:user_jwt, jwt)
        |> redirect(external: url)

      {:ok, %{redirect: url}} ->
        redirect(conn, external: url)

      {:error, _status, body} ->
        conn
        |> put_flash(:error, humanize_error(body))
        |> redirect(to: ~p"/")
    end
  end

  def register(conn, params) do
    case IamAuth.register(params["username"], params["password"], params["registration_key"]) do
      {:ok, principal} ->
        msg =
          if principal.active do
            "Your account is active. You can sign in."
          else
            "Registration received. An administrator must approve your account before you can sign in."
          end

        conn
        |> put_flash(:info, msg)
        |> redirect(to: ~p"/")

      {:error, _status, body} ->
        conn
        |> put_flash(:error, humanize_error(body))
        |> redirect(to: ~p"/register")
    end
  end

  defp humanize_error(%{error: "user_not_found"}), do: "No such user. Register first."
  defp humanize_error(body) when is_map(body), do: inspect(body)
  defp humanize_error(body), do: to_string(body)
end
