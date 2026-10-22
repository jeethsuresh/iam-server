defmodule LakehouseWeb.IamSessionController do
  use LakehouseWeb, :controller

  alias LakehouseWeb.IamAuth
  alias LakehouseIam.Auth.{Sessions, Token}

  def create(conn, params) do
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
        issue_session(conn, token)

      {:ok, %{redirect: url} = payload} ->
        if Map.has_key?(payload, :user_jwt),
          do: issue_session(conn, payload.user_jwt, %{redirect: url}),
          else: json(conn, %{redirect: url})

      {:error, status, body} ->
        conn
        |> put_status(error_status(status))
        |> respond_error(body)
    end
  end

  def delete(conn, _params) do
    conn = LakehouseWeb.BrowserSession.logout(conn)

    case get_format(conn) do
      "html" ->
        conn
        |> put_flash(:info, "Signed out.")
        |> redirect(to: ~p"/")

      _ ->
        json(conn, "Logged out")
    end
  end

  def refresh(conn, _params) do
    conn = put_resp_header(conn, "cache-control", "no-store")

    case Sessions.rotate(conn.body_params["refresh_token"], :api) do
      {:ok, bundle} -> json(conn, bundle)
      _ -> conn |> put_status(401) |> json(%{error: "invalid_grant"})
    end
  end

  def revoke(conn, _params) do
    Sessions.revoke(conn.body_params["refresh_token"], :api)
    conn |> put_resp_header("cache-control", "no-store") |> send_resp(204, "")
  end

  def show(conn, _params) do
    claims = conn.assigns.jwt_claims

    conn
    |> put_resp_header("cache-control", "no-store")
    |> json(%{
      authenticated: true,
      expires_in: max(claims["exp"] - System.system_time(:second), 0)
    })
  end

  defp issue_session(conn, jwt, extra \\ %{}) do
    with {:ok, %{"username" => username}} <- Token.verify(jwt),
         {:ok, bundle} <- Sessions.issue(username, :api) do
      conn |> put_resp_header("cache-control", "no-store") |> json(Map.merge(bundle, extra))
    else
      _ -> conn |> put_status(401) |> json(%{error: "invalid_grant"})
    end
  end

  defp respond_error(conn, body) when is_map(body), do: json(conn, body)
  defp respond_error(conn, body), do: json(conn, body)

  defp error_status(:bad_request), do: 400
  defp error_status(:unauthorized), do: 401
  defp error_status(:not_found), do: 404
  defp error_status(:internal_server_error), do: 500
  defp error_status(_), do: 400
end
