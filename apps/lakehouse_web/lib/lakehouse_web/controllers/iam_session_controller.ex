defmodule LakehouseWeb.IamSessionController do
  use LakehouseWeb, :controller

  alias LakehouseWeb.IamAuth

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
        json(conn, %{token: token})

      {:ok, %{redirect: url} = payload} ->
        body =
          if Map.has_key?(payload, :user_jwt) do
            %{redirect: url, token: payload.user_jwt}
          else
            %{redirect: url}
          end

        json(conn, body)

      {:error, status, body} ->
        conn
        |> put_status(error_status(status))
        |> respond_error(body)
    end
  end

  def delete(conn, _params) do
    conn = configure_session(conn, drop: true)

    case get_format(conn) do
      "html" ->
        conn
        |> put_flash(:info, "Signed out.")
        |> redirect(to: ~p"/")

      _ ->
        json(conn, "Logged out")
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
