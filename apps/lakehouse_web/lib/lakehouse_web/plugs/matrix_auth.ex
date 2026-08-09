defmodule LakehouseWeb.Plugs.MatrixAuth do
  @moduledoc """
  Matrix Client-Server API authentication via `Authorization: Bearer` access token.
  """
  import Plug.Conn

  alias LakehouseIam.Accounts
  alias LakehouseIam.Schema.Principal

  def init(opts), do: opts

  def call(conn, _opts) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] ->
        case LakehouseIam.Auth.Token.verify(token) do
          {:ok, claims} ->
            username = claims["username"]

            case Accounts.fetch_user(username) do
              {:ok, %Principal{id: principal_id} = principal} ->
                conn
                |> assign(:jwt_claims, claims)
                |> assign(:username, username)
                |> assign(:principal_id, principal_id)
                |> assign(:current_principal, principal)

              :error ->
                matrix_error(conn, 401, "M_UNKNOWN_TOKEN", "Unknown access token")
            end

          :error ->
            matrix_error(conn, 401, "M_UNKNOWN_TOKEN", "Unknown access token")
        end

      _ ->
        matrix_error(conn, 401, "M_MISSING_TOKEN", "Missing access token")
    end
  end

  defp matrix_error(conn, status, errcode, error) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(%{"errcode" => errcode, "error" => error}))
    |> halt()
  end
end
