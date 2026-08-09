defmodule LakehouseWeb.Plugs.BearerAuth do
  @moduledoc """
  Validates `Authorization: Bearer` tokens using HS256 only (iam-server `/profile` semantics).
  """
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] ->
        case LakehouseIam.Auth.Token.verify(token) do
          {:ok, claims} ->
            username = claims["username"]

            conn =
              conn
              |> assign(:jwt_claims, claims)
              |> assign(:username, username)

            case LakehouseIam.Accounts.fetch_user(username) do
              {:ok, principal} -> assign(conn, :principal_id, principal.id)
              :error -> conn
            end

          :error ->
            conn
            |> put_resp_content_type("application/json")
            |> send_resp(401, Jason.encode!("Invalid token"))
            |> halt()
        end

      _ ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(401, Jason.encode!("Missing token"))
        |> halt()
    end
  end
end
