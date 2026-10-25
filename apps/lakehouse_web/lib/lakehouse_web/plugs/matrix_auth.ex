defmodule LakehouseWeb.Plugs.MatrixAuth do
  @moduledoc """
  Matrix Client-Server API authentication via `Authorization: Bearer` access token.
  """
  import Plug.Conn

  alias LakehouseIam.Accounts
  alias LakehouseIam.Schema.Principal

  def init(opts), do: opts

  def call(conn, opts) do
    conn = fetch_query_params(conn)
    authorization = if raw = token(conn), do: ["Bearer " <> raw], else: []

    case authorization do
      ["Bearer " <> token] ->
        case LakehouseMatrix.ClientStore.authenticate(token) do
          {:ok, principal, device, session} ->
            conn
            |> assign(:username, principal.username)
            |> assign(:principal_id, principal.id)
            |> assign(:current_principal, principal)
            |> assign(:matrix_device_id, device)
            |> assign(:matrix_session_id, session)
            |> LakehouseWeb.Plugs.MatrixAccountPolicy.call([])

          :expired ->
            conn
            |> put_resp_content_type("application/json")
            |> send_resp(
              401,
              Jason.encode!(%{
                "errcode" => "M_UNKNOWN_TOKEN",
                "error" => "Access token expired",
                "soft_logout" => true
              })
            )
            |> halt()

          :error ->
            legacy(conn, token, opts)
        end

      _ ->
        if opts[:optional],
          do: conn,
          else: matrix_error(conn, 401, "M_MISSING_TOKEN", "Missing access token")
    end
  end

  def token(conn) do
    case get_req_header(conn, "authorization") do
      [] ->
        params = fetch_query_params(conn).query_params
        if is_binary(params["access_token"]), do: params["access_token"]

      [header] ->
        case Regex.run(~r/\ABearer +([^\s]+)\z/i, header) do
          [_, raw] -> raw
          _ -> nil
        end

      _ ->
        nil
    end
  end

  defp legacy(conn, token, opts) do
    case LakehouseIam.Auth.Token.verify(token) do
      {:ok, claims} ->
        username = claims["username"]

        case Accounts.fetch_user(username) do
          {:ok, %Principal{id: principal_id} = principal} ->
            if Accounts.active?(principal) do
              conn
              |> assign(:jwt_claims, claims)
              |> assign(:username, username)
              |> assign(:principal_id, principal_id)
              |> assign(:current_principal, principal)
              |> assign(:matrix_device_id, "legacy")
              |> LakehouseWeb.Plugs.MatrixAccountPolicy.call([])
            else
              matrix_error(conn, 401, "M_UNKNOWN_TOKEN", "Unknown access token")
            end

          :error ->
            if opts[:optional],
              do: conn,
              else: matrix_error(conn, 401, "M_UNKNOWN_TOKEN", "Unknown access token")
        end

      :error ->
        if opts[:optional],
          do: conn,
          else: matrix_error(conn, 401, "M_UNKNOWN_TOKEN", "Unknown access token")
    end
  end

  defp matrix_error(conn, status, errcode, error) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(%{"errcode" => errcode, "error" => error}))
    |> halt()
  end
end
