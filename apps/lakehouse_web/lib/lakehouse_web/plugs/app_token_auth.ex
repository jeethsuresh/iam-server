defmodule LakehouseWeb.Plugs.AppTokenAuth do
  @moduledoc "Authenticates opaque third-party app access tokens."
  import Plug.Conn

  alias LakehouseIam.Apps.Tokens

  def init(opts), do: opts

  def call(conn, _opts) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] ->
        case Tokens.verify_access(token) do
          {:ok, %{grant: grant, token: token}} ->
            grant = %{grant | scopes: Tokens.effective_scopes(token, grant)}

            conn
            |> assign(:app_token, token)
            |> assign(:app_grant, grant)
            |> assign(:principal_id, grant.principal_id)
            |> assign(:app_origin, grant.app_origin)
            |> LakehouseWeb.Plugs.MatrixAccountPolicy.call([])

          {:error, _} ->
            conn
            |> put_resp_content_type("application/json")
            |> send_resp(401, Jason.encode!(%{error: "invalid_token"}))
            |> halt()
        end

      _ ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(401, Jason.encode!(%{error: "missing_token"}))
        |> halt()
    end
  end
end
