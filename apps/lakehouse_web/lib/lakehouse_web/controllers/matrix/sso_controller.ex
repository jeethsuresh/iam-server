defmodule LakehouseWeb.Matrix.SsoController do
  use LakehouseWeb, :controller
  alias LakehouseMatrix.ClientSso

  def start(conn, params) do
    conn = private_response(conn)
    issuer = URI.parse(LakehouseIam.Discovery.public_url())
    matrix = URI.parse(LakehouseMatrix.Discovery.public_url())

    if conn.host == matrix.host and
         (matrix.host != issuer.host or (matrix.port != issuer.port and conn.port == matrix.port)) do
      # Browser sessions and consent pages belong to IAM. Redirect before
      # creating a host-bound SSO request on the delegated Matrix API host.
      query = if conn.query_string == "", do: "", else: "?" <> conn.query_string
      redirect(conn, external: LakehouseIam.Discovery.public_url() <> conn.request_path <> query)
    else
      start_request(conn, params)
    end
  end

  defp start_request(conn, params) do
    if params["idpId"] in [nil, "gravitas"] and params["action"] in [nil, "login", "register"] do
      case ClientSso.start(params["redirectUrl"]) do
        {:ok, id} ->
          conn = put_session(conn, :matrix_sso_request, id)

          if params["action"] == "register",
            do:
              conn |> put_session(:return_to, "/matrix/sso/consent") |> redirect(to: "/register"),
            else: redirect(conn, to: "/matrix/sso/consent")

        {:error, reason} ->
          LakehouseWeb.Matrix.ProtocolController.respond(conn, {:error, reason})
      end
    else
      LakehouseWeb.Matrix.ProtocolController.respond(conn, {:error, :not_found})
    end
  end

  def consent(conn, _) do
    conn = private_response(conn)

    case ClientSso.fetch(get_session(conn, :matrix_sso_request)) do
      nil ->
        conn
        |> put_status(400)
        |> html("This Matrix sign-in request expired. Start sign-in again from your client.")

      url ->
        render(conn, :consent, url: url, username: conn.assigns.username)
    end
  end

  def approve(conn, params) do
    conn = private_response(conn)
    id = get_session(conn, :matrix_sso_request)

    if params["decision"] == "allow" do
      case ClientSso.approve(conn.assigns.principal_id, id) do
        {:ok, url} ->
          conn |> delete_session(:matrix_sso_request) |> redirect(external: url)

        _ ->
          conn
          |> delete_session(:matrix_sso_request)
          |> put_status(400)
          |> html("This Matrix sign-in request expired. Start sign-in again from your client.")
      end
    else
      conn |> delete_session(:matrix_sso_request) |> redirect(to: "/dashboard")
    end
  end

  defp private_response(conn),
    do:
      conn
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("referrer-policy", "no-referrer")
end
