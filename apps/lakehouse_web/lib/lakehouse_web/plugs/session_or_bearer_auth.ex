defmodule LakehouseWeb.Plugs.SessionOrBearerAuth do
  @moduledoc """
  Accepts `Authorization: Bearer` (HS256) or session key `user_jwt` set after browser login.
  """
  import Plug.Conn
  import Phoenix.Controller, only: [redirect: 2, put_flash: 3, get_format: 1]

  @session_key :user_jwt

  def init(opts), do: opts

  def call(conn, _opts) do
    token =
      case get_req_header(conn, "authorization") do
        ["Bearer " <> t] -> String.trim(t)
        _ -> nil
      end

    token =
      if token && token != "" do
        token
      else
        get_session(conn, @session_key)
      end

    cond do
      token in [nil, ""] ->
        maybe_halt_unauthorized(conn, "Missing token")

      true ->
        case LakehouseIam.Auth.Token.verify(token) do
          {:ok, claims} ->
            username = claims["username"]

            case LakehouseIam.Accounts.fetch_user(username) do
              {:ok, %{active: true} = principal} ->
                conn
                |> assign(:jwt_claims, claims)
                |> assign(:username, username)
                |> assign(:principal_id, principal.id)
                |> assign(:current_principal, principal)
                |> assign(:auth_token, token)
                |> assign(:current_user_is_admin, LakehouseIam.Accounts.admin?(username))

              _ ->
                maybe_halt_unauthorized(conn, "Unknown user")
            end

          :error ->
            maybe_halt_unauthorized(conn, "Invalid token")
        end
    end
  end

  defp maybe_halt_unauthorized(conn, msg) do
    if html_request?(conn) do
      conn
      |> put_flash(:error, msg)
      |> redirect(to: "/")
      |> halt()
    else
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(401, Jason.encode!(msg))
      |> halt()
    end
  end

  defp html_request?(conn) do
    case get_format(conn) do
      "html" -> true
      _ -> false
    end
  end
end
