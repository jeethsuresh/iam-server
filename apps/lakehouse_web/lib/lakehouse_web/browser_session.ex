defmodule LakehouseWeb.BrowserSession do
  @moduledoc "Host-only renewable credentials and a non-authenticating domain sign-in hint."
  import Plug.Conn
  alias LakehouseIam.{Accounts, Auth.Sessions, Auth.Token}

  def refresh_cookie_name,
    do: if(secure?(), do: "__Host-gravitas_refresh", else: "gravitas_refresh")

  def marker_cookie_name,
    do: if(secure?(), do: "__Secure-gravitas_signed_in", else: "gravitas_signed_in")

  def sign_in(conn, jwt) do
    conn = fetch_cookies(conn)

    with {:ok, %{"username" => username}} <- Token.verify(jwt),
         {:ok, bundle} <- Sessions.issue(username, :browser) do
      Sessions.revoke(conn.req_cookies[refresh_cookie_name()], :browser)
      {:ok, install(conn, bundle)}
    else
      _ -> {:error, conn}
    end
  end

  def accept_login(conn, bundle) do
    conn = fetch_cookies(conn)

    with {:ok, _} <- Token.verify(bundle.token) do
      Sessions.revoke(conn.req_cookies[refresh_cookie_name()], :browser)
      {:ok, install(conn, bundle)}
    else
      _ -> {:error, conn}
    end
  end

  def renew(conn) do
    conn = fetch_cookies(conn)
    raw = conn.req_cookies[refresh_cookie_name()]

    case verified_principal(get_session(conn, :user_jwt)) do
      {:ok, claims} ->
        ttl = claims["exp"] - System.system_time(:second)

        window =
          min(300, max(div(Application.fetch_env!(:lakehouse_iam, :token_ttl_seconds), 10), 0))

        cond do
          is_nil(claims["sid"]) ->
            case Sessions.issue(claims["username"], :browser) do
              {:ok, bundle} -> install(conn, bundle)
              _ -> conn
            end

          is_binary(raw) and ttl <= window ->
            rotate(conn, raw)

          true ->
            marker(conn, max((claims["rfe"] || claims["exp"]) - System.system_time(:second), 0))
        end

      _ ->
        if is_binary(raw), do: rotate(conn, raw), else: clear_hint(conn)
    end
  end

  def logout(conn) do
    conn = fetch_cookies(conn)
    Sessions.revoke(conn.req_cookies[refresh_cookie_name()], :browser)
    Sessions.revoke_access(get_session(conn, :user_jwt))
    conn |> clear_refresh() |> configure_session(drop: true)
  end

  defp rotate(conn, raw) do
    case Sessions.rotate(raw, :browser) do
      {:ok, bundle} -> install(conn, bundle)
      {:error, reason} when reason in [:invalid, :reused] -> clear_refresh(conn)
      _ -> conn
    end
  end

  defp verified_principal(jwt) do
    with {:ok, %{"username" => username} = claims} <- Token.verify(jwt),
         {:ok, %{active: true}} <- Accounts.fetch_user(username),
         do: {:ok, claims},
         else: (_ -> :error)
  end

  defp install(conn, bundle) do
    conn
    |> put_session(:user_jwt, bundle.token)
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_cookie(
      refresh_cookie_name(),
      bundle.refresh_token,
      cookie_options() ++ [max_age: bundle.refresh_expires_in]
    )
    |> marker(bundle.refresh_expires_in, true)
  end

  defp marker(conn, remaining, force \\ false) do
    if force or conn.req_cookies[marker_cookie_name()] != "1" do
      put_resp_cookie(conn, marker_cookie_name(), "1", marker_options() ++ [max_age: remaining])
    else
      conn
    end
  end

  defp clear_hint(conn) do
    if Map.has_key?(conn.req_cookies, marker_cookie_name()),
      do: delete_resp_cookie(conn, marker_cookie_name(), marker_options()),
      else: conn
  end

  defp clear_refresh(conn) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> delete_resp_cookie(refresh_cookie_name(), cookie_options())
    |> delete_resp_cookie(marker_cookie_name(), marker_options())
  end

  defp secure?, do: Application.get_env(:lakehouse_web, :secure_auth_cookies, false)
  defp cookie_options, do: [secure: secure?(), http_only: true, same_site: "Lax", path: "/"]

  defp marker_options do
    case Application.get_env(:lakehouse_web, :sso_cookie_domain) do
      domain when is_binary(domain) -> cookie_options() ++ [domain: domain]
      _ -> cookie_options()
    end
  end
end
