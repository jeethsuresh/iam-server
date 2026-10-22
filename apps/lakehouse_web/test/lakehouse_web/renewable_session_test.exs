defmodule LakehouseWeb.RenewableSessionTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.{Auth.Sessions, Auth.Token, Repo}
  alias LakehouseIam.Schema.Session
  alias LakehouseWeb.{BrowserSession, MatrixFixtures}

  setup do
    user = MatrixFixtures.user_fixture("renewweb")

    old =
      for key <- [:secure_auth_cookies, :sso_cookie_domain],
          into: %{},
          do: {key, Application.get_env(:lakehouse_web, key)}

    Application.put_env(:lakehouse_web, :secure_auth_cookies, true)
    Application.put_env(:lakehouse_web, :sso_cookie_domain, "gravitas.cool")

    on_exit(fn ->
      Enum.each(old, fn {key, value} ->
        if is_nil(value),
          do: Application.delete_env(:lakehouse_web, key),
          else: Application.put_env(:lakehouse_web, key, value)
      end)
    end)

    {:ok, user: user}
  end

  defp login_api,
    do: post(build_conn(), "/login", %{username: "renewweb", password: "password123"})

  defp login_browser,
    do: post(build_conn(), "/web/login", %{username: "renewweb", password: "password123"})

  defp refreshed(raw), do: post(build_conn(), "/refresh", %{refresh_token: raw})

  test "API login is additive and refresh accepts body credentials only" do
    body = login_api() |> json_response(200)
    assert body["expires_in"] == 3600
    assert body["token_type"] == "Bearer"
    assert is_binary(body["refresh_token"])

    assert json_response(
             post(build_conn(), "/refresh?refresh_token=" <> body["refresh_token"], %{}),
             401
           )["error"] == "invalid_grant"

    next = refreshed(body["refresh_token"]) |> json_response(200)
    refute next["refresh_token"] == body["refresh_token"]
    assert json_response(refreshed(body["refresh_token"]), 401)["error"] == "invalid_grant"
    assert :error = Token.verify(next["token"])
  end

  test "revocation is idempotent and invalidates access immediately" do
    body = login_api() |> json_response(200)

    for _ <- 1..2 do
      conn = post(build_conn(), "/revoke", %{refresh_token: body["refresh_token"]})
      assert response(conn, 204) == ""
      assert get_resp_header(conn, "cache-control") == ["no-store"]
    end

    assert :error = Token.verify(body["token"])
  end

  test "browser credentials are host-only; the shared cookie is only a secure sign-in hint" do
    conn = login_browser()
    refresh = conn.resp_cookies["__Host-gravitas_refresh"]
    marker = conn.resp_cookies["__Secure-gravitas_signed_in"]

    assert refresh.secure && refresh.http_only && refresh.same_site == "Lax" &&
             refresh.path == "/"

    refute Map.has_key?(refresh, :domain)
    assert refresh.max_age in 2_591_998..2_592_000
    assert marker.value == "1" && marker.domain == "gravitas.cool"
    assert marker.secure && marker.http_only && marker.same_site == "Lax"
    refute conn.resp_body =~ refresh.value
    assert {:error, :invalid} = Sessions.rotate(refresh.value, :api)
  end

  test "missing access cookie renews from a persistent refresh cookie" do
    initial = login_browser()
    raw = initial.resp_cookies[BrowserSession.refresh_cookie_name()].value

    conn =
      build_conn()
      |> put_req_cookie(BrowserSession.refresh_cookie_name(), raw)
      |> get("/settings")

    assert html_response(conn, 200) =~ "Settings"
    assert {:ok, _} = Token.verify(get_session(conn, :user_jwt))
    refute conn.resp_cookies[BrowserSession.refresh_cookie_name()].value == raw
  end

  test "a fresh password login replaces and revokes the previous browser family" do
    initial = login_browser()
    old = initial.resp_cookies[BrowserSession.refresh_cookie_name()].value

    next =
      initial |> recycle() |> post("/web/login", %{username: "renewweb", password: "password123"})

    assert redirected_to(next) == "/dashboard"
    assert {:error, :invalid} = Sessions.rotate(old, :browser)

    assert {:ok, _} =
             Sessions.rotate(
               next.resp_cookies[BrowserSession.refresh_cookie_name()].value,
               :browser
             )
  end

  test "expired access is renewed before protected pages and the JSON heartbeat", %{user: user} do
    initial = login_browser()
    {:ok, claims} = Token.verify(get_session(initial, :user_jwt))

    expired =
      Token.issue(user.username,
        session_id: claims["sid"],
        session_expires_at: claims["rfe"],
        expires_in: -1
      )

    raw = initial.resp_cookies[BrowserSession.refresh_cookie_name()].value

    conn =
      build_conn()
      |> init_test_session(user_jwt: expired)
      |> put_req_cookie(BrowserSession.refresh_cookie_name(), raw)
      |> put_req_header("accept", "application/json")
      |> get("/web/session")

    assert json_response(conn, 200)["authenticated"]
    assert get_resp_header(conn, "cache-control") == ["no-store"]
    assert {:ok, renewed} = Token.verify(get_session(conn, :user_jwt))
    assert renewed["sid"] == claims["sid"]
  end

  test "silent application starts renew an expired base session without demanding a password", %{
    user: user
  } do
    {:ok, bundle} = Sessions.issue(user.username, :browser)

    params = %{
      callerURL: "http://127.0.0.1:4102/",
      redirectURL: "http://127.0.0.1:4102/oauth/callback",
      codeChallenge: LakehouseIam.Apps.Pkce.challenge("test-verifier"),
      scope: "profile.name",
      state: "flowstate",
      prompt: "none"
    }

    prior = Application.get_env(:lakehouse_iam, :relaxed_callback_urls)
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)
    on_exit(fn -> Application.put_env(:lakehouse_iam, :relaxed_callback_urls, prior) end)

    conn =
      build_conn()
      |> put_req_cookie(BrowserSession.refresh_cookie_name(), bundle.refresh_token)
      |> get("/oauth/start", params)

    query = conn |> redirected_to() |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["error"] == "consent_required"
    assert query["state"] == "flowstate"
  end

  test "a forged shared marker cannot authenticate" do
    conn =
      build_conn()
      |> put_req_cookie(BrowserSession.marker_cookie_name(), "1")
      |> get("/dashboard")

    assert redirected_to(conn) == "/"
    refute get_session(conn, :user_jwt)
    assert conn.resp_cookies[BrowserSession.marker_cookie_name()].max_age == 0
  end

  test "logout clears both exact cookie scopes and revokes the browser family" do
    initial = login_browser()
    raw = initial.resp_cookies[BrowserSession.refresh_cookie_name()].value
    jwt = get_session(initial, :user_jwt)
    conn = initial |> recycle() |> post("/web/logout")
    assert redirected_to(conn) == "/"
    assert conn.resp_cookies[BrowserSession.refresh_cookie_name()].max_age == 0
    refute Map.has_key?(conn.resp_cookies[BrowserSession.refresh_cookie_name()], :domain)
    assert conn.resp_cookies[BrowserSession.marker_cookie_name()].domain == "gravitas.cool"
    assert conn.resp_cookies[BrowserSession.marker_cookie_name()].max_age == 0
    assert {:error, :invalid} = Sessions.rotate(raw, :browser)
    assert :error = Token.verify(jwt)
  end

  test "expired refresh cannot revive the account or extend the cookie lifetime" do
    initial = login_browser()
    session = Repo.one!(Session)

    Repo.update!(
      Ecto.Changeset.change(session, expires_at: DateTime.add(DateTime.utc_now(), -1, :second))
    )

    conn = initial |> recycle() |> get("/settings")
    assert redirected_to(conn) == "/"
    assert conn.resp_cookies[BrowserSession.refresh_cookie_name()].max_age == 0
  end

  test "explicit bearer authentication never renews using ambient cookies" do
    initial = login_browser()

    conn =
      initial
      |> recycle()
      |> put_req_header("authorization", "Bearer invalid")
      |> put_req_header("accept", "application/json")
      |> get("/web/session")

    assert json_response(conn, 401) == "Invalid token"
    refute Map.has_key?(conn.resp_cookies, BrowserSession.refresh_cookie_name())
  end
end
