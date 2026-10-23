defmodule LakehouseWeb.NativeBrokerTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.{Accounts, Federated}
  alias LakehouseIam.Apps.{Grants, Pkce, Tokens}
  alias LakehouseIam.Auth.{Sessions, Token}
  alias LakehouseWeb.MatrixFixtures
  alias LakehouseWeb.Test.Api.OAuthClient

  @broker "http://127.0.0.1:4105"
  @app "http://127.0.0.1:4106"

  setup do
    old_origin = Application.get_env(:lakehouse_iam, :native_broker_origin)
    old_relaxed = Application.get_env(:lakehouse_iam, :relaxed_callback_urls)
    Application.put_env(:lakehouse_iam, :native_broker_origin, @broker)
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)
    on_exit(fn ->
      Application.put_env(:lakehouse_iam, :native_broker_origin, old_origin)
      Application.put_env(:lakehouse_iam, :relaxed_callback_urls, old_relaxed)
    end)
    {:ok, user} = Accounts.register_user("brokerweb", "password123", approve: true)
    {:ok, family} = Sessions.issue(user.username, :browser)
    {:ok, claims} = Token.verify(family.token)
    {:ok, grant} = Grants.upsert(user.id, @broker, ["profile.name", "native.broker"], :selected)
    {:ok, pair} = Tokens.issue(grant, claims["sid"])
    verifier = Pkce.generate_verifier()
    params = %{app_origin: @app, redirect_uri: @app <> "/auth/gravitas/callback",
      code_challenge: Pkce.challenge(verifier), code_challenge_method: "S256", scope: "profile.name", state: "native-client-state"}
    %{user: user, family: family, pair: pair, grant: grant, verifier: verifier, params: params}
  end

  test "JSON broker authorization exchanges through normal PKCE with a live family proof", c do
    {:ok, _} = Grants.upsert(c.user.id, @app, ["profile.name"], :selected)
    conn = OAuthClient.broker_authorize(c.pair.access_token, c.params)
    assert get_resp_header(conn, "cache-control") == ["no-store"]
    result = json_response(conn, 200)
    assert result["state"] == c.params.state && result["sub"] == c.user.id
    assert result["session_id"] == c.pair.session_id && result["expires_in"] <= 60
    child = OAuthClient.token(%{grant_type: "authorization_code", code: result["code"],
      code_verifier: c.verifier, redirect_uri: c.params.redirect_uri}) |> json_response(200)
    assert child["scope"] == "profile.name" && child["session_id"] == c.pair.session_id
    assert OAuthClient.session_check(child["session_check_token"]).status == 200
    Sessions.revoke(c.family.refresh_token, :browser)
    assert OAuthClient.session_check(child["session_check_token"]).status == 401
    assert OAuthClient.broker_authorize(c.pair.access_token, c.params) |> json_response(401) == %{"error" => "invalid_token"}
  end

  test "cookies and non-broker token kinds cannot authorize native clients", c do
    cookie_conn = build_conn() |> init_test_session(user_jwt: c.family.token)
    assert post(cookie_conn, "/oauth/broker/authorize", c.params) |> json_response(401) == %{"error" => "invalid_token"}
    for raw <- [c.pair.refresh_token, c.pair.session_check_token, c.family.token] do
      conn = OAuthClient.broker_authorize(raw, c.params)
      assert json_response(conn, 401) == %{"error" => "invalid_token"}
      assert get_resp_header(conn, "cache-control") == ["no-store"]
    end
    {:ok, ordinary} = Tokens.issue(c.grant, c.pair.session_id, scopes: ["profile.name"])
    assert OAuthClient.broker_authorize(ordinary.access_token, c.params) |> json_response(403) == %{"error" => "insufficient_scope"}
  end

  test "missing target consent and malformed requests fail without creating a grant", c do
    assert OAuthClient.broker_authorize(c.pair.access_token, c.params) |> json_response(403) == %{"error" => "consent_required"}
    refute Grants.get(c.user.id, @app)
    bad = Map.put(c.params, :redirect_uri, "https://elsewhere.example/callback")
    assert OAuthClient.broker_authorize(c.pair.access_token, bad) |> json_response(400) == %{"error" => "invalid_request"}
    refute Grants.get(c.user.id, @app)
  end

  test "new broker permission requires readable explicit browser consent", c do
    :ok = Grants.revoke(c.grant.id)
    conn = build_conn() |> init_test_session(user_jwt: MatrixFixtures.browser_token(c.user.username))
    conn = get(conn, "/oauth/start", %{callerURL: @broker, redirectURL: @broker <> "/auth/android/callback",
      codeChallenge: Pkce.challenge(c.verifier), scope: "profile.name native.broker", state: "broker-consent"})
    path = redirected_to(conn)
    assert path =~ "/oauth/consent?sessionID="
    page = conn |> recycle() |> get(path) |> html_response(200)
    assert page =~ "sign you into apps you have already approved on this device"
    refute Grants.get(c.user.id, @broker)
    sid = URI.decode_query(URI.parse(path).query)["sessionID"]
    assert Federated.fetch(sid).scopes == ["profile.name", "native.broker"]
  end

  test "new profile-only credentials cannot use previously approved chat permissions", c do
    {:ok, grant} = Grants.upsert(c.user.id, @app, ["profile.name", "chats.list"], :selected)
    {:ok, pair} = Tokens.issue(grant, c.pair.session_id, scopes: ["profile.name"])
    assert OAuthClient.me(pair.access_token).status == 200
    assert OAuthClient.chats(pair.access_token).status == 403
  end
end
