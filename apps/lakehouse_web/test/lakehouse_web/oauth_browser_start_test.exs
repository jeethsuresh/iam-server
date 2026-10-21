defmodule LakehouseWeb.OAuthBrowserStartTest do
  use LakehouseWeb.ConnCase

  alias LakehouseIam.{Accounts, Federated, Identifier}
  alias LakehouseIam.Apps.{Grants, Pkce}
  alias LakehouseIam.Auth.Token
  alias LakehouseWeb.MatrixFixtures

  setup do
    previous = Application.get_env(:lakehouse_iam, :relaxed_callback_urls)
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)
    on_exit(fn -> Application.put_env(:lakehouse_iam, :relaxed_callback_urls, previous) end)
    user = MatrixFixtures.user_fixture("browserstart")
    verifier = Pkce.generate_verifier()

    params = %{
      "callerURL" => "http://127.0.0.1:4102/",
      "redirectURL" => "http://127.0.0.1:4102/callback?keep=1",
      "codeChallenge" => Pkce.challenge(verifier),
      "codeChallengeMethod" => "S256",
      "scope" => "profile.name",
      "state" => "state & +/"
    }

    {:ok, user: user, verifier: verifier, params: params}
  end

  defp signed_in(user),
    do: build_conn() |> init_test_session(user_jwt: Token.issue(user.username))

  defp callback(conn, params) do
    uri = conn |> redirected_to() |> URI.parse()
    expected = URI.parse(params["redirectURL"])

    assert {uri.scheme, uri.host, uri.port, uri.path} ==
             {expected.scheme, expected.host, expected.port, expected.path}

    query = URI.decode_query(uri.query)
    assert query["state"] == params["state"]
    assert query["keep"] == "1"
    query
  end

  test "backend registration can defer identity to the browser session", %{params: params} do
    body = post(build_conn(), "/backend/register", params) |> json_response(200)
    assert body["username"] == nil
    assert body["userID"] == nil
    assert Federated.fetch(body["sessionID"]).username == nil
  end

  test "interactive initiation uses the active account and requests new consent", %{
    user: user,
    params: params
  } do
    conn = get(signed_in(user), "/oauth/start", params)
    assert redirected_to(conn) =~ "/oauth/consent?sessionID="
    sid = URI.decode_query(URI.parse(redirected_to(conn)).query)["sessionID"]
    assert Federated.fetch(sid).username == user.username
  end

  test "silent sign-out returns login_required to the registered callback", %{params: params} do
    query =
      get(build_conn(), "/oauth/start", Map.put(params, "prompt", "none")) |> callback(params)

    assert query["error"] == "login_required"
    refute query["code"]
  end

  test "silent mode never creates consent", %{user: user, params: params} do
    query =
      get(signed_in(user), "/oauth/start", Map.put(params, "prompt", "none")) |> callback(params)

    assert query["error"] == "consent_required"
    refute Grants.get(user.id, "http://127.0.0.1:4102")
  end

  test "silent mode reuses a grant and exchanges a PKCE code", %{
    user: user,
    params: params,
    verifier: verifier
  } do
    {:ok, _} = Grants.upsert(user.id, "http://127.0.0.1:4102", ["profile.name"], :selected)

    query =
      get(signed_in(user), "/oauth/start", Map.put(params, "prompt", "none")) |> callback(params)

    refute query["error"]

    tokens =
      post(build_conn(), "/oauth/token", %{
        grant_type: "authorization_code",
        code: query["code"],
        code_verifier: verifier,
        redirect_uri: params["redirectURL"]
      })
      |> json_response(200)

    profile =
      build_conn()
      |> put_req_header("authorization", "Bearer " <> tokens["access_token"])
      |> get("/app/v1/me")
      |> json_response(200)

    assert profile["user_id"] == Identifier.format(user.username)
  end

  test "explicit identity cannot silently select a different logged-in account", %{
    user: user,
    params: params
  } do
    query =
      get(
        signed_in(user),
        "/oauth/start",
        Map.merge(params, %{"login_hint" => "someoneelse", "prompt" => "none"})
      )
      |> callback(params)

    assert query["error"] == "login_required"
  end

  test "inactive sessions cannot silently authorize", %{user: user, params: params} do
    conn = signed_in(user)
    {:ok, _} = Accounts.set_active(user.id, false)
    query = get(conn, "/oauth/start", Map.put(params, "prompt", "none")) |> callback(params)
    assert query["error"] == "login_required"
  end

  test "initiation rejects unvalidated callbacks and missing state", %{params: params} do
    for invalid <- [
          Map.put(params, "redirectURL", "http://127.0.0.1:9999/callback"),
          Map.put(params, "redirectURL", "http://169.254.169.254/callback"),
          Map.put(params, "codeChallenge", "invalid"),
          Map.delete(params, "state")
        ] do
      assert get(build_conn(), "/oauth/start", invalid).status == 400
    end
  end

  test "registration and password-error links retain validated continuation", %{params: params} do
    conn = get(build_conn(), "/oauth/start", Map.put(params, "screen", "register"))
    location = redirected_to(conn)
    assert location =~ "/register?sessionID="
    sid = URI.decode_query(URI.parse(location).query)["sessionID"]
    page = get(build_conn(), location) |> html_response(200)
    assert page =~ ~s(name="sessionID")
    assert page =~ sid

    signup =
      post(build_conn(), "/web/register", %{
        "username" => "continuedsignup",
        "password" => "password123",
        "registration_key" => "test-invitation-key",
        "sessionID" => sid
      })

    assert {:ok, %{active: false}} = Accounts.fetch_user("continuedsignup")
    assert Federated.fetch(sid).username == "continuedsignup"
    assert redirected_to(signup) =~ "sessionID=#{sid}"

    failure =
      post(build_conn(), "/web/login", %{
        username: "continuedsignup",
        password: "wrong",
        sessionID: sid
      })

    assert redirected_to(failure) =~ "sessionID=#{sid}"
    login = get(build_conn(), redirected_to(failure)) |> html_response(200)
    assert login =~ "/register?sessionID="

    {:ok, _} =
      Accounts.set_active(
        Accounts.fetch_user("continuedsignup") |> elem(1) |> Map.fetch!(:id),
        true
      )

    success =
      post(build_conn(), "/web/login", %{
        username: "continuedsignup",
        password: "password123",
        sessionID: sid
      })

    assert redirected_to(success) == "/oauth/consent?sessionID=#{sid}"
  end
end
