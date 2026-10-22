defmodule LakehouseWeb.SingleLogoutTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.{Auth.Token, Apps.Grants, Apps.Pkce}
  alias LakehouseWeb.{MatrixFixtures, Test.Api.OAuthClient}

  setup do
    old = Application.get_env(:lakehouse_iam, :relaxed_callback_urls)
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)
    on_exit(fn -> Application.put_env(:lakehouse_iam, :relaxed_callback_urls, old) end)
    user = MatrixFixtures.user_fixture("singlelogout")
    %{user: user}
  end

  defp login do
    post(build_conn(), "/web/login", %{username: "singlelogout", password: "password123"})
  end

  defp start(conn, user, origin) do
    {:ok, _} = Grants.upsert(user.id, origin, ["profile.name"], :all, [])
    verifier = Pkce.generate_verifier()
    callback = origin <> "/callback"

    conn =
      conn
      |> recycle()
      |> get("/oauth/start", %{
        callerURL: origin,
        redirectURL: callback,
        codeChallenge: Pkce.challenge(verifier),
        scope: "profile.name",
        state: "independent-state",
        prompt: "none"
      })

    query = conn |> redirected_to() |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["code"] && query["state"] == "independent-state"

    {conn,
     %{
       grant_type: "authorization_code",
       code: query["code"],
       code_verifier: verifier,
       redirect_uri: callback
     }}
  end

  defp proof_status(token) do
    build_conn() |> put_req_header("authorization", "Bearer " <> token) |> get("/oauth/session")
  end

  test "one browser logout revokes all its apps while leaving consent and other devices", %{
    user: user
  } do
    {first, code1} = start(login(), user, "http://127.0.0.1:4102")
    {first, code2} = start(first, user, "http://127.0.0.1:4103")
    {other, code3} = start(login(), user, "http://127.0.0.1:4102")

    [a, b, independent] =
      Enum.map([code1, code2, code3], &(OAuthClient.token(&1) |> json_response(200)))

    for pair <- [a, b, independent],
        do: assert(json_response(proof_status(pair["session_check_token"]), 200)["active"])

    assert a["session_id"] == b["session_id"]
    refute a["session_id"] == independent["session_id"]
    assert redirected_to(first |> recycle() |> post("/web/logout")) == "/"

    for pair <- [a, b] do
      assert json_response(proof_status(pair["session_check_token"]), 401)["active"] == false
      assert OAuthClient.me(pair["access_token"]).status == 401

      assert OAuthClient.token(%{
               grant_type: "refresh_token",
               refresh_token: pair["refresh_token"]
             }).status == 400
    end

    assert json_response(proof_status(independent["session_check_token"]), 200)["active"]
    assert {:ok, _} = Token.verify(get_session(other, :user_jwt))
    assert length(Grants.list_for_principal(user.id)) == 2
  end

  test "codes issued before logout cannot create fresh app sessions afterward", %{user: user} do
    {conn, code} = start(login(), user, "http://127.0.0.1:4102")
    conn |> recycle() |> post("/web/logout")
    assert json_response(OAuthClient.token(code), 400)["error"] == "invalid_grant"
  end

  test "GET logout cannot revoke a session and POST logout is CSRF-protected" do
    conn = login()
    jwt = get_session(conn, :user_jwt)
    page = conn |> recycle() |> get("/logout")
    assert html_response(page, 200) =~ "connected services in this browser"
    assert {:ok, _} = Token.verify(jwt)

    assert_raise Plug.CSRFProtection.InvalidCSRFTokenError, fn ->
      page
      |> recycle()
      |> put_private(:plug_skip_csrf_protection, false)
      |> post("/web/logout", %{})
    end

    assert {:ok, _} = Token.verify(jwt)
  end

  test "proof is unavailable to bearer data tokens or query strings", %{user: user} do
    {_conn, code} = start(login(), user, "http://127.0.0.1:4102")
    pair = OAuthClient.token(code) |> json_response(200)

    for raw <- [pair["access_token"], pair["refresh_token"], "invalid"] do
      rejected = proof_status(raw)
      assert json_response(rejected, 401)["active"] == false
      assert get_resp_header(rejected, "cache-control") == ["no-store"]
    end

    assert get(build_conn(), "/oauth/session?session_check_token=" <> pair["session_check_token"]).status ==
             401

    assert OAuthClient.me(pair["session_check_token"]).status == 401
  end

  test "password entry during federated login binds the completed code to the installed browser family",
       %{user: user} do
    origin = "http://127.0.0.1:4102"
    {:ok, _} = Grants.upsert(user.id, origin, ["profile.name"], :all, [])
    verifier = Pkce.generate_verifier()

    reg =
      OAuthClient.backend_register(%{
        username: user.username,
        callerURL: origin,
        redirectURL: origin <> "/callback",
        codeChallenge: Pkce.challenge(verifier),
        scope: "profile.name"
      })
      |> json_response(200)

    conn =
      post(build_conn(), "/web/login", %{
        username: user.username,
        password: "password123",
        sessionID: reg["sessionID"]
      })

    code =
      conn
      |> redirected_to()
      |> URI.parse()
      |> Map.fetch!(:query)
      |> URI.decode_query()
      |> Map.fetch!("code")

    pair =
      OAuthClient.token(%{
        grant_type: "authorization_code",
        code: code,
        code_verifier: verifier,
        redirect_uri: origin <> "/callback"
      })
      |> json_response(200)

    {:ok, claims} = Token.verify(get_session(conn, :user_jwt))
    assert pair["session_id"] == claims["sid"]
    assert proof_status(pair["session_check_token"]).status == 200
    conn |> recycle() |> post("/web/logout")
    assert proof_status(pair["session_check_token"]).status == 401
  end
end
