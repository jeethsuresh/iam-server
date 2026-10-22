defmodule LakehouseWeb.OAuthPkceTest do
  use LakehouseWeb.ConnCase

  alias LakehouseIam.Apps.Pkce
  alias LakehouseMatrix.Matrix
  alias LakehouseWeb.MatrixFixtures
  alias LakehouseWeb.Test.Api.OAuthClient

  setup do
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)
    LakehouseIam.Federated.reset!()
    user = MatrixFixtures.user_fixture("oauthuser")
    assert {:ok, _} = Matrix.create_room(user.id, %{"name" => "OAuth Room"})
    [room | _] = LakehouseMatrix.Memberships.list_joined_rooms(user.id)
    {:ok, user: user, room: room}
  end

  test "full PKCE code flow and app API", %{user: user, room: room} do
    verifier = Pkce.generate_verifier()
    challenge = Pkce.challenge(verifier)
    redirect = "http://127.0.0.1:4102/oauth/callback"
    caller = "http://127.0.0.1:4102/"

    reg =
      OAuthClient.backend_register(%{
        "username" => LakehouseIam.Identifier.format(user.username),
        "callerURL" => caller,
        "redirectURL" => redirect,
        "codeChallenge" => challenge,
        "codeChallengeMethod" => "S256",
        "scope" => "profile.name chats.list chats.read chats.write",
        "state" => "st1"
      })

    body = json_response(reg, 200)
    assert %{"sessionID" => sid, "username" => "oauthuser"} = body
    assert body["userID"] == LakehouseIam.Identifier.format("oauthuser")
    refute Map.has_key?(body, "publicKey")

    code = consent_code(user.username, sid, %{"all_rooms" => "true"})

    tok =
      OAuthClient.token(%{
        "grant_type" => "authorization_code",
        "code" => code,
        "code_verifier" => verifier,
        "redirect_uri" => redirect
      })

    assert %{"access_token" => access, "refresh_token" => _} = json_response(tok, 200)

    me = OAuthClient.me(access)
    assert %{"username" => "oauthuser", "name" => "oauthuser"} = json_response(me, 200)
    assert json_response(me, 200)["user_id"] == LakehouseIam.Identifier.format("oauthuser")

    chats = OAuthClient.chats(access)
    assert %{"chats" => chats_list} = json_response(chats, 200)
    assert Enum.any?(chats_list, &(&1["id"] == room.id))

    write = OAuthClient.create_event(access, room.id, "hello from app")
    assert write.status == 200

    events = OAuthClient.list_events(access, room.id)
    assert %{"events" => evs} = json_response(events, 200)
    assert Enum.any?(evs, fn e -> get_in(e, ["content", "body"]) == "hello from app" end)
  end

  test "wrong verifier is rejected", %{user: user} do
    verifier = Pkce.generate_verifier()
    challenge = Pkce.challenge(verifier)
    redirect = "http://127.0.0.1:4102/oauth/callback"

    reg =
      OAuthClient.backend_register(%{
        "username" => user.username,
        "callerURL" => "http://127.0.0.1:4102/",
        "redirectURL" => redirect,
        "codeChallenge" => challenge,
        "codeChallengeMethod" => "S256",
        "scope" => "profile.name"
      })

    sid = json_response(reg, 200)["sessionID"]
    code = consent_code(user.username, sid, %{"all_rooms" => "true"})

    tok =
      OAuthClient.token(%{
        "grant_type" => "authorization_code",
        "code" => code,
        "code_verifier" => "totally-wrong-verifier-value-xxxx",
        "redirect_uri" => redirect
      })

    assert tok.status == 400
  end

  test "another application reuses the IAM browser login and asks for consent", %{user: user} do
    reg =
      OAuthClient.backend_register(%{
        "username" => LakehouseIam.Identifier.format(user.username),
        "callerURL" => "http://127.0.0.1:4103/",
        "redirectURL" => "http://127.0.0.1:4103/callback",
        "codeChallenge" => Pkce.challenge(Pkce.generate_verifier()),
        "scope" => "profile.name"
      })

    sid = json_response(reg, 200)["sessionID"]

    conn =
      build_conn()
      |> Plug.Test.init_test_session(%{user_jwt: MatrixFixtures.browser_token(user.username)})
      |> get("/oauth/authorize", sessionID: sid)

    assert redirected_to(conn, 302) == "/oauth/consent?sessionID=#{sid}"
  end

  test "cross-origin register rejected" do
    v = Pkce.generate_verifier()

    reg =
      OAuthClient.backend_register(%{
        "username" => "x",
        "callerURL" => "http://127.0.0.1:4102/",
        "redirectURL" => "http://127.0.0.1:9999/cb",
        "codeChallenge" => Pkce.challenge(v),
        "codeChallengeMethod" => "S256",
        "scope" => "profile.name"
      })

    assert reg.status == 400
  end

  test "missing scope returns 403", %{user: user} do
    verifier = Pkce.generate_verifier()
    redirect = "http://127.0.0.1:4102/oauth/callback"

    reg =
      OAuthClient.backend_register(%{
        "username" => user.username,
        "callerURL" => "http://127.0.0.1:4102/",
        "redirectURL" => redirect,
        "codeChallenge" => Pkce.challenge(verifier),
        "codeChallengeMethod" => "S256",
        "scope" => "profile.name"
      })

    sid = json_response(reg, 200)["sessionID"]
    code = consent_code(user.username, sid, %{})

    access =
      json_response(
        OAuthClient.token(%{
          "grant_type" => "authorization_code",
          "code" => code,
          "code_verifier" => verifier,
          "redirect_uri" => redirect
        }),
        200
      )["access_token"]

    assert OAuthClient.chats(access).status == 403
  end

  test "revoke invalidates tokens", %{user: user} do
    verifier = Pkce.generate_verifier()
    redirect = "http://127.0.0.1:4102/oauth/callback"
    origin = "http://127.0.0.1:4102"

    reg =
      OAuthClient.backend_register(%{
        "username" => user.username,
        "callerURL" => origin <> "/",
        "redirectURL" => redirect,
        "codeChallenge" => Pkce.challenge(verifier),
        "codeChallengeMethod" => "S256",
        "scope" => "profile.name"
      })

    sid = json_response(reg, 200)["sessionID"]
    code = consent_code(user.username, sid, %{})

    access =
      json_response(
        OAuthClient.token(%{
          "grant_type" => "authorization_code",
          "code" => code,
          "code_verifier" => verifier,
          "redirect_uri" => redirect
        }),
        200
      )["access_token"]

    assert :ok = LakehouseIam.Apps.Tokens.revoke_app(user.id, origin)
    assert OAuthClient.me(access).status == 401
  end

  defp consent_code(username, sid, extra) do
    jwt = MatrixFixtures.browser_token(username)

    conn =
      build_conn()
      |> Plug.Test.init_test_session(%{user_jwt: jwt})
      |> get("/oauth/consent", %{"sessionID" => sid})

    assert html_response(conn, 200) =~ "Authorize application"
    csrf = Phoenix.Controller.get_csrf_token()

    consent =
      conn
      |> post(
        "/oauth/consent",
        Map.merge(%{"sessionID" => sid, "_csrf_token" => csrf}, extra)
      )

    assert redirected_to(consent, 302) =~ "code="
    URI.decode_query(URI.parse(redirected_to(consent, 302)).query)["code"]
  end
end
