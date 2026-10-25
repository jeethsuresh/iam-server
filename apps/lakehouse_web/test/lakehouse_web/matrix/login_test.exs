defmodule LakehouseWeb.Matrix.LoginTest do
  use LakehouseWeb.ConnCase, async: false
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientLogin, ClientStore, Identity}
  alias LakehouseWeb.MatrixFixtures

  setup do
    user = MatrixFixtures.user_fixture("matrixlogin")
    %{user: user}
  end

  defp api(session, method, path, body \\ %{}),
    do:
      build_conn()
      |> put_req_header("authorization", "Bearer " <> session["access_token"])
      |> Phoenix.ConnTest.dispatch(@endpoint, method, path, body)

  defp login(user, params \\ %{}),
    do:
      build_conn()
      |> post(
        "/_matrix/client/v3/login",
        Map.merge(
          %{
            "type" => "m.login.password",
            "identifier" => %{"type" => "m.id.user", "user" => Identity.user_id(user.username)},
            "password" => "password123",
            "device_id" => "FIRST",
            "refresh_token" => true
          },
          params
        )
      )
      |> json_response(200)

  test "logging in again replaces only that device's access and refresh credentials", %{
    user: user
  } do
    first = login(user)
    other = login(user, %{"device_id" => "OTHER"})
    fresh = login(user)
    assert api(first, :get, "/_matrix/client/v3/account/whoami").status == 401

    assert post(build_conn(), "/_matrix/client/v3/refresh", %{
             "refresh_token" => first["refresh_token"]
           }).status == 401

    assert api(other, :get, "/_matrix/client/v3/account/whoami").status == 200
    assert api(fresh, :get, "/_matrix/client/v3/account/whoami").status == 200
  end

  test "expired access tokens soft log out, refresh responses can be retried and logout revokes refresh",
       %{user: user} do
    session = login(user)

    assert session["expires_in_ms"] == 3_600_000 and
             String.starts_with?(session["refresh_token"], "mrt_")

    digest = ClientStore.hash(session["access_token"])

    Repo.update_all(from(s in "matrix_sessions", where: s.token_hash == ^digest),
      set: [expires_at: DateTime.add(ClientStore.now(), -1, :second)]
    )

    assert api(session, :get, "/_matrix/client/v3/account/whoami")
           |> json_response(401)
           |> Map.fetch!("soft_logout")

    fresh =
      post(build_conn(), "/_matrix/client/v3/refresh", %{
        "refresh_token" => session["refresh_token"]
      })

    assert get_resp_header(fresh, "cache-control") == ["no-store"]
    first = json_response(fresh, 200)
    refute Map.has_key?(first, "refresh_token")

    retry =
      post(build_conn(), "/_matrix/client/v3/refresh", %{
        "refresh_token" => session["refresh_token"]
      })
      |> json_response(200)

    refute first["access_token"] == retry["access_token"]
    assert api(first, :get, "/_matrix/client/v3/account/whoami").status == 401

    assert api(retry, :get, "/_matrix/client/v3/account/whoami")
           |> json_response(200)
           |> Map.fetch!("device_id") == "FIRST"

    assert get(build_conn(), "/_matrix/client/v3/account/whoami", %{
             "access_token" => retry["access_token"]
           }).status == 200

    assert api(retry, :post, "/_matrix/client/v3/logout").status == 200

    assert post(build_conn(), "/_matrix/client/v3/refresh", %{
             "refresh_token" => session["refresh_token"]
           })
           |> json_response(401)
           |> Map.fetch!("errcode") == "M_UNKNOWN_TOKEN"

    assert :error == ClientStore.authenticate(retry["access_token"])
  end

  test "one-use tokens require fresh exact-request UIA, expire, retain rate limiting after redemption and never widen grants",
       %{user: user} do
    session = login(user)

    {:ok, grant} =
      LakehouseIam.Apps.Grants.upsert(
        user.id,
        "https://river.example",
        ["chats.read"],
        :selected,
        []
      )

    challenge = api(session, :post, "/_matrix/client/v1/login/get_token") |> json_response(401)

    auth = %{
      "type" => "m.login.password",
      "session" => challenge["session"],
      "user" => user.username,
      "password" => "password123"
    }

    generated =
      api(session, :post, "/_matrix/client/v1/login/get_token", %{"auth" => auth})
      |> json_response(200)

    assert generated["expires_in_ms"] == 120_000

    params = %{
      "type" => "m.login.token",
      "token" => generated["login_token"],
      "device_id" => "SECOND"
    }

    second = post(build_conn(), "/_matrix/client/v3/login", params) |> json_response(200)
    assert second["user_id"] == session["user_id"] and second["device_id"] == "SECOND"
    assert post(build_conn(), "/_matrix/client/v3/login", params).status == 403

    assert api(session, :post, "/_matrix/client/v1/login/get_token", %{"auth" => auth}).status ==
             401

    challenge = api(session, :post, "/_matrix/client/v1/login/get_token") |> json_response(401)
    auth = Map.put(auth, "session", challenge["session"])

    assert api(session, :post, "/_matrix/client/v1/login/get_token", %{"auth" => auth}).status ==
             429

    assert Repo.get!(LakehouseIam.Schema.AppGrant, grant.id).room_ids == []

    {:ok, expired} = ClientLogin.generate(user.id, false)
    digest = ClientStore.hash(expired["login_token"])

    Repo.update_all(from(t in "matrix_login_tokens", where: t.token_hash == ^digest),
      set: [expires_at: DateTime.add(ClientStore.now(), -1, :second)]
    )

    assert {:error, :invalid_credentials} == ClientLogin.redeem(expired["login_token"], %{})
    {:ok, revoked} = ClientLogin.generate(user.id, false, "FIRST")
    assert api(session, :post, "/_matrix/client/v3/logout").status == 200
    assert {:error, :invalid_credentials} == ClientLogin.redeem(revoked["login_token"], %{})
  end

  test "invalid token-login device parameters do not consume a login token and inactive users cannot refresh",
       %{user: user} do
    {:ok, token} = ClientLogin.generate(user.id, false)

    assert {:error, :invalid_param} ==
             ClientLogin.redeem(token["login_token"], %{"device_id" => []})

    assert {:ok, _} = ClientLogin.redeem(token["login_token"], %{"device_id" => "VALID"})
    session = login(user)
    user |> Ecto.Changeset.change(active: false) |> Repo.update!()
    assert {:error, :unknown_token} == ClientLogin.refresh(session["refresh_token"])
    assert :error == ClientStore.authenticate(session["access_token"])
  end

  test "SSO requires browser-bound explicit consent, preserves callback state and issues only one usable token",
       %{user: user} do
    browser =
      build_conn() |> init_test_session(user_jwt: MatrixFixtures.browser_token(user.username))

    callback = "https://matrix.example/callback?state=a&state=b&loginToken=old#section"

    started =
      get(browser, "/_matrix/client/v3/login/sso/redirect/gravitas", %{"redirectUrl" => callback})

    assert redirected_to(started) == "/matrix/sso/consent"
    assert Repo.aggregate(from(s in "matrix_sessions"), :count) == 0
    page = started |> recycle() |> get("/matrix/sso/consent")
    assert html_response(page, 200) =~ "Allow full Matrix access"
    assert html_response(page, 200) =~ "current and future rooms"
    assert get_resp_header(page, "referrer-policy") == ["no-referrer"]
    assert get_resp_header(page, "cache-control") == ["no-store"]

    unrelated =
      build_conn()
      |> init_test_session(user_jwt: MatrixFixtures.browser_token(user.username))
      |> get("/matrix/sso/consent")

    assert unrelated.status == 400
    csrf = Phoenix.Controller.get_csrf_token()

    approved =
      page |> post("/matrix/sso/consent", %{"decision" => "allow", "_csrf_token" => csrf})

    url = URI.parse(redirected_to(approved))
    assert url.host == "matrix.example" and url.fragment == "section"
    query = URI.query_decoder(url.query) |> Enum.to_list()
    assert [{"state", "a"}, {"state", "b"}, {"loginToken", token}] = query
    assert {:ok, _} = ClientLogin.redeem(token, %{})
    assert {:error, :invalid_credentials} == ClientLogin.redeem(token, %{})
    assert approved |> recycle() |> get("/matrix/sso/consent") |> html_response(400)
  end

  test "SSO starts remember only local navigation and reject executable, insecure and unknown callbacks",
       %{user: user} do
    started =
      get(build_conn(), "/_matrix/client/v3/login/sso/redirect", %{
        "redirectUrl" => "https://matrix.example/cb"
      })

    auth = started |> recycle() |> get("/matrix/sso/consent")
    assert redirected_to(auth) == "/"
    assert get_session(auth, :return_to) == "/matrix/sso/consent"
    login_page = auth |> recycle() |> get("/")
    assert html_response(login_page, 200)

    signed_in =
      post(login_page, "/web/login", %{
        "username" => user.username,
        "password" => "password123",
        "_csrf_token" => Phoenix.Controller.get_csrf_token()
      })

    assert redirected_to(signed_in) == "/matrix/sso/consent"

    assert signed_in |> recycle() |> get("/matrix/sso/consent") |> html_response(200) =~
             "Allow full Matrix access"

    for callback <- [
          "javascript:alert(1)",
          "data:text/html,test",
          "http://matrix.example/cb",
          "https://user:pass@matrix.example/cb",
          "https://matrix.example/\r\ntest",
          nil
        ] do
      assert get(build_conn(), "/_matrix/client/v3/login/sso/redirect", %{
               "redirectUrl" => callback
             }).status == 400
    end

    assert get(build_conn(), "/_matrix/client/v3/login/sso/redirect/unknown", %{
             "redirectUrl" => "https://matrix.example/cb"
           }).status == 404
  end
end
