defmodule LakehouseWeb.SessionReturnTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.Auth.Token
  alias LakehouseIam.Apps.Catalog
  alias LakehouseWeb.MatrixFixtures

  defp expired_token(username) do
    previous = Application.fetch_env!(:lakehouse_iam, :token_ttl_seconds)
    Application.put_env(:lakehouse_iam, :token_ttl_seconds, -1)

    try do
      Token.issue(username)
    after
      Application.put_env(:lakehouse_iam, :token_ttl_seconds, previous)
    end
  end

  test "expired browser sessions clear stale credentials and retain the requested local page" do
    user = MatrixFixtures.user_fixture("expiredreturn")

    conn =
      build_conn()
      |> init_test_session(user_jwt: expired_token(user.username))
      |> get("/groups?view=joined")

    assert redirected_to(conn) == "/"
    assert get_session(conn, :user_jwt) == nil
    assert get_session(conn, :return_to) == "/groups?view=joined"
    page = conn |> recycle() |> get("/") |> html_response(200)
    assert page =~ "Please sign in again to continue."
    refute page =~ "Invalid token"
  end

  test "a successful browser login consumes the original destination once" do
    user = MatrixFixtures.user_fixture("resumereturn")
    conn = get(build_conn(), "/settings")
    assert get_session(conn, :return_to) == "/settings"

    conn =
      conn |> recycle() |> post("/web/login", %{username: user.username, password: "password123"})

    assert redirected_to(conn) == "/settings"
    refute get_session(conn, :return_to)
    assert Token.verify(get_session(conn, :user_jwt)) |> elem(0) == :ok

    conn =
      conn |> recycle() |> post("/web/login", %{username: user.username, password: "password123"})

    assert redirected_to(conn) == "/dashboard"
  end

  test "opening the home page also discards an expired browser credential" do
    user = MatrixFixtures.user_fixture("homeexpiry")
    conn = build_conn() |> init_test_session(user_jwt: expired_token(user.username)) |> get("/")
    assert html_response(conn, 200) =~ "Please sign in again to continue."
    refute get_session(conn, :user_jwt)
  end

  test "failed login keeps the pending destination without issuing credentials" do
    user = MatrixFixtures.user_fixture("retryreturn")

    conn =
      build_conn()
      |> get("/groups")
      |> recycle()
      |> post("/web/login", %{username: user.username, password: "wrong"})

    assert redirected_to(conn) =~ "/?username="
    assert get_session(conn, :return_to) == "/groups"
    refute get_session(conn, :user_jwt)
  end

  test "a service launch resumes through its own app login after signing in" do
    user = MatrixFixtures.user_fixture("launchreturn")

    {:ok, service} =
      Catalog.create(%{
        name: "Notes",
        home_url: "https://notes.example/",
        login_url: "https://notes.example/auth/start"
      })

    path = "/services/#{service.id}/launch"

    conn =
      get(build_conn(), path)
      |> recycle()
      |> post("/web/login", %{username: user.username, password: "password123"})

    assert redirected_to(conn) == path
    conn = conn |> recycle() |> get(path)
    assert redirected_to(conn) == Catalog.launch_url(service, user.username)
  end

  test "external, malformed and action destinations cannot be restored from session data" do
    user = MatrixFixtures.user_fixture("safereturn")

    for target <- [
          "https://evil.example",
          "//evil.example",
          "/\\evil.example",
          "/%2f%2fevil.example",
          "/logout",
          "/web/admin/approve",
          "/groups/../logout",
          "/settings\r\nLocation: https://evil.example"
        ] do
      conn =
        build_conn()
        |> init_test_session(return_to: target)
        |> post("/web/login", %{username: user.username, password: "password123"})

      assert redirected_to(conn) == "/dashboard"
      refute get_session(conn, :return_to)
    end
  end

  test "expired API tokens still receive 401 without redirects" do
    user = MatrixFixtures.user_fixture("apiExpiry")

    conn =
      build_conn()
      |> put_req_header("authorization", "Bearer " <> expired_token(user.username))
      |> get("/api/v1/services")

    assert json_response(conn, 401) == "Invalid token"
    assert get_resp_header(conn, "location") == []
  end

  test "unauthenticated mutations are not replayed after login" do
    conn =
      build_conn()
      |> init_test_session(return_to: "/settings")
      |> post("/services", %{service: %{name: "Unexpected"}})

    assert redirected_to(conn) == "/"
    refute get_session(conn, :return_to)
    assert Catalog.list() == []
  end

  test "oversized destination queries cannot overflow the browser session cookie" do
    conn = get(build_conn(), "/groups?filter=" <> String.duplicate("a", 5000))
    assert redirected_to(conn) == "/"
    refute get_session(conn, :return_to)
  end
end
