defmodule LakehouseWeb.LoginTest do
  use LakehouseWeb.ConnCase

  alias LakehouseIam.{Accounts, Auth.Token}

  setup do
    previous = Application.get_env(:lakehouse_iam, :identity_domain)
    Application.put_env(:lakehouse_iam, :identity_domain, "example.com")
    on_exit(fn -> Application.put_env(:lakehouse_iam, :identity_domain, previous) end)
    :ok
  end

  test "sign-in explains the local domain and preserves full-address sign-in" do
    page = build_conn() |> get("/") |> html_response(200)
    assert page =~ ~s(placeholder="user")
    assert page =~ ~s(aria-describedby="username-help")
    assert page =~ "A username without a domain signs in to"
    assert page =~ "example.com"
    assert page =~ "@user:example.com"
  end

  test "bare and fully qualified API logins authenticate the same local account" do
    assert {:ok, _} = Accounts.register_user("localuser", "password123", approve: true)

    for username <- ["localuser", "@localuser:example.com"] do
      response =
        build_conn()
        |> post("/login", %{username: username, password: "password123"})
        |> json_response(200)

      assert {:ok, %{"username" => "localuser"}} = Token.verify(response["token"])
    end

    conn =
      post(build_conn(), "/login", %{
        username: "@localuser:other.example",
        password: "password123"
      })

    assert response(conn, 400)
  end
end
