defmodule LakehouseWeb.DashboardTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.Apps.{Catalog, Grants}
  alias LakehouseWeb.MatrixFixtures

  defp signed_in(user) do
    token = LakehouseIam.Auth.Token.issue(user.username)
    build_conn() |> init_test_session(user_jwt: token)
  end

  test "dashboard needs authentication and user can only see their own connections" do
    assert redirected_to(get(build_conn(), "/dashboard")) == "/"
    alice = MatrixFixtures.user_fixture("dashalice")
    bob = MatrixFixtures.user_fixture("dashbob")

    {:ok, service} =
      Catalog.create(%{
        name: "Notes",
        home_url: "https://notes.example/",
        login_url: "https://notes.example/auth/start"
      })

    {:ok, _} = Grants.upsert(alice.id, service.origin, ["profile.name"], :selected)
    assert get(signed_in(alice), "/dashboard") |> html_response(200) =~ "Open service"
    assert get(signed_in(bob), "/dashboard") |> html_response(200) =~ "Connect service"
    launch = get(signed_in(alice), "/services/#{service.id}/launch")
    assert redirected_to(launch) == Catalog.launch_url(service, alice.username)
    refute redirected_to(launch) =~ "token"
    assert get(signed_in(alice), "/services/invalid/launch") |> response(404)
  end

  test "deactivated accounts cannot launch services and the sign-in page does not loop" do
    alice = MatrixFixtures.user_fixture("disabledviewer")
    conn = signed_in(alice)
    {:ok, _} = LakehouseIam.Accounts.set_active(alice.id, false)
    assert redirected_to(get(conn, "/dashboard")) == "/"
    assert get(conn, "/") |> html_response(200) =~ "Sign in"

    api_conn =
      build_conn()
      |> put_req_header(
        "authorization",
        "Bearer " <> LakehouseIam.Auth.Token.issue(alice.username)
      )

    assert get(api_conn, "/api/v1/services") |> response(401)
  end

  test "members cannot add or remove shared services, including by direct request" do
    alice = MatrixFixtures.user_fixture("catalogmember")

    {:ok, service} =
      Catalog.create(%{
        name: "Notes",
        home_url: "https://notes.example/",
        login_url: "https://notes.example/auth/start"
      })

    for {method, path, params} <- [
          {:get, "/services/manage", %{}},
          {:post, "/services", %{service: %{name: "Evil"}}},
          {:post, "/services/#{service.id}/delete", %{}}
        ] do
      conn = Phoenix.ConnTest.dispatch(signed_in(alice), @endpoint, method, path, params)
      assert redirected_to(conn) == "/"
    end

    assert Catalog.get(service.id)
    assert Catalog.list() == [service]
  end
end
