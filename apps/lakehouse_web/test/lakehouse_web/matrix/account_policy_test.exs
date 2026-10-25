defmodule LakehouseWeb.Matrix.AccountPolicyTest do
  use LakehouseWeb.ConnCase, async: false
  alias LakehouseWeb.MatrixFixtures
  alias LakehouseMatrix.Turn

  setup do
    user = MatrixFixtures.user_fixture("policyuser")

    session =
      build_conn()
      |> post("/_matrix/client/v3/login", %{
        "type" => "m.login.password",
        "user" => user.username,
        "password" => "password123"
      })
      |> json_response(200)

    old = Application.get_env(:lakehouse_matrix, :turn)
    Application.delete_env(:lakehouse_matrix, :turn)

    on_exit(fn ->
      if old,
        do: Application.put_env(:lakehouse_matrix, :turn, old),
        else: Application.delete_env(:lakehouse_matrix, :turn)
    end)

    %{session: session, user: user}
  end

  defp api(session, method, path, body \\ %{}) do
    conn = build_conn() |> put_req_header("authorization", "Bearer " <> session["access_token"])
    Phoenix.ConnTest.dispatch(conn, @endpoint, method, "/_matrix/client" <> path, body)
  end

  test "Matrix registration and recovery cannot bypass IAM approval or claimed capabilities",
       ctx do
    for path <- [
          "/v3/register",
          "/v3/register/email/requestToken",
          "/v3/register/msisdn/requestToken",
          "/v3/account/password/email/requestToken",
          "/v3/account/password/msisdn/requestToken"
        ] do
      assert post(build_conn(), "/_matrix/client" <> path, %{})
             |> json_response(403)
             |> Map.fetch!("errcode") == "M_FORBIDDEN"
    end

    for path <- [
          "/v3/register/available?username=policytest",
          "/v1/register/m.login.registration_token/validity?token=guess"
        ] do
      assert get(build_conn(), "/_matrix/client" <> path)
             |> json_response(403)
             |> Map.fetch!("errcode") == "M_FORBIDDEN"
    end

    assert api(ctx.session, :get, "/v3/account/3pid") |> json_response(200) == %{
             "threepids" => []
           }

    for path <- [
          "/v3/account/3pid",
          "/v3/account/3pid/add",
          "/v3/account/3pid/bind",
          "/v3/account/3pid/unbind",
          "/v3/account/3pid/delete",
          "/v3/account/3pid/email/requestToken",
          "/v3/account/3pid/msisdn/requestToken"
        ] do
      assert api(ctx.session, :post, path) |> json_response(403) |> Map.fetch!("errcode") ==
               "M_THREEPID_DENIED"
    end

    assert api(ctx.session, :post, "/v3/account/password", %{"new_password" => "ignored"}).status ==
             403

    assert LakehouseIam.Accounts.password_valid?(ctx.user.username, "password123")
    capabilities = api(ctx.session, :get, "/v3/capabilities") |> json_response(200)
    refute capabilities["capabilities"]["m.change_password"]["enabled"]
    refute capabilities["capabilities"]["m.3pid_changes"]["enabled"]
    assert get(build_conn(), "/_matrix/client/v3/account/3pid").status == 401
  end

  test "no configured third-party networks produce an empty inventory and unknown lookups", ctx do
    assert api(ctx.session, :get, "/v3/thirdparty/protocols") |> json_response(200) == %{}

    for path <- [
          "/v3/thirdparty/protocol/unknown",
          "/v3/thirdparty/user/unknown",
          "/v3/thirdparty/location/unknown",
          "/v3/thirdparty/user?userid=%40alice%3Alocalhost",
          "/v3/thirdparty/location?alias=%23portal%3Alocalhost"
        ] do
      assert api(ctx.session, :get, path) |> json_response(404) |> Map.fetch!("errcode") ==
               "M_NOT_FOUND"
    end
  end

  test "runtime TURN configuration validates before application startup" do
    keys = ~w(MATRIX_TURN_URIS MATRIX_TURN_SHARED_SECRET MATRIX_TURN_TTL)
    old = Map.new(keys, &{&1, System.get_env(&1)})

    on_exit(fn ->
      for {key, value} <- old do
        if value, do: System.put_env(key, value), else: System.delete_env(key)
      end
    end)

    System.put_env("MATRIX_TURN_URIS", "turn:turn.example.org:3478?transport=udp")
    System.put_env("MATRIX_TURN_SHARED_SECRET", String.duplicate("a", 32))
    System.put_env("MATRIX_TURN_TTL", "3600")
    path = Path.expand("../../../../../config/runtime.exs", __DIR__)
    config = Config.Reader.read!(path, env: :test, target: :host)
    assert config[:lakehouse_matrix][:turn].ttl == 3600
    System.put_env("MATRIX_TURN_URIS", "https://not-a-turn-server.example")

    assert_raise RuntimeError, "Invalid Matrix TURN configuration", fn ->
      Config.Reader.read!(path, env: :test, target: :host)
    end
  end

  test "TURN credentials are optional, expiring, user-bound and never expose the shared secret",
       ctx do
    assert api(ctx.session, :get, "/v3/voip/turnServer").status == 404

    config = %{
      uris: ["turn:turn.example.org:3478?transport=udp", "turns:[2001:db8::1]:443?transport=tcp"],
      secret: String.duplicate("a", 32),
      ttl: 3600
    }

    assert Turn.valid_config?(config)
    Application.put_env(:lakehouse_matrix, :turn, config)

    assert {:ok,
            %{
              "username" => "1700003600:@alice:localhost",
              "password" => "/DiqlmZMnMBEEnAPBIDUkMsQ98c="
            }} = Turn.credentials("alice", 1_700_000_000)

    response = api(ctx.session, :get, "/v3/voip/turnServer")
    body = json_response(response, 200)
    assert body["uris"] == config.uris and body["ttl"] == 3600
    assert String.ends_with?(body["username"], ":@policyuser:localhost")
    refute response.resp_body =~ config.secret
    assert get_resp_header(response, "cache-control") == ["no-store"]

    for uri <- [
          "https://turn.example.org",
          "turn://user:pass@host",
          "turn:host/private",
          "turn:host#fragment",
          "turn:host?transport=other",
          "turn:host:70000"
        ] do
      refute Turn.valid_config?(%{config | uris: [uri]})
    end

    refute Turn.valid_config?(%{config | ttl: 0})
    refute Turn.valid_config?(%{config | secret: "short"})
    assert get(build_conn(), "/_matrix/client/v3/voip/turnServer").status == 401
  end
end
