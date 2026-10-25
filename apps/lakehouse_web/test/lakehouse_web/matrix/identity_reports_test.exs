defmodule LakehouseWeb.Matrix.IdentityReportsTest do
  use LakehouseWeb.ConnCase, async: false
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, Identity}
  alias LakehouseWeb.MatrixFixtures

  setup do
    keys = [:native_event_graph, :signing_key, :signing_key_id]
    old = Map.new(keys, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :native_event_graph, true)

    Application.put_env(
      :lakehouse_matrix,
      :signing_key,
      Base.encode64(<<0::256>>, padding: false)
    )

    Application.put_env(:lakehouse_matrix, :signing_key_id, "ed25519:test")

    on_exit(fn ->
      for {key, value} <- old do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    alice = MatrixFixtures.user_fixture("identityalice")
    bob = MatrixFixtures.user_fixture("identitybob")
    {:ok, a} = ClientStore.login(alice.username, "password123", %{"device_id" => "A"})
    {:ok, b} = ClientStore.login(bob.username, "password123", %{"device_id" => "B"})
    %{alice: alice, bob: bob, a: a, b: b}
  end

  defp api(session, method, path, body \\ %{}),
    do:
      build_conn()
      |> put_req_header("authorization", "Bearer " <> session["access_token"])
      |> Phoenix.ConnTest.dispatch(@endpoint, method, path, body)

  test "OpenID attestations are private to their owner, expire and cannot authenticate Matrix clients",
       ctx do
    response =
      api(ctx.a, :post, "/_matrix/client/v3/user/#{ctx.a["user_id"]}/openid/request_token")

    assert get_resp_header(response, "cache-control") == ["no-store"]
    token = json_response(response, 200)
    assert token["expires_in"] == 3600 and token["token_type"] == "Bearer"
    assert token["matrix_server_name"] == Identity.homeserver_domain()
    path = "/_matrix/federation/v1/openid/userinfo?access_token=" <> token["access_token"]
    assert get(build_conn(), path) |> json_response(200) == %{"sub" => ctx.a["user_id"]}

    assert api(ctx.b, :post, "/_matrix/client/v3/user/#{ctx.a["user_id"]}/openid/request_token").status ==
             403

    assert api(token, :get, "/_matrix/client/v3/account/whoami").status == 401

    assert get(
             build_conn(),
             "/_matrix/federation/v1/openid/userinfo?access_token=" <> ctx.a["access_token"]
           ).status == 401

    digest = ClientStore.hash(token["access_token"])
    assert Repo.one(from t in "matrix_openid_tokens", select: t.token_hash) == digest

    Repo.update_all(from(t in "matrix_openid_tokens", where: t.token_hash == ^digest),
      set: [expires_at: DateTime.add(ClientStore.now(), -1, :second)]
    )

    assert get(build_conn(), path) |> json_response(401) |> Map.fetch!("errcode") ==
             "M_UNKNOWN_TOKEN"

    fresh =
      api(ctx.a, :post, "/_matrix/client/v3/user/#{ctx.a["user_id"]}/openid/request_token")
      |> json_response(200)

    ctx.alice |> Ecto.Changeset.change(active: false) |> Repo.update!()

    assert get(
             build_conn(),
             "/_matrix/federation/v1/openid/userinfo?access_token=" <> fresh["access_token"]
           ).status == 401
  end

  test "reports retain legitimate evidence references and conceal inaccessible events without trusting body routing keys",
       ctx do
    room =
      api(ctx.a, :post, "/_matrix/client/v3/createRoom", %{"name" => "Private"})
      |> json_response(200)
      |> Map.fetch!("room_id")

    sent =
      api(ctx.a, :put, "/_matrix/client/v3/rooms/#{room}/send/m.room.message/one", %{
        "body" => "private"
      })
      |> json_response(200)

    path = "/_matrix/client/v3/rooms/#{room}/report/#{sent["event_id"]}"
    assert api(ctx.b, :post, path, %{"reason" => "cannot see"}).status == 200
    refute Repo.exists?(from(r in "matrix_reports"))
    assert api(ctx.a, :post, path, %{"score" => -999}).status == 200

    assert api(ctx.b, :post, "/_matrix/client/v3/rooms/#{room}/report", %{
             "reason" => "",
             "eventId" => "$spoof"
           }).status == 200

    assert api(ctx.b, :post, "/_matrix/client/v3/users/@unknown:remote.example/report", %{
             "reason" => "spam",
             "roomId" => room
           }).status == 200

    reports =
      Repo.all(
        from r in "matrix_reports", select: {r.kind, r.reason, r.room_ref, r.event_id, r.user_id}
      )

    assert {"event", "", room, sent["event_id"], nil} in reports
    assert {"room", "", room, nil, nil} in reports
    assert {"user", "spam", nil, nil, "@unknown:remote.example"} in reports
    assert api(ctx.b, :post, "/_matrix/client/v3/rooms/#{room}/report", %{}).status == 400
  end

  test "reports limit storage and rate without requiring membership for room/user reports", ctx do
    ref = "!" <> String.duplicate("a", 43)
    path = "/_matrix/client/v3/rooms/#{ref}/report"
    assert api(ctx.b, :post, path, %{"reason" => String.duplicate("a", 16_385)}).status == 413
    for _ <- 1..10, do: assert(api(ctx.b, :post, path, %{"reason" => "report"}).status == 200)
    limited = api(ctx.b, :post, path, %{"reason" => "report"})
    assert json_response(limited, 429)["errcode"] == "M_LIMIT_EXCEEDED"
    assert get_resp_header(limited, "retry-after") == ["60"]
    assert Repo.aggregate("matrix_reports", :count) == 10
  end
end
