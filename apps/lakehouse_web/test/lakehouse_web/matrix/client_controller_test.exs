defmodule LakehouseWeb.Matrix.ClientControllerTest do
  use LakehouseWeb.ConnCase, async: true

  import LakehouseWeb.MatrixFixtures

  alias LakehouseIam.Accounts
  alias LakehouseMatrix.Identity

  setup do
    _ = user_fixture("alice")
    _ = user_fixture("bob")
    :ok
  end

  test "GET /_matrix/client/versions", %{conn: conn} do
    conn = get(conn, "/_matrix/client/versions")
    assert %{"versions" => ["v1.1"], "unstable_features" => %{"org.matrix.msc4186" => true}} = json_response(conn, 200)
  end

  test "POST /_matrix/client/v3/login", %{conn: conn} do
    conn = matrix_login(conn, "alice")

    assert %{
             "user_id" => "@alice:localhost",
             "access_token" => token,
             "home_server" => "localhost"
           } = json_response(conn, 200)

    assert is_binary(token) and token != ""
  end

  test "matrix room lifecycle: create, join, message, leave, sync", %{conn: conn} do
    login = matrix_login(conn, "alice") |> json_response(200)
    token = login["access_token"]
    auth = auth_header(token)

    create =
      conn
      |> put_req_header(elem(auth, 0), elem(auth, 1))
      |> put_req_header("content-type", "application/json")
      |> post("/_matrix/client/v3/createRoom", %{"name" => "General", "preset" => "public_chat"})
      |> json_response(200)

    assert %{"room_id" => room_id} = create
    assert String.starts_with?(room_id, "!")
    {:ok, room_uuid} = Identity.parse_room_id(room_id)

    bob_login = matrix_login(build_conn(), "bob") |> json_response(200)
    bob_auth = auth_header(bob_login["access_token"])

    join =
      build_conn()
      |> put_req_header(elem(bob_auth, 0), elem(bob_auth, 1))
      |> put_req_header("content-type", "application/json")
      |> post("/_matrix/client/v3/join/#{room_id}", %{})
      |> json_response(200)

    assert join["room_id"] == room_id

    send =
      build_conn()
      |> put_req_header(elem(auth, 0), elem(auth, 1))
      |> put_req_header("content-type", "application/json")
      |> put("/_matrix/client/v3/rooms/#{room_id}/send/m.room.message/m1", %{
        "msgtype" => "m.text",
        "body" => "hello matrix"
      })
      |> json_response(200)

    assert %{"event_id" => event_id} = send
    assert String.starts_with?(event_id, "$")

    messages =
      build_conn()
      |> put_req_header(elem(auth, 0), elem(auth, 1))
      |> get("/_matrix/client/v3/rooms/#{room_id}/messages")
      |> json_response(200)

    assert Enum.any?(messages["chunk"], &(&1["content"]["body"] == "hello matrix"))

    sync =
      build_conn()
      |> put_req_header(elem(auth, 0), elem(auth, 1))
      |> get("/_matrix/client/v3/sync")
      |> json_response(200)

    assert Map.has_key?(sync["rooms"]["join"], room_id)
    joined = sync["rooms"]["join"][room_id]
    assert Enum.any?(joined["timeline"]["events"], &(&1["content"]["body"] == "hello matrix"))

    bob_sync =
      build_conn()
      |> put_req_header(elem(bob_auth, 0), elem(bob_auth, 1))
      |> get("/_matrix/client/v3/sync")
      |> json_response(200)

    assert Map.has_key?(bob_sync["rooms"]["join"], room_id)

    _ =
      build_conn()
      |> put_req_header(elem(bob_auth, 0), elem(bob_auth, 1))
      |> post("/_matrix/client/v3/rooms/#{room_id}/leave", %{})
      |> json_response(200)

    bob_sync_after =
      build_conn()
      |> put_req_header(elem(bob_auth, 0), elem(bob_auth, 1))
      |> get("/_matrix/client/v3/sync")
      |> json_response(200)

    refute Map.has_key?(bob_sync_after["rooms"]["join"], room_id)

    alice_sync =
      build_conn()
      |> put_req_header(elem(auth, 0), elem(auth, 1))
      |> get("/_matrix/client/v3/sync")
      |> json_response(200)

    assert Map.has_key?(alice_sync["rooms"]["join"], room_id)
    assert room_uuid
  end

  test "users only see rooms they joined in sync", %{conn: conn} do
    alice = matrix_login(conn, "alice") |> json_response(200)
    alice_auth = auth_header(alice["access_token"])

    create =
      build_conn()
      |> put_req_header(elem(alice_auth, 0), elem(alice_auth, 1))
      |> put_req_header("content-type", "application/json")
      |> post("/_matrix/client/v3/createRoom", %{"name" => "Alice only"})
      |> json_response(200)

    bob = matrix_login(build_conn(), "bob") |> json_response(200)
    bob_auth = auth_header(bob["access_token"])

    bob_sync =
      build_conn()
      |> put_req_header(elem(bob_auth, 0), elem(bob_auth, 1))
      |> get("/_matrix/client/v3/sync")
      |> json_response(200)

    assert bob_sync["rooms"]["join"] == %{}

    {:ok, room_uuid} = Identity.parse_room_id(create["room_id"])
    {:ok, alice_principal} = Accounts.fetch_user("alice")

    assert {:ok, _} = LakehouseMatrix.Matrix.add_member(room_uuid, alice_principal.id, "bob")

    bob_sync_after =
      build_conn()
      |> put_req_header(elem(bob_auth, 0), elem(bob_auth, 1))
      |> get("/_matrix/client/v3/sync")
      |> json_response(200)

    assert Map.has_key?(bob_sync_after["rooms"]["join"], create["room_id"])
  end
end
