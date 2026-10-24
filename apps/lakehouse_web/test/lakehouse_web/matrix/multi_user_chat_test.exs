defmodule LakehouseWeb.Matrix.MultiUserChatTest do
  use LakehouseWeb.ConnCase, async: false

  alias LakehouseMatrix.Identity
  import LakehouseWeb.MatrixFixtures

  setup do
    _ = user_fixture("alice")
    _ = user_fixture("bob")
    :ok
  end

  test "separate logins exchange messages back and forth", %{conn: conn} do
    alice =
      matrix_login(conn, "alice")
      |> json_response(200)

    bob =
      matrix_login(build_conn(), "bob")
      |> json_response(200)

    alice_auth = auth_header(alice["access_token"])
    bob_auth = auth_header(bob["access_token"])

    %{"room_id" => room_id} =
      build_conn()
      |> put_req_header(elem(alice_auth, 0), elem(alice_auth, 1))
      |> put_req_header("content-type", "application/json")
      |> post("/_matrix/client/v3/createRoom", %{"name" => "DM", "invite" => [Identity.user_id("bob")]})
      |> json_response(200)

    assert build_conn()
           |> put_req_header(elem(bob_auth, 0), elem(bob_auth, 1))
           |> put_req_header("content-type", "application/json")
           |> post("/_matrix/client/v3/join/#{room_id}", %{})
           |> json_response(200)

    assert %{"event_id" => _} =
             build_conn()
             |> put_req_header(elem(alice_auth, 0), elem(alice_auth, 1))
             |> put_req_header("content-type", "application/json")
             |> put("/_matrix/client/v3/rooms/#{room_id}/send/m.room.message/a1", %{
               "msgtype" => "m.text",
               "body" => "from-alice"
             })
             |> json_response(200)

    bob_messages =
      build_conn()
      |> put_req_header(elem(bob_auth, 0), elem(bob_auth, 1))
      |> get("/_matrix/client/v3/rooms/#{room_id}/messages")
      |> json_response(200)

    assert Enum.any?(bob_messages["chunk"], &(&1["content"]["body"] == "from-alice"))

    assert %{"event_id" => _} =
             build_conn()
             |> put_req_header(elem(bob_auth, 0), elem(bob_auth, 1))
             |> put_req_header("content-type", "application/json")
             |> put("/_matrix/client/v3/rooms/#{room_id}/send/m.room.message/b1", %{
               "msgtype" => "m.text",
               "body" => "from-bob"
             })
             |> json_response(200)

    alice_messages =
      build_conn()
      |> put_req_header(elem(alice_auth, 0), elem(alice_auth, 1))
      |> get("/_matrix/client/v3/rooms/#{room_id}/messages")
      |> json_response(200)

    bodies = Enum.map(alice_messages["chunk"], & &1["content"]["body"])
    assert "from-alice" in bodies
    assert "from-bob" in bodies

    bob_sync =
      build_conn()
      |> put_req_header(elem(bob_auth, 0), elem(bob_auth, 1))
      |> get("/_matrix/client/v3/sync")
      |> json_response(200)

    bob_events = get_in(bob_sync, ["rooms", "join", room_id, "timeline", "events"]) || []
    assert Enum.any?(bob_events, &(&1["content"]["body"] == "from-alice"))
    assert Enum.any?(bob_events, &(&1["content"]["body"] == "from-bob"))
  end
end
