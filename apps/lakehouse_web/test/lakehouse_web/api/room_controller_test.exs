defmodule LakehouseWeb.Api.RoomControllerTest do
  use LakehouseWeb.ConnCase, async: false

  import LakehouseWeb.MatrixFixtures

  alias LakehouseMatrix.{Identity, Memberships}

  setup do
    alice = user_fixture("aliceapi")
    %{alice: alice}
  end

  test "POST /api/v1/rooms uses Matrix event path and joins creator", %{alice: alice} do
    token = LakehouseIam.Auth.Token.issue(alice.username)

    conn =
      build_conn()
      |> put_req_header("authorization", "Bearer #{token}")
      |> put_req_header("content-type", "application/json")
      |> post("/api/v1/rooms", %{"name" => "API Room", "topic" => "via matrix"})

    assert %{"id" => id, "matrix_room_id" => mx, "name" => "API Room"} = json_response(conn, 201)
    assert mx == Identity.room_id(id)
    assert Memberships.joined?(id, alice.id)
  end
end
