defmodule LakehouseWeb.Matrix.LegacySyncTest do
  use LakehouseWeb.ConnCase, async: false
  alias LakehouseWeb.MatrixFixtures
  alias LakehouseMatrix.{ClientLogin, ClientRooms}

  test "legacy snapshots and event streams use authenticated routes and Matrix JSON errors" do
    user = MatrixFixtures.user_fixture("legacysync")
    {:ok, session} = ClientLogin.open(user, %{})
    {:ok, %{"room_id" => ref}} = ClientRooms.create(user.id, %{})

    conn = fn ->
      build_conn() |> put_req_header("authorization", "Bearer " <> session["access_token"])
    end

    assert get(build_conn(), "/_matrix/client/v3/initialSync")
           |> json_response(401)
           |> Map.fetch!("errcode") == "M_MISSING_TOKEN"

    initial = get(conn.(), "/_matrix/client/v3/initialSync?limit=1") |> json_response(200)
    assert [%{"room_id" => ^ref}] = initial["rooms"]

    assert get(conn.(), "/_matrix/client/v3/rooms/" <> URI.encode(ref) <> "/initialSync")
           |> json_response(200)
           |> Map.fetch!("room_id") == ref

    assert get(
             conn.(),
             "/_matrix/client/v3/events?timeout=0&from=" <> URI.encode_www_form(initial["end"])
           )
           |> json_response(200)
           |> Map.fetch!("chunk") == []

    assert get(conn.(), "/_matrix/client/v3/events/%24absent")
           |> json_response(404)
           |> Map.fetch!("errcode") == "M_NOT_FOUND"

    assert get(conn.(), "/_matrix/client/v3/initialSync?archived=invalid")
           |> json_response(400)
           |> Map.fetch!("errcode") == "M_INVALID_PARAM"
  end
end
