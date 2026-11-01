defmodule LakehouseWeb.Matrix.LegacyMediaTest do
  use LakehouseWeb.ConnCase, async: false
  alias LakehouseMatrix.{Media, Identity}
  alias LakehouseWeb.MatrixFixtures

  test "legacy federation downloads expose standard Matrix MXCs while retaining private River authorization" do
    user = MatrixFixtures.user_fixture("legacymedia")

    {:ok, public} =
      Media.upload(user.id, <<0, 255, 1, 2>>, matrix_public: true, filename: "public.bin")

    {:ok, private} = Media.upload(user.id, "private River bytes", filename: "private.txt")
    domain = Identity.homeserver_domain()
    login = build_conn() |> MatrixFixtures.matrix_login(user.username) |> json_response(200)

    for version <- ["r0", "v3"] do
      path = "/_matrix/media/#{version}/download/#{domain}/"

      assert build_conn()
             |> get(path <> public.media_id <> "?allow_remote=false")
             |> response(200) == <<0, 255, 1, 2>>

      assert build_conn() |> get(path <> private.media_id) |> json_response(404)

      assert build_conn()
             |> put_req_header("authorization", "Bearer " <> login["access_token"])
             |> get(path <> private.media_id)
             |> response(200) == "private River bytes"

      assert build_conn()
             |> get("/_matrix/media/#{version}/download/remote.example/id")
             |> json_response(404)

      assert build_conn()
             |> put_req_header("authorization", "Bearer " <> login["access_token"])
             |> get("/_matrix/media/#{version}/download/remote.example/id?allow_remote=false")
             |> json_response(404)
    end

    assert build_conn()
           |> get("/_matrix/client/v1/media/download/#{domain}/#{public.media_id}")
           |> json_response(401)
  end
end
