defmodule LakehouseWeb.Matrix.UploadConnectionTest do
  use LakehouseWeb.ConnCase, async: false
  alias LakehouseMatrix.{AsyncMedia, Identity, Media}
  alias LakehouseWeb.Matrix.{MediaController}
  alias LakehouseWeb.MatrixFixtures

  # Like a real HTTP adapter, the body reader returns a new, consumed stream
  # cursor. Reusing the old cursor to send the response loses that progress.
  defmodule CursorAdapter do
    def read_req_body({adapter, state, _consumed}, options) do
      {status, bytes, next} = adapter.read_req_body(state, options)
      {status, bytes, {adapter, next, true}}
    end

    def send_resp({adapter, state, true}, status, headers, body) do
      {:ok, sent, next} = adapter.send_resp(state, status, headers, body)
      {:ok, sent, {adapter, next, true}}
    end
  end

  test "raw uploads preserve the consumed HTTP stream for ordinary and reserved MXCs" do
    user = MatrixFixtures.user_fixture("uploadcursor")
    bytes = :binary.copy(<<0, 255, 1, 2>>, 1024)

    for reserved <- [false, true] do
      conn =
        Plug.Test.conn(:post, "/_matrix/media/v3/upload?filename=cursor.bin", bytes)
        |> fetch_query_params()
        |> put_req_header("content-type", "application/octet-stream")
        |> assign(:principal_id, user.id)
        |> assign(:matrix_device_id, "cursor-device")

      {adapter, state} = conn.adapter
      conn = %{conn | adapter: {CursorAdapter, {adapter, state, false}}}

      {conn, id} =
        if reserved do
          {:ok, %{"content_uri" => uri}} = AsyncMedia.create(user.id)
          id = Media.media_id_from_uri(uri)
          params = %{"serverName" => Identity.homeserver_domain(), "mediaId" => id}
          {MediaController.upload_reserved(conn, params), id}
        else
          response = MediaController.upload(conn, %{"filename" => "cursor.bin"})
          uri = Jason.decode!(response.resp_body)["content_uri"]
          {response, Media.media_id_from_uri(uri)}
        end

      assert conn.status == 200
      assert {CursorAdapter, {_, _, true}} = conn.adapter
      assert {:ok, %{body: ^bytes}} = Media.download(user.id, Identity.homeserver_domain(), id)
    end
  end
end
