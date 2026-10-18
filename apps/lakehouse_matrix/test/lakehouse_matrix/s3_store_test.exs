defmodule LakehouseMatrix.S3StoreTest do
  use ExUnit.Case, async: false
  alias LakehouseMatrix.Media.Store.{S3, Unavailable}

  setup do
    old = Application.get_env(:lakehouse_matrix, :s3)

    Application.put_env(:lakehouse_matrix, :s3,
      endpoint: "https://storage.example.com",
      bucket: "media",
      access_key_id: "test-key",
      secret_access_key: "test-secret"
    )

    on_exit(fn -> Application.put_env(:lakehouse_matrix, :s3, old) end)
  end

  test "R2 requests are signed and response bytes are preserved" do
    Req.Test.stub(__MODULE__, fn conn ->
      assert conn.request_path == "/media/object-id"
      [auth] = Plug.Conn.get_req_header(conn, "authorization")
      assert String.starts_with?(auth, "AWS4-HMAC-SHA256")
      assert auth =~ "/auto/s3/aws4_request"

      case conn.method do
        "PUT" ->
          {:ok, "hello", conn} = Plug.Conn.read_body(conn)
          Plug.Conn.send_resp(conn, 200, "")

        "GET" ->
          Plug.Conn.send_resp(conn, 200, "hello")

        "DELETE" ->
          Plug.Conn.send_resp(conn, 204, "")
      end
    end)

    opts = [plug: {Req.Test, __MODULE__}]
    assert :ok = S3.put("object-id", "hello", opts)
    assert {:ok, "hello"} = S3.get("object-id", opts)
    assert :ok = S3.delete("object-id", opts)
  end

  test "an unconfigured ephemeral store cannot silently lose uploads" do
    assert {:error, :storage_unavailable} = Unavailable.put("id", "body")
  end
end
