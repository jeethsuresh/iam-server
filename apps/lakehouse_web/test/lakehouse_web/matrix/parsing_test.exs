defmodule LakehouseWeb.Matrix.ParsingTest do
  use LakehouseWeb.ConnCase, async: false
  alias LakehouseWeb.MatrixFixtures

  setup do
    user = MatrixFixtures.user_fixture("parsinguser")
    old = Map.new([:media_root, :media_store], &{&1, Application.get_env(:lakehouse_matrix, &1)})
    root = Path.join(System.tmp_dir!(), "matrix-parsing-#{System.unique_integer([:positive])}")
    Application.put_env(:lakehouse_matrix, :media_root, root)
    Application.put_env(:lakehouse_matrix, :media_store, LakehouseMatrix.Media.Store.Local)

    on_exit(fn ->
      File.rm_rf!(root)

      for {key, value} <- old do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    params = %{
      "type" => "m.login.password",
      "user" => user.username,
      "password" => "password123",
      "device_id" => "P"
    }

    %{user: user, params: params}
  end

  defp raw(method, path, body, headers \\ []) do
    conn =
      Enum.reduce(headers, Plug.Test.conn(method, path, body), fn {key, value}, conn ->
        put_req_header(conn, key, value)
      end)

    @endpoint.call(conn, @endpoint.init([]))
  end

  test "Matrix JSON bodies work without Content-Type and malformed/non-object bodies have readable CORS errors",
       ctx do
    session =
      raw(:post, "/_matrix/client/v3/login", Jason.encode!(Map.put(ctx.params, "_json", [1, 2])))
      |> json_response(200)

    assert session["device_id"] == "P"

    for {body, code} <- [
          {"{", "M_NOT_JSON"},
          {"[]", "M_BAD_JSON"},
          {"null", "M_BAD_JSON"},
          {"", "M_NOT_JSON"},
          {<<255>>, "M_NOT_JSON"}
        ] do
      response =
        raw(:post, "/_matrix/client/v3/login", body, [{"origin", "https://client.example"}])

      assert json_response(response, 400)["errcode"] == code
      assert get_resp_header(response, "access-control-allow-origin") == ["*"]
    end

    get_with_body =
      raw(:get, "/_matrix/client/versions", "not a JSON body", [
        {"content-type", "application/json"}
      ])

    assert get_with_body.status == 200

    assert raw(:post, "/_matrix/client/v3/logout", "", [
             {"authorization", "Bearer " <> session["access_token"]}
           ]).status == 200
  end

  test "JSON file uploads preserve their bytes and MIME type while legacy base64 uploads still work",
       ctx do
    session =
      raw(:post, "/_matrix/client/v3/login", Jason.encode!(ctx.params)) |> json_response(200)

    auth = [{"authorization", "Bearer " <> session["access_token"]}]
    bytes = "{ \"base64\": \"SGVsbG8=\", \"_json\": [1, 2] }\n"

    upload =
      raw(
        :post,
        "/_matrix/media/v3/upload?filename=example.json",
        bytes,
        auth ++ [{"content-type", "application/json"}]
      )
      |> json_response(200)

    [server, id] =
      upload["content_uri"] |> String.replace_prefix("mxc://", "") |> String.split("/", parts: 2)

    download = raw(:get, "/_matrix/client/v1/media/download/#{server}/#{id}", "", auth)
    assert download.status == 200 and download.resp_body == bytes

    assert get_resp_header(download, "content-type")
           |> hd()
           |> String.starts_with?("application/json")

    legacy = MatrixFixtures.browser_token(ctx.user.username)

    uploaded =
      raw(
        :post,
        "/_matrix/media/v3/upload",
        Jason.encode!(%{
          "base64" => Base.encode64("legacy bytes"),
          "content_type" => "text/plain"
        }),
        [{"authorization", "Bearer " <> legacy}, {"content-type", "application/json"}]
      )
      |> json_response(200)

    [server, id] =
      uploaded["content_uri"]
      |> String.replace_prefix("mxc://", "")
      |> String.split("/", parts: 2)

    download = raw(:get, "/_matrix/client/v1/media/download/#{server}/#{id}", "", auth)
    assert download.status == 200 and download.resp_body == "legacy bytes"
  end

  test "authentication accepts case-insensitive Bearer and query tokens but ignores body credentials",
       ctx do
    session =
      raw(:post, "/_matrix/client/v3/login", Jason.encode!(ctx.params)) |> json_response(200)

    token = session["access_token"]

    assert raw(:get, "/_matrix/client/v3/account/whoami", "", [
             {"authorization", "bearer " <> token}
           ]).status == 200

    assert raw(:post, "/_matrix/client/v3/keys/upload?access_token=#{token}", "{}").status == 200

    rejected =
      raw(:post, "/_matrix/client/v3/keys/upload", Jason.encode!(%{"access_token" => token}))

    assert json_response(rejected, 401)["errcode"] == "M_MISSING_TOKEN"
  end
end
