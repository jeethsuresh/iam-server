defmodule LakehouseWeb.Matrix.FederationTest do
  use LakehouseWeb.ConnCase, async: false
  alias LakehouseMatrix.{Federation.Auth, Federation.Signing, Federation.Transport}
  alias LakehouseWeb.MatrixFixtures

  setup do
    seed = :crypto.strong_rand_bytes(32)
    remote = "remote.example"
    key_id = "ed25519:test1"

    keys =
      Signing.sign(
        %{
          "server_name" => remote,
          "valid_until_ts" => System.system_time(:millisecond) + 60_000,
          "verify_keys" => %{
            key_id => %{"key" => Base.encode64(Signing.public_key(seed), padding: false)}
          },
          "old_verify_keys" => %{}
        },
        seed,
        key_id,
        remote
      )

    old =
      Map.new(
        [:signing_key, :signing_key_id, :federation_key_fetcher],
        &{&1, Application.get_env(:lakehouse_matrix, &1)}
      )

    Application.put_env(:lakehouse_matrix, :signing_key, Base.encode64(seed, padding: false))
    Application.put_env(:lakehouse_matrix, :signing_key_id, key_id)

    Application.put_env(:lakehouse_matrix, :federation_key_fetcher, fn
      ^remote, "/_matrix/key/v2/server" -> {:ok, keys}
      _, _ -> {:error, :unavailable}
    end)

    on_exit(fn ->
      for {key, value} <- old do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    %{seed: seed, remote: remote, key: key_id, keys: keys}
  end

  defp header(ctx, method, uri, content \\ nil, destination \\ "localhost") do
    object =
      Signing.request_object(method, uri, ctx.remote, destination, content)
      |> Signing.sign(ctx.seed, ctx.key, ctx.remote)

    sig = object["signatures"][ctx.remote][ctx.key]
    ~s(X-Matrix origin="#{ctx.remote}",key="#{ctx.key}",destination="#{destination}",sig="#{sig}")
  end

  test "canonical JSON orders keys, preserves Unicode and rejects floats or oversized integers" do
    assert Signing.canonical(%{"z" => 1, "a" => [true, nil, "火"]}) ==
             ~s({"a":[true,null,"火"],"z":1})

    assert_raise ArgumentError, fn -> Signing.canonical(%{"n" => 1.2}) end
    assert_raise ArgumentError, fn -> Signing.canonical(%{"n" => 9_007_199_254_740_992}) end
    assert_raise ArgumentError, fn -> Signing.canonical(%{atom: "key"}) end
  end

  test "server keys are self-signed and have the configured stable public key", ctx do
    body = build_conn() |> get("/_matrix/key/v2/server") |> json_response(200)
    assert body["server_name"] == "localhost"
    assert Signing.verify(body, Signing.public_key(ctx.seed), ctx.key, "localhost")
    assert body["valid_until_ts"] > System.system_time(:millisecond)

    assert build_conn() |> get("/.well-known/matrix/server") |> json_response(200) == %{
             "m.server" => "localhost:443"
           }
  end

  test "key discovery fails explicitly when there is no persistent signing key" do
    Application.delete_env(:lakehouse_matrix, :signing_key)
    assert build_conn() |> get("/_matrix/key/v2/server") |> json_response(503)
    assert build_conn() |> get("/.well-known/matrix/server") |> json_response(404)
  end

  test "valid remote signatures authorize profile queries, preserving the signed query URI",
       ctx do
    user = MatrixFixtures.user_fixture("federatedquery")

    uri =
      "/_matrix/federation/v1/query/profile?" <>
        URI.encode_query(%{"user_id" => LakehouseMatrix.Identity.user_id(user.username)})

    body =
      build_conn()
      |> put_req_header("authorization", header(ctx, "GET", uri))
      |> get(uri)
      |> json_response(200)

    assert body["displayname"] == user.username

    assert build_conn()
           |> put_req_header("authorization", header(ctx, "GET", uri <> "&field=displayname"))
           |> get(uri)
           |> json_response(401)
  end

  test "a client bearer token cannot authenticate as a federation server", ctx do
    MatrixFixtures.user_fixture("fedbearer")
    login = build_conn() |> MatrixFixtures.matrix_login("fedbearer") |> json_response(200)

    assert build_conn()
           |> put_req_header("authorization", "Bearer " <> login["access_token"])
           |> get("/_matrix/federation/v1/query/profile?user_id=@fedbearer:localhost")
           |> json_response(401)

    fetch = fn _, _ -> {:ok, ctx.keys} end

    assert {:error, :unauthorized} =
             Auth.verify(
               "GET",
               "/path",
               nil,
               [header(ctx, "GET", "/path", nil, "other.example")],
               fetch
             )
  end

  test "signed request bodies are authenticated and empty transactions have replay-safe results",
       ctx do
    content = %{
      "origin" => ctx.remote,
      "origin_server_ts" => System.system_time(:millisecond),
      "pdus" => [],
      "edus" => []
    }

    uri = "/_matrix/federation/v1/send/test"

    assert build_conn()
           |> put_req_header("authorization", header(ctx, "PUT", uri, content))
           |> put(uri, content)
           |> json_response(200) == %{"pdus" => %{}}

    assert build_conn()
           |> put_req_header("authorization", header(ctx, "PUT", uri, content))
           |> put(uri, Map.put(content, "origin_server_ts", 0))
           |> json_response(401)
  end

  test "expired keys, substituted keys, and ambiguous headers are rejected", ctx do
    assert {:error, :invalid_key} =
             Auth.key(Map.put(ctx.keys, "valid_until_ts", 0), ctx.remote, ctx.key)

    assert {:error, :invalid_key} =
             Auth.key(Map.put(ctx.keys, "server_name", "other.example"), ctx.remote, ctx.key)

    assert {:error, :invalid_header} =
             Auth.parse(header(ctx, "GET", "/path") <> ~s(,origin="evil.example"))

    assert {:error, :invalid_header} = Auth.parse(header(ctx, "GET", "/path") <> "unparsed")

    altered =
      put_in(
        ctx.keys,
        ["verify_keys", ctx.key, "key"],
        Base.encode64(:crypto.strong_rand_bytes(32), padding: false)
      )

    assert {:error, :invalid_key} = Auth.key(altered, ctx.remote, ctx.key)
  end

  test "federation discovery rejects internal, metadata, mapped and non-routable addresses" do
    for ip <- [
          {127, 0, 0, 1},
          {10, 0, 0, 1},
          {172, 16, 0, 1},
          {192, 168, 0, 1},
          {169, 254, 169, 254},
          {100, 64, 0, 1},
          {224, 0, 0, 1},
          {0, 0, 0, 0, 0, 0, 0, 1},
          {0xFD00, 0, 0, 0, 0, 0, 0, 1},
          {0xFE80, 0, 0, 0, 0, 0, 0, 1},
          {0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 1}
        ] do
      refute Transport.public_ip?(ip)
    end

    assert Transport.public_ip?({1, 1, 1, 1})
    assert Transport.public_ip?({0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111})

    for name <- [
          "example.org/path",
          "example.org?query",
          "user@example.org",
          "example.org#fragment",
          "example.org\n",
          "example.org:0"
        ] do
      assert {:error, _} = Transport.server_name(name)
    end

    assert {:ok, %{host: "example.org", port: 8448}} = Transport.server_name("example.org:8448")
    assert {:ok, [%{port: 443, tls_name: "example.org"}]} = Transport.resolve("example.org:443")
  end
end
