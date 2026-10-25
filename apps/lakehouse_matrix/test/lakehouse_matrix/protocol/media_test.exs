defmodule LakehouseMatrix.FederationMediaTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{Fixtures, Identity}
  alias LakehouseMatrix.Federation.Media, as: FederationMedia
  alias LakehouseMatrix.Federation.Transport

  setup do
    root = Path.join(System.tmp_dir!(), "matrix-media-#{System.unique_integer([:positive])}")
    keys = [:media_root, :media_store, :federation_media_requester]
    old = Map.new(keys, &{&1, Application.get_env(:lakehouse_matrix, &1)})
    Application.put_env(:lakehouse_matrix, :media_root, root)
    Application.put_env(:lakehouse_matrix, :media_store, LakehouseMatrix.Media.Store.Local)

    on_exit(fn ->
      File.rm_rf(root)

      for {key, value} <- old do
        if is_nil(value),
          do: Application.delete_env(:lakehouse_matrix, key),
          else: Application.put_env(:lakehouse_matrix, key, value)
      end
    end)

    %{alice: Fixtures.user_fixture("alice"), bob: Fixtures.user_fixture("bob")}
  end

  test "only standard Matrix uploads are available by authenticated MXC possession", ctx do
    alias LakehouseMatrix.Media

    assert {:ok, private} =
             Media.upload(ctx.alice.id, "private River file", filename: "private.txt")

    assert {:error, :forbidden} =
             Media.download(ctx.bob.id, Identity.homeserver_domain(), private.media_id)

    assert {:error, :not_found} = Media.federation_download(private.media_id)

    assert {:ok, standard} =
             Media.upload(ctx.alice.id, <<0, 255, 0, 1>>,
               filename: "encrypted.bin",
               matrix_public: true
             )

    assert {:ok, %{body: <<0, 255, 0, 1>>}} =
             Media.download(ctx.bob.id, Identity.homeserver_domain(), standard.media_id)

    assert {:ok, %{body: <<0, 255, 0, 1>>}} = Media.federation_download(standard.media_id)
    assert {:error, :not_found} = Media.federation_download("not-a-uuid")

    assert {:error, :not_found} =
             Media.download(ctx.alice.id, Identity.homeserver_domain(), "../private")
  end

  test "multipart round trip preserves ciphertext and safe Unicode filenames" do
    media = %{
      body: <<0, 255, 13, 10, 0, 4>>,
      content_type: "application/octet-stream",
      filename: "秘密.bin"
    }

    {type, body} = FederationMedia.encode(media)

    assert {:ok, ^media} =
             FederationMedia.decode(%{body: body, headers: %{"content-type" => [type]}})

    assert FederationMedia.disposition("text/html", "bad\r\n\"name.html") =~ "attachment;"
    refute FederationMedia.disposition("text/html", "bad\r\n\"name.html") =~ "\r"
    assert FederationMedia.disposition("image/png", nil) == "inline"

    assert {:error, :invalid_media} =
             FederationMedia.decode(%{
               body: body,
               headers: %{"content-type" => "multipart/mixed; boundary=wrong"}
             })

    assert {:error, :invalid_media} = FederationMedia.decode(%{body: "garbage", headers: %{}})
  end

  test "remote media cannot be confused with local private media or escape the media path", ctx do
    alias LakehouseMatrix.Media
    {:ok, private} = Media.upload(ctx.alice.id, "local secret", filename: "secret.txt")

    Application.put_env(:lakehouse_matrix, :federation_media_requester, fn "remote.org", path ->
      send(self(), {:path, path})

      {type, body} =
        FederationMedia.encode(%{body: "remote bytes", content_type: "text/plain", filename: nil})

      {:ok, %{body: body, headers: %{"content-type" => type}}}
    end)

    assert {:ok, %{body: "remote bytes"}} =
             Media.download(ctx.alice.id, "remote.org", private.media_id)

    assert_received {:path, path}
    assert path == "/_matrix/federation/v1/media/download/" <> private.media_id <> "?timeout_ms=0"
    assert {:error, :not_found} = Media.download(ctx.alice.id, "remote.org", "../admin")
    refute_received {:path, _}
    assert {:error, :blocked_address} = Transport.get_raw_url("https://127.0.0.1/private")

    assert {:error, :blocked_address} =
             Transport.get_raw_url("https://user:password@example.org/private")
  end
end
