defmodule LakehouseMatrix.AsyncMediaTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{AsyncMedia, ClientStore, Fixtures, Identity, Media}

  setup do
    root =
      Path.join(System.tmp_dir!(), "matrix-async-media-#{System.unique_integer([:positive])}")

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

    %{
      alice: Fixtures.user_fixture("alice"),
      bob: Fixtures.user_fixture("bob"),
      server: Identity.homeserver_domain()
    }
  end

  test "reservations are owner-bound, single-use, expiring and unavailable until completed",
       ctx do
    assert {:ok, %{"content_uri" => uri, "unused_expires_at" => expires}} =
             AsyncMedia.create(ctx.alice.id)

    id = Media.media_id_from_uri(uri)
    assert expires > System.system_time(:millisecond)
    assert AsyncMedia.pending?(id)
    fetch = fn -> Media.download(ctx.bob.id, ctx.server, id) end

    assert {:error, :not_yet_uploaded} =
             AsyncMedia.fetch(ctx.server, id, %{"timeout_ms" => "0"}, fetch)

    assert {:error, :forbidden} = AsyncMedia.put(ctx.bob.id, ctx.server, id, "wrong writer")
    assert {:error, :not_found} = AsyncMedia.put(ctx.alice.id, "remote.org", id, "wrong origin")
    assert {:error, :invalid_upload} = AsyncMedia.put(ctx.alice.id, ctx.server, id, "")
    assert AsyncMedia.pending?(id)
    bytes = <<0, 255, 13, 10, 42>>

    assert {:ok, %{}} =
             AsyncMedia.put(ctx.alice.id, ctx.server, id, bytes,
               filename: "encrypted.bin",
               content_type: "application/octet-stream"
             )

    refute AsyncMedia.pending?(id)
    assert {:ok, %{body: ^bytes}} = AsyncMedia.fetch(ctx.server, id, %{}, fetch)
    assert {:ok, %{body: ^bytes}} = Media.federation_download(id)

    assert {:error, :cannot_overwrite_media} =
             AsyncMedia.put(ctx.alice.id, ctx.server, id, "overwrite")

    assert {:ok, %{body: ^bytes}} = fetch.()

    {:ok, %{"content_uri" => expired}} = AsyncMedia.create(ctx.alice.id)
    expired = Media.media_id_from_uri(expired)

    Repo.update_all(
      from(r in "matrix_media_reservations", where: r.media_id == type(^expired, :binary_id)),
      set: [expires_at: DateTime.add(ClientStore.now(), -1, :second)]
    )

    refute AsyncMedia.pending?(expired)
    assert {:error, :not_found} = AsyncMedia.put(ctx.alice.id, ctx.server, expired, "late")

    assert {:error, :not_found} =
             AsyncMedia.fetch(ctx.server, expired, %{"timeout_ms" => 0}, fn ->
               Media.federation_download(expired)
             end)
  end

  test "pending reservations are bounded and remote waits preserve origin errors", ctx do
    for _ <- 1..32, do: assert({:ok, _} = AsyncMedia.create(ctx.alice.id))
    assert {:error, :rate_limited} = AsyncMedia.create(ctx.alice.id)

    assert {:error, :invalid_param} =
             AsyncMedia.fetch(ctx.server, "id", %{"timeout_ms" => -1}, fn ->
               flunk("invalid timeout called storage")
             end)

    assert {:error, :not_found} =
             AsyncMedia.fetch("remote.org", "id", %{"allow_remote" => "false"}, fn ->
               flunk("remote disabled called transport")
             end)

    Application.put_env(:lakehouse_matrix, :federation_media_requester, fn "remote.org", path ->
      assert URI.decode_query(URI.parse(path).query)["timeout_ms"] == "0"
      {:error, {:http, 504, %{"errcode" => "M_NOT_YET_UPLOADED"}}}
    end)

    assert {:error, :not_yet_uploaded} =
             AsyncMedia.fetch("remote.org", "id", %{"timeout_ms" => 0}, fn ->
               Media.download(ctx.bob.id, "remote.org", "id")
             end)
  end
end
