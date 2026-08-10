defmodule LakehouseMatrix.MediaTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{Fixtures, Media}
  alias LakehouseMatrix.Media.Store.Remote

  setup do
    root = Path.join(System.tmp_dir!(), "lakehouse-media-#{System.unique_integer([:positive])}")
    File.rm_rf!(root)
    File.mkdir_p!(root)

    previous_root = Application.get_env(:lakehouse_matrix, :media_root)
    previous_store = Application.get_env(:lakehouse_matrix, :media_store)

    Application.put_env(:lakehouse_matrix, :media_root, root)
    Application.put_env(:lakehouse_matrix, :media_store, LakehouseMatrix.Media.Store.Local)

    on_exit(fn ->
      File.rm_rf(root)
      Application.put_env(:lakehouse_matrix, :media_root, previous_root)
      Application.put_env(:lakehouse_matrix, :media_store, previous_store)
    end)

    user = Fixtures.user_fixture("mediauser")
    %{root: root, user: user}
  end

  test "local store put and get round-trip", %{user: user} do
    assert {:ok, result} =
             Media.upload(user.id, "hello world", filename: "note.txt", content_type: "text/plain")

    assert result.content_uri =~ ~r"^mxc://localhost/"
    assert result.info["mimetype"] == "text/plain"
    assert result.info["size"] == byte_size("hello world")

    assert {:ok, %{body: body, content_type: type}} =
             Media.download(user.id, "localhost", result.media_id)

    assert body == "hello world"
    assert type == "text/plain"
  end

  test "rejects uploads over 10MB", %{user: user} do
    huge = :crypto.strong_rand_bytes(10 * 1024 * 1024 + 1)
    assert {:error, :too_large} = Media.upload(user.id, huge, filename: "big.bin")
  end

  test "compresses images and exposes thumbnail", %{user: user} do
    png = sample_png()

    assert {:ok, result} =
             Media.upload(user.id, png, filename: "photo.png", content_type: "image/png")

    assert result.info["mimetype"] == "image/png"
    assert is_binary(result.info["thumbnail_url"])
    assert result.info["thumbnail_url"] =~ ~r"^mxc://localhost/"
    assert is_integer(result.info["thumbnail_info"]["size"])
    assert result.info["thumbnail_info"]["size"] < byte_size(png) or
             result.info["thumbnail_info"]["size"] > 0

    thumb_id = Media.media_id_from_uri(result.info["thumbnail_url"])
    assert {:ok, %{body: thumb}} = Media.download(user.id, "localhost", thumb_id)
    assert byte_size(thumb) > 0
    assert byte_size(thumb) < byte_size(png)
  end

  test "remote store stub returns not_implemented" do
    assert {:error, :not_implemented} = Remote.put("id", "bytes", [])
    assert {:error, :not_implemented} = Remote.get("id", [])
    assert {:error, :not_implemented} = Remote.delete("id", [])
  end

  defp sample_png do
    path = Path.join(System.tmp_dir!(), "lakehouse-sample-#{System.unique_integer([:positive])}.png")

    # Plasma noise makes a large PNG so JPEG preview is meaningfully smaller.
    {_, 0} =
      System.cmd(
        "magick",
        ["-size", "1200x900", "plasma:fractal", path],
        stderr_to_stdout: true
      )

    data = File.read!(path)
    File.rm(path)
    data
  end
end
