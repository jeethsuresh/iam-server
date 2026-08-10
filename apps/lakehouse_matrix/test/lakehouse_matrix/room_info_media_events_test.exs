defmodule LakehouseMatrix.RoomInfoMediaEventsTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{Fixtures, Identity, Matrix, Media, Memberships, Rooms, State}

  setup do
    root = Path.join(System.tmp_dir!(), "lakehouse-media-ev-#{System.unique_integer([:positive])}")
    File.rm_rf!(root)
    File.mkdir_p!(root)
    previous = Application.get_env(:lakehouse_matrix, :media_root)
    Application.put_env(:lakehouse_matrix, :media_root, root)
    on_exit(fn -> File.rm_rf(root); Application.put_env(:lakehouse_matrix, :media_root, previous) end)

    alice = Fixtures.user_fixture("aliceinfo")
    bob = Fixtures.user_fixture("bobinfo")
    carol = Fixtures.user_fixture("carolinfo")

    assert {:ok, %{"room_id" => room_mx}} = Matrix.create_room(alice.id, %{"name" => "InfoRoom"})
    {:ok, room_id} = Identity.parse_room_id(room_mx)
    assert {:ok, _} = Matrix.add_member(room_id, alice.id, "bobinfo")

    %{alice: alice, bob: bob, carol: carol, room_id: room_id, room_mx: room_mx}
  end

  test "set_name emits m.room.name and updates room record", %{alice: alice, bob: bob, room_id: room_id} do
    assert {:ok, event} = Matrix.set_name(bob.id, room_id, "Renamed")
    assert event["type"] == "m.room.name"
    assert event["content"]["name"] == "Renamed"
    assert Rooms.get_room(room_id).name == "Renamed"

    assert {:ok, _} = Matrix.set_name(alice.id, room_id, "Again")
    assert Rooms.get_room(room_id).name == "Again"
  end

  test "set_avatar emits m.room.avatar", %{alice: alice, room_id: room_id} do
    assert {:ok, upload} =
             Media.upload(alice.id, "fake-image-bytes", filename: "a.png", content_type: "image/png")

    assert {:ok, event} = Matrix.set_avatar(alice.id, room_id, upload.content_uri, upload.info)
    assert event["type"] == "m.room.avatar"
    assert event["content"]["url"] == upload.content_uri
    assert Rooms.get_room(room_id).avatar_url == upload.content_uri

    state = State.get(room_id, "m.room.avatar", "")
    assert state["content"]["url"] == upload.content_uri
  end

  test "creator can remove member; member cannot", %{
    alice: alice,
    bob: bob,
    carol: carol,
    room_id: room_id
  } do
    assert {:ok, _} = Matrix.add_member(room_id, alice.id, "carolinfo")
    assert Memberships.joined?(room_id, carol.id)

    assert {:error, :forbidden} = Matrix.remove_member(bob.id, room_id, "carolinfo")
    assert Memberships.joined?(room_id, carol.id)

    assert {:ok, event} = Matrix.remove_member(alice.id, room_id, "carolinfo")
    assert event["type"] == "m.room.member"
    assert event["content"]["membership"] == "leave"
    refute Memberships.joined?(room_id, carol.id)
  end

  test "cannot remove self via remove_member", %{alice: alice, room_id: room_id} do
    assert {:error, :cannot_remove_self} = Matrix.remove_member(alice.id, room_id, "aliceinfo")
  end

  test "non-creator cannot add_member", %{bob: bob, carol: carol, room_id: room_id} do
    assert {:error, :forbidden} = Matrix.add_member(room_id, bob.id, "carolinfo")
    refute Memberships.joined?(room_id, carol.id)
  end

  test "list_room_files returns image and file messages", %{alice: alice, room_id: room_id} do
    assert {:ok, up} =
             Media.upload(alice.id, "file-bytes", filename: "doc.txt", content_type: "text/plain")

    assert {:ok, _} =
             Matrix.send_message(alice.id, room_id, "f1", %{
               "msgtype" => "m.file",
               "body" => "doc.txt",
               "url" => up.content_uri,
               "info" => up.info
             })

    assert {:ok, img} =
             Media.upload(alice.id, sample_png(), filename: "p.png", content_type: "image/png")

    assert {:ok, _} =
             Matrix.send_message(alice.id, room_id, "f2", %{
               "msgtype" => "m.image",
               "body" => "p.png",
               "url" => img.content_uri,
               "info" => img.info
             })

    assert {:ok, _} =
             Matrix.send_message(alice.id, room_id, "t1", %{
               "msgtype" => "m.text",
               "body" => "hello"
             })

    files = Matrix.list_room_files(alice.id, room_id)
    assert length(files) == 2
    assert Enum.all?(files, &(&1["content"]["msgtype"] in ["m.file", "m.image"]))
  end

  defp sample_png do
    path = Path.join(System.tmp_dir!(), "ev-png-#{System.unique_integer([:positive])}.png")
    {_, 0} = System.cmd("magick", ["-size", "64x64", "xc:blue", path], stderr_to_stdout: true)
    data = File.read!(path)
    File.rm(path)
    data
  end
end
