defmodule LakehouseMatrix.RoomServerTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{Fixtures, Matrix, RoomServer, Rooms}

  setup do
    alice = Fixtures.user_fixture("alicers")
    bob = Fixtures.user_fixture("bobrs")
    assert {:ok, %{"room_id" => room_mx}} = Matrix.create_room(alice.id, %{"name" => "Cache"})
    {:ok, room_id} = LakehouseMatrix.Identity.parse_room_id(room_mx)
    {:ok, _} = Rooms.ensure_started(room_id)
    %{alice: alice, bob: bob, room_id: room_id}
  end

  test "snapshot includes membership and timeline caches", %{alice: alice, room_id: room_id} do
    assert {:ok, _} =
             Matrix.send_message(alice.id, room_id, "t1", %{
               "body" => "cached",
               "msgtype" => "m.text"
             })

    snap = RoomServer.snapshot(room_id)
    assert snap.memberships[alice.id] == "join"
    assert Enum.any?(snap.timeline, &(&1["content"]["body"] == "cached"))
  end

  test "typing ephemeral and presence tracked on room actor", %{
    alice: alice,
    bob: bob,
    room_id: room_id
  } do
    assert {:ok, _} = Matrix.add_member(room_id, alice.id, "bobrs")

    Phoenix.PubSub.subscribe(LakehouseWeb.PubSub, "room:#{room_id}")

    :ok = RoomServer.track_presence(room_id, alice.id, %{username: "alicers"})
    assert_receive {:room_presence, ^room_id, presence}, 500
    assert Map.has_key?(presence, alice.id)

    :ok = RoomServer.set_typing(room_id, bob.id, "bobrs", true)
    assert_receive {:room_ephemeral, ^room_id, %{"type" => "m.typing"} = typing}, 500
    assert "@bobrs:localhost" in typing["content"]["user_ids"]
  end
end
