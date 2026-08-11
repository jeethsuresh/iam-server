defmodule LakehouseMatrix.MultiUserChatTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{Fixtures, Identity, Matrix}

  setup do
    alice = Fixtures.user_fixture("chatalice")
    bob = Fixtures.user_fixture("chatbob")
    %{alice: alice, bob: bob}
  end

  test "domain layer: separate principals exchange messages", %{alice: alice, bob: bob} do
    assert {:ok, %{"room_id" => room_mx}} = Matrix.create_room(alice.id, %{"name" => "Duo"})
    {:ok, room_id} = Identity.parse_room_id(room_mx)
    assert {:ok, _} = Matrix.add_member(room_id, alice.id, "chatbob")

    assert {:ok, _} =
             Matrix.send_message(alice.id, room_id, "d1", %{
               "body" => "alice-says-hi",
               "msgtype" => "m.text"
             })

    bob_chunk = Matrix.room_messages(bob.id, room_id)["chunk"]
    assert Enum.any?(bob_chunk, &(&1["content"]["body"] == "alice-says-hi"))

    assert {:ok, _} =
             Matrix.send_message(bob.id, room_id, "d2", %{
               "body" => "bob-replies",
               "msgtype" => "m.text"
             })

    alice_chunk = Matrix.room_messages(alice.id, room_id)["chunk"]
    bodies = Enum.map(alice_chunk, & &1["content"]["body"])
    assert "alice-says-hi" in bodies
    assert "bob-replies" in bodies

    bob_sync = Matrix.sync(bob.id, nil)
    events = get_in(bob_sync, ["rooms", "join", room_mx, "timeline", "events"]) || []
    assert Enum.any?(events, &(&1["content"]["body"] == "alice-says-hi"))
    assert Enum.any?(events, &(&1["content"]["body"] == "bob-replies"))
  end
end
