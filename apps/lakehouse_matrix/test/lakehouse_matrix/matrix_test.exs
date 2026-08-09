defmodule LakehouseMatrix.MatrixTest do
  use LakehouseMatrix.DataCase, async: true

  alias LakehouseIam.IAM
  alias LakehouseMatrix.{Events, Matrix, Memberships}
  alias LakehouseMatrix.Fixtures

  setup do
    alice = Fixtures.user_fixture("alice2")
    bob = Fixtures.user_fixture("bob2")
    _ = IAM.assign_role(alice.id, "member")
    _ = IAM.assign_role(bob.id, "member")
    {:ok, alice: alice, bob: bob}
  end

  test "add_member lets another user see the room and persisted messages", %{
    alice: alice,
    bob: bob
  } do
    assert {:ok, %{"room_id" => room_id}} = Matrix.create_room(alice.id, %{"name" => "Team"})
    {:ok, room_uuid} = LakehouseMatrix.Identity.parse_room_id(room_id)

    refute Memberships.joined?(room_uuid, bob.id)

    assert {:ok, %{"user_id" => "@bob2:localhost"}} =
             Matrix.add_member(room_uuid, alice.id, "bob2")

    assert Memberships.joined?(room_uuid, bob.id)
    assert room_uuid in Memberships.joined_room_ids(bob.id)

    assert {:ok, %{"event_id" => _}} =
             Matrix.send_message(alice.id, room_uuid, "m1", %{
               "body" => "stored hello",
               "msgtype" => "m.text"
             })

  assert [%{"content" => %{"body" => "stored hello"}}] =
           Events.list_timeline(room_uuid, limit: 10)

    chunk = Matrix.room_messages(bob.id, room_uuid)
    assert [%{"content" => %{"body" => "stored hello"}}] = chunk["chunk"]
  end

  test "add_member grants member role so added user can send", %{alice: alice, bob: bob} do
    _ = LakehouseIam.IAM.revoke_role(bob.id, "member")

    assert {:ok, %{"room_id" => room_id}} = Matrix.create_room(alice.id, %{"name" => "Team"})
    {:ok, room_uuid} = LakehouseMatrix.Identity.parse_room_id(room_id)

    refute IAM.can?(bob.id, "matrix.room.send", nil)

    assert {:ok, _} = Matrix.add_member(room_uuid, alice.id, "bob2")

    assert IAM.can?(bob.id, "matrix.room.send", nil)

    assert {:ok, _} =
             Matrix.send_message(bob.id, room_uuid, "m2", %{
               "body" => "bob can send",
               "msgtype" => "m.text"
             })
  end

  test "add_member rejects unknown users", %{alice: alice} do
    assert {:ok, %{"room_id" => room_id}} = Matrix.create_room(alice.id, %{"name" => "Solo"})
    {:ok, room_uuid} = LakehouseMatrix.Identity.parse_room_id(room_id)

    assert {:error, :user_not_found} = Matrix.add_member(room_uuid, alice.id, "nobody")
  end
end
