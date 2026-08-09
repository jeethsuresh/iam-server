defmodule LakehouseMatrix.InviteSyncTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{Fixtures, Identity, Matrix, Memberships, Sync}

  setup do
    alice = Fixtures.user_fixture("aliceinv")
    bob = Fixtures.user_fixture("bobinv")
    %{alice: alice, bob: bob}
  end

  test "invite appears in sync invite section and join accepts invite", %{alice: alice, bob: bob} do
    assert {:ok, %{"room_id" => room_mx}} = Matrix.create_room(alice.id, %{"name" => "Invites"})
    {:ok, room_id} = Identity.parse_room_id(room_mx)

    assert {:ok, _} = Matrix.invite(alice.id, room_id, "bobinv")
    assert Memberships.invited?(room_id, bob.id)

    bob_sync = Sync.sync(bob.id, nil)
    assert Map.has_key?(bob_sync["rooms"]["invite"], room_mx)
    refute Map.has_key?(bob_sync["rooms"]["join"], room_mx)

    assert {:ok, _} = Matrix.join_room(bob.id, room_mx)
    assert Memberships.joined?(room_id, bob.id)

    bob_after = Sync.sync(bob.id, nil)
    assert Map.has_key?(bob_after["rooms"]["join"], room_mx)
    refute Map.has_key?(bob_after["rooms"]["invite"], room_mx)
  end

  test "leave appears in incremental sync leave section", %{alice: alice, bob: bob} do
    assert {:ok, %{"room_id" => room_mx}} = Matrix.create_room(alice.id, %{"name" => "LeaveMe"})
    {:ok, room_id} = Identity.parse_room_id(room_mx)
    assert {:ok, _} = Matrix.add_member(room_id, alice.id, "bobinv")

    since = Sync.current_token()
    # Ensure membership.updated_at advances past the token second boundary.
    Process.sleep(1100)
    assert {:ok, _} = Matrix.leave_room(bob.id, room_mx)

    bob_sync = Sync.sync(bob.id, since, full_state: false)
    assert Map.has_key?(bob_sync["rooms"]["leave"], room_mx)
  end

  test "set_topic emits m.room.topic", %{alice: alice} do
    assert {:ok, %{"room_id" => room_mx}} = Matrix.create_room(alice.id, %{"name" => "Topics"})
    {:ok, room_id} = Identity.parse_room_id(room_mx)

    assert {:ok, event} = Matrix.set_topic(alice.id, room_id, "hello topic")
    assert event["type"] == "m.room.topic"
    assert event["content"]["topic"] == "hello topic"
  end

  test "sync timeout returns after waiting when idle", %{alice: alice} do
    assert {:ok, _} = Matrix.create_room(alice.id, %{"name" => "Idle"})
    since = Sync.current_token()

    {micros, payload} =
      :timer.tc(fn ->
        Sync.sync(alice.id, since, full_state: false, timeout: 400)
      end)

    assert is_map(payload["rooms"])
    assert micros >= 300_000
  end
end
