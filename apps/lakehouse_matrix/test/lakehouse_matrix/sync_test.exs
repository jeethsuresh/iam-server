defmodule LakehouseMatrix.SyncTest do
  use LakehouseMatrix.DataCase, async: false

  alias LakehouseMatrix.{Fixtures, Matrix, Sync}

  setup do
    alice = Fixtures.user_fixture("alice")
    bob = Fixtures.user_fixture("bob")
    %{alice: alice, bob: bob}
  end

  test "sync only includes joined rooms", %{alice: alice, bob: bob} do
    assert {:ok, %{"room_id" => room_mx}} = Matrix.create_room(alice.id, %{"name" => "Private"})
    alice_sync = Sync.sync(alice.id, nil)
    bob_sync = Sync.sync(bob.id, nil)

    assert Map.has_key?(alice_sync["rooms"]["join"], room_mx)
    assert bob_sync["rooms"]["join"] == %{}
  end
end
