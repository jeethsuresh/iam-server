defmodule LakehouseIam.Apps.GrantsTest do
  use LakehouseIam.DataCase

  alias LakehouseIam.Accounts
  alias LakehouseIam.Apps.Grants

  setup do
    {:ok, principal} = Accounts.register_user("grantuser", "password123", approve: true)
    {:ok, principal: principal}
  end

  test "upsert and covers scopes/rooms", %{principal: p} do
    room = Ecto.UUID.generate()

    assert {:ok, grant} =
             Grants.upsert(p.id, "http://app.test:4100", ["profile.name", "chats.read"], :selected, [
               room
             ])

    assert Grants.covers?(grant, ["profile.name"], :selected, [room])
    refute Grants.covers?(grant, ["chats.write"], :selected, [room])
    refute Grants.covers?(grant, ["chats.read"], :all, [])
    assert Grants.room_allowed?(grant, room)
  end

  test "revoke removes grant", %{principal: p} do
    {:ok, grant} = Grants.upsert(p.id, "http://app.test:4100", ["profile.name"], :all, [])
    assert :ok = Grants.revoke(grant.id)
    assert Grants.get(p.id, "http://app.test:4100") == nil
  end
end
