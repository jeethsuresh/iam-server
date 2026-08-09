defmodule LakehouseIam.AuthorizationTest do
  use LakehouseIam.DataCase, async: false

  alias LakehouseIam.{Accounts, Authorization, IAM, Repo}

  setup do
    LakehouseIam.Fixtures.ensure_rbac!()
    {:ok, alice} = Accounts.register_user("alice", "password123", approve: true)
    {:ok, _} = IAM.assign_role(alice.id, "member")
    %{alice: alice}
  end

  test "can? is true for global member grant", %{alice: alice} do
    assert Authorization.can?(alice.id, "matrix.room.send", "arn:lakehouse:matrix:room:missing")
    assert Authorization.can?(alice.id, "matrix.room.create", nil)
  end

  test "can? is false without grant", %{alice: alice} do
    Repo.delete_all(from g in LakehouseIam.Schema.Grant, select: g.id)
    refute Authorization.can?(alice.id, "matrix.room.send", nil)
  end

  test "assign_role and revoke_role", %{alice: alice} do
    assert {:ok, _} = Authorization.assign_role(alice.id, "room_admin", nil)
    assert "room_admin" in IAM.roles_for(alice.id)
    assert :ok = Authorization.revoke_role(alice.id, "room_admin", nil)
  end

end
