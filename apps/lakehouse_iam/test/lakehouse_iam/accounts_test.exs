defmodule LakehouseIam.AccountsTest do
  use LakehouseIam.DataCase, async: false

  alias LakehouseIam.{Accounts, IAM}

  setup do
    Application.put_env(:lakehouse_iam, :admin_username, "admin")
    Application.put_env(:lakehouse_iam, :admin_password, "adminpass")
    LakehouseIam.Fixtures.ensure_rbac!()
    _ = LakehouseIam.Bootstrap.run()
    :ok
  end

  test "register pending then approve then password valid" do
    assert {:ok, pending} = Accounts.register_user("pendinguser", "password123", approve: false)
    refute pending.active
    refute Accounts.password_valid?("pendinguser", "wrong")

    assert {:ok, active} = Accounts.approve_user("admin", "pendinguser")
    assert active.active
    assert Accounts.password_valid?("pendinguser", "password123")
    assert IAM.roles_for(active.id) != []
  end

  test "non-admin cannot approve" do
    {:ok, _} = Accounts.register_user("actor", "password123", approve: true)
    {:ok, _} = Accounts.register_user("target", "password123", approve: false)
    assert {:error, :forbidden} = Accounts.approve_user("actor", "target")
  end

  test "change_own_password" do
    {:ok, _} = Accounts.register_user("pwduser", "password123", approve: true)
    assert :ok = Accounts.change_own_password("pwduser", "password123", "password999", "password999")
    assert Accounts.password_valid?("pwduser", "password999")
    refute Accounts.password_valid?("pwduser", "password123")
  end
end
