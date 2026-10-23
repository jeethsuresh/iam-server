defmodule LakehouseIam.AccountsTest do
  use LakehouseIam.DataCase, async: false

  alias LakehouseIam.{Accounts, IAM}
  alias LakehouseIam.Schema.{Grant, Principal, Resource, Role}

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

  test "global admin grants allow approval and revocation takes effect immediately" do
    {:ok, actor} = Accounts.register_user("roleadmin", "password123", approve: true)
    {:ok, _} = Accounts.register_user("pendingrole", "password123", approve: false)
    refute Accounts.admin?(actor.username)

    assert {:ok, _} = IAM.assign_role(actor.id, "admin")
    assert Accounts.admin?("ROLEADMIN")
    assert Accounts.admin?("admin")
    assert {:ok, %{active: true}} = Accounts.approve_user(actor.username, "pendingrole")

    assert :ok = IAM.revoke_role(actor.id, "admin")
    refute Accounts.admin?(actor.username)
    assert {:error, :forbidden} = Accounts.approve_user(actor.username, "pendingrole")
    assert Accounts.admin?("admin")
  end

  test "scoped grants and inactive users cannot become global administrators" do
    {:ok, actor} = Accounts.register_user("scopedadmin", "password123", approve: true)
    role = Repo.get_by!(Role, name: "admin")
    resource = Repo.insert!(%Resource{arn: "arn:test:room"})

    Repo.insert!(%Grant{principal_id: actor.id, role_id: role.id, resource_id: resource.id})
    refute Accounts.admin?(actor.username)

    assert {:ok, _} = IAM.assign_role(actor.id, "admin")
    assert Accounts.admin?(actor.username)
    assert {:ok, _} = Accounts.set_active(actor.id, false)
    refute Accounts.admin?(actor.username)
    refute Accounts.admin?("unknownuser")
  end

  test "role administrators retain their own password and can change it" do
    {:ok, actor} = Accounts.register_user("passwordadmin", "password123", approve: true)
    assert {:ok, _} = IAM.assign_role(actor.id, "admin")
    assert Accounts.password_valid?(actor.username, "password123")
    refute Accounts.password_valid?(actor.username, "adminpass")

    assert :ok =
             Accounts.change_own_password(actor.username, "password123", "password999", "password999")

    assert Accounts.password_valid?(actor.username, "password999")
    assert {:error, :forbidden, _} =
             Accounts.change_own_password("admin", "adminpass", "password999", "password999")
  end

  test "username collision after validation returns a changeset instead of raising" do
    attrs = %{type: :user, username: "racesignup", active: false}
    first = Principal.registration_changeset(%Principal{}, attrs)
    overlapping = Principal.registration_changeset(%Principal{}, attrs)

    assert {:ok, _} = Repo.insert(first)
    assert {:error, changeset} = Repo.insert(overlapping)
    assert {"already taken", _} = changeset.errors[:username]
    assert Repo.aggregate(from(p in Principal, where: p.username == "racesignup"), :count) == 1
  end

  test "change_own_password" do
    {:ok, _} = Accounts.register_user("pwduser", "password123", approve: true)

    assert :ok =
             Accounts.change_own_password("pwduser", "password123", "password999", "password999")

    assert Accounts.password_valid?("pwduser", "password999")
    refute Accounts.password_valid?("pwduser", "password123")
  end
end
