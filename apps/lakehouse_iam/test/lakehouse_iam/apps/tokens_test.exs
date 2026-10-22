defmodule LakehouseIam.Apps.TokensTest do
  use LakehouseIam.DataCase

  alias LakehouseIam.Accounts
  alias LakehouseIam.Apps.{Grants, Tokens}

  setup do
    {:ok, principal} = Accounts.register_user("tokuser", "password123", approve: true)
    {:ok, grant} = Grants.upsert(principal.id, "http://app.test:4100", ["profile.name"], :all, [])
    {:ok, principal: principal, grant: grant}
  end

  test "issue and verify access token", %{grant: grant} do
    assert {:ok, %{access_token: access, refresh_token: refresh, expires_in: 3600}} =
             Tokens.issue(grant)

    assert {:ok, %{grant: g}} = Tokens.verify_access(access)
    assert g.id == grant.id

    assert {:ok, %{access_token: access2}} = Tokens.refresh(refresh)
    assert {:ok, _} = Tokens.verify_access(access2)
  end

  test "revoke invalidates tokens", %{principal: p, grant: grant} do
    {:ok, %{access_token: access}} = Tokens.issue(grant)
    assert :ok = Tokens.revoke_app(p.id, grant.app_origin)
    assert {:error, _} = Tokens.verify_access(access)
  end

  test "a refresh credential can only be consumed once", %{grant: grant} do
    {:ok, first} = Tokens.issue(grant)
    assert {:ok, next} = Tokens.refresh(first.refresh_token)
    assert next.refresh_token != first.refresh_token
    assert {:error, :revoked} = Tokens.refresh(first.refresh_token)
    assert {:ok, _} = Tokens.verify_access(next.access_token)
  end
end
