defmodule LakehouseIam.AppSessionLogoutTest do
  use LakehouseIam.DataCase, async: false
  alias LakehouseIam.{Accounts, Auth.Sessions, Auth.Token}
  alias LakehouseIam.Apps.{Grants, Tokens}
  alias LakehouseIam.Schema.{AppToken, Session}

  setup do
    {:ok, user} = Accounts.register_user("logoutuser", "password123", approve: true)
    {:ok, family} = Sessions.issue(user.username, :browser)
    {:ok, claims} = Token.verify(family.token)
    {:ok, grant} = Grants.upsert(user.id, "http://app.test:4100", ["profile.name"], :all, [])
    %{user: user, family: family, family_id: claims["sid"], grant: grant}
  end

  test "the proof is hashed, app-bound, and usable only for session status", c do
    assert {:ok, pair} = Tokens.issue(c.grant, c.family_id)
    assert {:ok, status} = Tokens.check_session(pair.session_check_token)
    assert status.active && status.sub == c.user.id && status.session_id == c.family_id
    assert status.app_origin == c.grant.app_origin
    assert status.iss == LakehouseIam.Discovery.public_url()
    assert pair.session_check_expires_in in 2_591_990..2_592_000

    assert Repo.get_by!(AppToken, kind: :session_check).token_hash ==
             Tokens.hash(pair.session_check_token)

    assert {:error, :invalid} = Tokens.verify_access(pair.session_check_token)
    assert {:error, :invalid} = Tokens.refresh(pair.session_check_token)

    for raw <- [pair.access_token, pair.refresh_token, c.family.token, nil, "bad"] do
      assert {:error, :invalid} = Tokens.check_session(raw)
    end
  end

  test "central logout invalidates every app token but preserves consent", c do
    {:ok, another} =
      Grants.upsert(c.user.id, "http://other.test:4100", ["profile.name"], :all, [])

    pairs =
      for grant <- [c.grant, another] do
        {:ok, pair} = Tokens.issue(grant, c.family_id)
        pair
      end

    Sessions.revoke(c.family.refresh_token, :browser)

    for pair <- pairs do
      assert {:error, :invalid} = Tokens.check_session(pair.session_check_token)
      assert {:error, _} = Tokens.verify_access(pair.access_token)
      assert {:error, _} = Tokens.refresh(pair.refresh_token)
    end

    assert length(Grants.list_for_principal(c.user.id)) == 2
    assert {:error, :invalid_session} = Tokens.issue(c.grant, c.family_id)
  end

  test "logout leaves independent browser families and other accounts active", c do
    {:ok, second} = Sessions.issue(c.user.username, :browser)
    {:ok, second_claims} = Token.verify(second.token)
    {:ok, other} = Tokens.issue(c.grant, second_claims["sid"])
    {:ok, first} = Tokens.issue(c.grant, c.family_id)
    Sessions.revoke(c.family.refresh_token, :browser)
    assert {:error, :invalid} = Tokens.check_session(first.session_check_token)
    assert {:ok, _} = Tokens.check_session(other.session_check_token)
    assert {:ok, _} = Sessions.rotate(second.refresh_token, :browser)
  end

  test "a family cannot issue tokens for another account's grant", c do
    {:ok, other} = Accounts.register_user("otherlogout", "password123", approve: true)
    {:ok, grant} = Grants.upsert(other.id, "http://app.test:4100", ["profile.name"], :all, [])
    assert {:error, :invalid_session} = Tokens.issue(grant, c.family_id)
  end

  test "refresh retains the family and cannot extend its absolute expiry", c do
    session = Repo.get!(Session, c.family_id)
    expiry = DateTime.add(DateTime.utc_now(), 30, :second)
    Repo.update!(change(session, expires_at: expiry))
    {:ok, first} = Tokens.issue(c.grant, c.family_id)
    assert first.expires_in in 28..30
    {:ok, next} = Tokens.refresh(first.refresh_token)
    assert next.session_id == c.family_id && next.expires_in <= first.expires_in
    {:ok, status} = Tokens.check_session(next.session_check_token)
    assert status.exp == DateTime.to_unix(expiry)
    Repo.update!(change(session, expires_at: DateTime.add(DateTime.utc_now(), -1, :second)))
    assert {:error, :invalid} = Tokens.check_session(next.session_check_token)
  end

  test "consent revocation and password changes invalidate status proof", c do
    {:ok, pair} = Tokens.issue(c.grant, c.family_id)
    :ok = Accounts.set_password(c.user.id, "differentpassword")
    assert {:error, :invalid} = Tokens.check_session(pair.session_check_token)
    {:ok, family} = Sessions.issue(c.user.username, :browser)
    {:ok, claims} = Token.verify(family.token)
    {:ok, fresh} = Tokens.issue(c.grant, claims["sid"])
    :ok = Grants.revoke(c.grant.id)
    assert {:error, :invalid} = Tokens.check_session(fresh.session_check_token)
  end
end
