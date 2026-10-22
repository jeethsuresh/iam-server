defmodule LakehouseIam.SessionsTest do
  use LakehouseIam.DataCase, async: false
  alias LakehouseIam.{Accounts, Auth.Sessions, Auth.Token}
  alias LakehouseIam.Schema.{Principal, Session, RefreshToken}

  setup do
    principal = Repo.insert!(%Principal{type: :user, username: "renewuser", active: true})
    {:ok, principal: principal}
  end

  test "credentials are hashed and access is bounded by the fixed refresh family" do
    assert {:ok, bundle} = Sessions.issue("renewuser", :api)
    assert bundle.expires_in == 3600
    assert bundle.refresh_expires_in in 2_591_998..2_592_000
    assert {:ok, claims} = Token.verify(bundle.token)
    assert claims["sid"] && claims["rfe"]
    token = Repo.one!(RefreshToken)
    refute token.token_hash == bundle.refresh_token
    assert token.token_hash == Sessions.hash(bundle.refresh_token)
    session = Repo.one!(Session)
    assert {:ok, next} = Sessions.rotate(bundle.refresh_token, :api)
    assert next.refresh_token != bundle.refresh_token
    assert Repo.get!(Session, session.id).expires_at == session.expires_at
  end

  test "API refresh is single use and reuse revokes every access token in its family" do
    {:ok, first} = Sessions.issue("renewuser", :api)
    {:ok, next} = Sessions.rotate(first.refresh_token, :api)
    assert {:ok, _} = Token.verify(next.token)
    assert {:error, :reused} = Sessions.rotate(first.refresh_token, :api)
    assert :error = Token.verify(first.token)
    assert :error = Token.verify(next.token)
    assert {:error, :invalid} = Sessions.rotate(next.refresh_token, :api)
  end

  test "parallel browser requests reuse the same replacement within the grace period" do
    {:ok, first} = Sessions.issue("renewuser", :browser)
    {:ok, next} = Sessions.rotate(first.refresh_token, :browser)
    assert {:ok, duplicate} = Sessions.rotate(first.refresh_token, :browser)
    assert duplicate.refresh_token == next.refresh_token
    {:ok, third} = Sessions.rotate(next.refresh_token, :browser)
    assert {:ok, late} = Sessions.rotate(first.refresh_token, :browser)
    assert late.refresh_token == third.refresh_token
    assert {:ok, _} = Token.verify(late.token)
  end

  test "browser replay after grace revokes the family" do
    {:ok, first} = Sessions.issue("renewuser", :browser)
    {:ok, next} = Sessions.rotate(first.refresh_token, :browser)
    old = Repo.get_by!(RefreshToken, token_hash: Sessions.hash(first.refresh_token))
    Repo.update!(change(old, used_at: DateTime.add(DateTime.utc_now(), -7, :second)))
    assert {:error, :reused} = Sessions.rotate(first.refresh_token, :browser)
    assert :error = Token.verify(next.token)
  end

  test "browser and API credentials cannot be exchanged across channels" do
    {:ok, browser} = Sessions.issue("renewuser", :browser)
    {:ok, api} = Sessions.issue("renewuser", :api)
    assert {:error, :invalid} = Sessions.rotate(browser.refresh_token, :api)
    assert {:error, :invalid} = Sessions.rotate(api.refresh_token, :browser)
    Sessions.revoke(browser.refresh_token, :api)
    assert {:ok, _} = Sessions.rotate(browser.refresh_token, :browser)
  end

  test "revoking an old credential revokes its replacement too" do
    {:ok, first} = Sessions.issue("renewuser", :api)
    {:ok, next} = Sessions.rotate(first.refresh_token, :api)
    assert :ok = Sessions.revoke(first.refresh_token, :api)
    assert {:error, :invalid} = Sessions.rotate(next.refresh_token, :api)
    assert :error = Token.verify(next.token)
    assert :ok = Sessions.revoke(first.refresh_token, :api)
  end

  test "expired families cannot refresh or authenticate" do
    {:ok, bundle} = Sessions.issue("renewuser", :api)
    session = Repo.one!(Session)
    Repo.update!(change(session, expires_at: DateTime.add(DateTime.utc_now(), -1, :second)))
    assert {:error, :invalid} = Sessions.rotate(bundle.refresh_token, :api)
    assert :error = Token.verify(bundle.token)
  end

  test "deactivation permanently revokes renewal even after reactivation", %{principal: p} do
    {:ok, bundle} = Sessions.issue("renewuser", :api)
    {:ok, _} = Accounts.set_active(p.id, false)
    assert {:error, :invalid} = Sessions.issue("renewuser", :api)
    {:ok, _} = Accounts.set_active(p.id, true)
    assert {:error, :invalid} = Sessions.rotate(bundle.refresh_token, :api)
  end

  test "password changes revoke browser and API families", %{principal: p} do
    {:ok, api} = Sessions.issue("renewuser", :api)
    {:ok, browser} = Sessions.issue("renewuser", :browser)
    assert :ok = Accounts.set_password(p.id, "newpassword123")
    for token <- [api.token, browser.token], do: assert(:error == Token.verify(token))
    assert {:error, :invalid} = Sessions.rotate(browser.refresh_token, :browser)
  end

  test "malformed or unknown credentials never authenticate" do
    for raw <- [nil, "", %{}, "bad", String.duplicate("a", 257)] do
      assert {:error, :invalid} = Sessions.rotate(raw, :api)
    end

    refute Sessions.active?("invalid", "renewuser")
    assert :error = Token.verify(nil)
  end
end
