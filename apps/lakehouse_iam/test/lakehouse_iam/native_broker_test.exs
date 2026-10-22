defmodule LakehouseIam.NativeBrokerTest do
  use LakehouseIam.DataCase, async: false

  alias LakehouseIam.{Accounts, Federated, NativeBroker}
  alias LakehouseIam.Apps.{Grants, Pkce, Tokens}
  alias LakehouseIam.Auth.{OAuth, Sessions, Token}
  alias LakehouseIam.Schema.{AppToken, FederatedEntry, Session}

  @broker "http://127.0.0.1:4105"
  @app "http://127.0.0.1:4106"

  setup do
    old_origin = Application.get_env(:lakehouse_iam, :native_broker_origin)
    old_relaxed = Application.get_env(:lakehouse_iam, :relaxed_callback_urls)
    Application.put_env(:lakehouse_iam, :native_broker_origin, @broker)
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)

    on_exit(fn ->
      Application.put_env(:lakehouse_iam, :native_broker_origin, old_origin)
      Application.put_env(:lakehouse_iam, :relaxed_callback_urls, old_relaxed)
    end)

    {:ok, user} = Accounts.register_user("nativebroker", "password123", approve: true)
    {:ok, family} = Sessions.issue(user.username, :browser)
    {:ok, claims} = Token.verify(family.token)
    {:ok, grant} = Grants.upsert(user.id, @broker, ["profile.name", "native.broker"], :selected)
    {:ok, pair} = Tokens.issue(grant, claims["sid"])
    verifier = Pkce.generate_verifier()

    params = %{
      "app_origin" => @app,
      "redirect_uri" => @app <> "/auth/gravitas/callback",
      "code_challenge" => Pkce.challenge(verifier),
      "code_challenge_method" => "S256",
      "scope" => "profile.name",
      "state" => Pkce.generate_verifier()
    }

    %{user: user, family: family, family_id: claims["sid"], grant: grant, pair: pair,
      verifier: verifier, params: params}
  end

  defp consent(c, scopes \\ ["profile.name"]) do
    {:ok, grant} = Grants.upsert(c.user.id, @app, scopes, :selected)
    grant
  end

  test "delegated codes preserve identity/family, are PKCE bound, one-use and expire in sixty seconds", c do
    consent(c)
    assert {:ok, result} = NativeBroker.authorize(c.pair.access_token, c.params)
    assert result.state == c.params["state"]
    assert result.sub == c.user.id && result.session_id == c.family_id
    assert result.issuer == LakehouseIam.Discovery.public_url()
    assert result.app_origin == @app && result.redirect_uri == c.params["redirect_uri"]
    assert result.expires_in in 59..60

    assert {:ok, child} = OAuth.exchange_code(result.code, c.verifier, result.redirect_uri)
    assert {:ok, proof} = Tokens.check_session(child.session_check_token)
    assert proof.sub == c.user.id && proof.session_id == c.family_id && proof.app_origin == @app
    assert child.scope == "profile.name"
    assert {:error, :invalid_grant} = OAuth.exchange_code(result.code, c.verifier, result.redirect_uri)

    {:ok, bad} = NativeBroker.authorize(c.pair.access_token, c.params)
    assert {:error, :invalid_code_verifier} = OAuth.exchange_code(bad.code, Pkce.generate_verifier(), bad.redirect_uri)
    {:ok, late} = NativeBroker.authorize(c.pair.access_token, c.params)
    from(e in FederatedEntry, where: e.kind == :code) |> Repo.update_all(set: [expires_at: 0])
    assert {:error, :invalid_grant} = OAuth.exchange_code(late.code, c.verifier, late.redirect_uri)
  end

  test "a broker cannot create consent, expand scopes or recursively delegate", c do
    assert {:error, :consent_required} = NativeBroker.authorize(c.pair.access_token, c.params)
    refute Grants.get(c.user.id, @app)
    consent(c, ["profile.name", "chats.read"])

    for scope <- ["", "chats.read", "profile.name chats.read", "native.broker"] do
      assert {:error, :invalid_request} = NativeBroker.authorize(c.pair.access_token, Map.put(c.params, "scope", scope))
    end

    assert {:ok, result} = NativeBroker.authorize(c.pair.access_token, c.params)
    {:ok, child} = OAuth.exchange_code(result.code, c.verifier, result.redirect_uri)
    {:ok, auth} = Tokens.verify_access(child.access_token)
    assert auth.token.scopes == ["profile.name"]
    assert {:error, :insufficient_scope} = NativeBroker.authorize(child.access_token, c.params)
  end

  test "central logout revokes broker refresh, child proof and unfinished codes but preserves another browser", c do
    consent(c)
    {:ok, code} = NativeBroker.authorize(c.pair.access_token, c.params)
    {:ok, child} = OAuth.exchange_code(code.code, c.verifier, code.redirect_uri)
    {:ok, pending} = NativeBroker.authorize(c.pair.access_token, c.params)
    {:ok, other_family} = Sessions.issue(c.user.username, :browser)
    {:ok, other_claims} = Token.verify(other_family.token)
    {:ok, other} = Tokens.issue(c.grant, other_claims["sid"])
    :ok = Sessions.revoke(c.family.refresh_token, :browser)
    assert {:error, :invalid_token} = NativeBroker.authorize(c.pair.access_token, c.params)
    assert {:error, _} = Tokens.refresh(c.pair.refresh_token)
    assert {:error, :invalid} = Tokens.check_session(child.session_check_token)
    assert {:error, :invalid_grant} = OAuth.exchange_code(pending.code, c.verifier, pending.redirect_uri)
    assert {:ok, _} = NativeBroker.authorize(other.access_token, c.params)
    assert length(Grants.list_for_principal(c.user.id)) == 2
  end

  test "refresh retains explicit broker capability and the fixed family expiry", c do
    consent(c)
    session = Repo.get!(Session, c.family_id)
    expiry = DateTime.add(DateTime.utc_now(), 30, :second)
    Repo.update!(change(session, expires_at: expiry))
    {:ok, next} = Tokens.refresh(c.pair.refresh_token)
    assert next.scope == "profile.name native.broker" && next.session_id == c.family_id
    {:ok, proof} = Tokens.check_session(next.session_check_token)
    assert proof.exp == DateTime.to_unix(expiry)
    assert {:ok, result} = NativeBroker.authorize(next.access_token, c.params)
    assert result.expires_in in 28..30
  end

  test "grant upgrade never elevates previously issued tokens, refreshes or codes", c do
    consent(c)
    {:ok, old_pair} = Tokens.issue(c.grant, c.family_id, scopes: ["profile.name"])
    {:ok, legacy} = Tokens.issue(c.grant, c.family_id)
    from(t in AppToken, where: t.token_hash in ^[Tokens.hash(legacy.access_token), Tokens.hash(legacy.refresh_token)])
    |> Repo.update_all(set: [scopes: nil])

    for pair <- [old_pair, legacy] do
      assert {:error, :insufficient_scope} = NativeBroker.authorize(pair.access_token, c.params)
      {:ok, refreshed} = Tokens.refresh(pair.refresh_token)
      refute "native.broker" in String.split(refreshed.scope)
      assert {:error, :insufficient_scope} = NativeBroker.authorize(refreshed.access_token, c.params)
    end

    request = %{app_origin: @broker, redirect_url: @broker <> "/auth/android/callback",
      scopes: ["profile.name"], code_challenge: c.params["code_challenge"], code_challenge_method: "S256", state: "old-request"}
    {:ok, redirect} = OAuth.issue_code_redirect(request, c.user.id, :selected, [], session_id: c.family_id)
    code = URI.decode_query(URI.parse(redirect).query)["code"]
    {:ok, token} = OAuth.exchange_code(code, c.verifier, request.redirect_url)
    assert token.scope == "profile.name"
    assert {:error, :insufficient_scope} = NativeBroker.authorize(token.access_token, c.params)
  end

  test "only the configured broker and exact native callback may request delegation", c do
    attrs = %{caller_url: @broker, redirect_url: @broker <> "/auth/android/callback",
      code_challenge: c.params["code_challenge"], scope: "profile.name native.broker", state: "state"}
    assert {:ok, _, _} = Federated.register(attrs)
    assert {:error, _} = Federated.register(Map.put(attrs, :redirect_url, @broker <> "/callback"))
    assert {:error, _} = Federated.register(Map.merge(attrs, %{caller_url: @app, redirect_url: @app <> "/auth/android/callback"}))
    Application.delete_env(:lakehouse_iam, :native_broker_origin)
    assert {:error, _} = Federated.register(attrs)
    assert {:error, :insufficient_scope} = NativeBroker.authorize(c.pair.access_token, c.params)
  end

  test "status proofs, refresh credentials and unbound access cannot authorize child apps", c do
    consent(c)
    {:ok, unbound} = Tokens.issue(c.grant)
    for raw <- [c.pair.session_check_token, c.pair.refresh_token, c.family.token, "invalid", nil] do
      assert {:error, :invalid_token} = NativeBroker.authorize(raw, c.params)
    end
    assert {:error, :insufficient_scope} = NativeBroker.authorize(unbound.access_token, c.params)
  end

  test "untrusted callback, missing state and invalid PKCE cannot mint a code", c do
    consent(c)
    for params <- [Map.put(c.params, "redirect_uri", "https://other.example/callback"),
                   Map.put(c.params, "redirect_uri", @app <> "/callback#fragment"),
                   Map.put(c.params, "app_origin", @app <> "/path"),
                   Map.put(c.params, "code_challenge", "bad"),
                   Map.put(c.params, "code_challenge_method", "plain"),
                   Map.delete(c.params, "state")] do
      assert {:error, :invalid_request} = NativeBroker.authorize(c.pair.access_token, params)
    end
  end
end
