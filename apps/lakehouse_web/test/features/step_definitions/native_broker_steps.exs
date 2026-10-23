defmodule LakehouseWeb.Bdd.NativeBrokerSteps do
  use Cucumber.StepDefinition
  import ExUnit.Assertions
  import Phoenix.ConnTest
  import Wallaby.Browser
  alias LakehouseIam.{Accounts, Auth.Sessions, Auth.Token}
  alias LakehouseIam.Apps.{Grants, Pkce, Tokens}
  alias LakehouseWeb.Test.Api.OAuthClient
  alias Wallaby.Query

  @broker "http://127.0.0.1:4105"
  @app "http://127.0.0.1:4106"

  defp configure do
    old_origin = Application.get_env(:lakehouse_iam, :native_broker_origin)
    old_relaxed = Application.get_env(:lakehouse_iam, :relaxed_callback_urls)
    Application.put_env(:lakehouse_iam, :native_broker_origin, @broker)
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)
    ExUnit.Callbacks.on_exit(fn ->
      Application.put_env(:lakehouse_iam, :native_broker_origin, old_origin)
      Application.put_env(:lakehouse_iam, :relaxed_callback_urls, old_relaxed)
    end)
  end

  step "Private Store has an explicitly authorized native broker login for {string}", %{args: [username]} = context do
    configure()
    {:ok, user} = Accounts.fetch_user(username)
    {:ok, family} = Sessions.issue(username, :browser)
    {:ok, claims} = Token.verify(family.token)
    {:ok, grant} = Grants.upsert(user.id, @broker, ["profile.name", "native.broker"], :selected)
    {:ok, pair} = Tokens.issue(grant, claims["sid"])
    verifier = Pkce.generate_verifier()
    params = %{app_origin: @app, redirect_uri: @app <> "/auth/gravitas/callback",
      code_challenge: Pkce.challenge(verifier), code_challenge_method: "S256", scope: "profile.name", state: "child-state"}
    {:ok, Map.merge(context, %{broker_user: user, broker_family: family, broker_pair: pair,
      broker_verifier: verifier, broker_params: params})}
  end

  step "Private Store requests an unapproved native service login", context do
    conn = OAuthClient.broker_authorize(context.broker_pair.access_token, context.broker_params)
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "native service consent is required and no grant is created", context do
    assert json_response(context.last_conn, 403) == %{"error" => "consent_required"}
    refute Grants.get(context.broker_user.id, @app)
    :ok
  end

  step "that native service is approved and receives a broker login", context do
    {:ok, _} = Grants.upsert(context.broker_user.id, @app, ["profile.name"], :selected)
    result = OAuthClient.broker_authorize(context.broker_pair.access_token, context.broker_params) |> json_response(200)
    pair = OAuthClient.token(%{grant_type: "authorization_code", code: result["code"],
      code_verifier: context.broker_verifier, redirect_uri: context.broker_params.redirect_uri}) |> json_response(200)
    assert pair["session_id"] == context.broker_pair.session_id
    assert OAuthClient.session_check(pair["session_check_token"]).status == 200
    {:ok, Map.put(context, :native_pair, pair)}
  end

  step "I sign out of the broker's Gravitas browser login", context do
    :ok = Sessions.revoke(context.broker_family.refresh_token, :browser)
    :ok
  end

  step "the native service and broker refresh cannot resume the revoked login", context do
    assert OAuthClient.session_check(context.native_pair["session_check_token"]).status == 401
    assert OAuthClient.broker_authorize(context.broker_pair.access_token, context.broker_params).status == 401
    assert OAuthClient.token(%{grant_type: "refresh_token", refresh_token: context.broker_pair.refresh_token}).status == 400
    :ok
  end

  step "I review Private Store's native login request", context do
    configure()
    params = %{callerURL: @broker, redirectURL: @broker <> "/auth/android/callback",
      codeChallenge: Pkce.challenge(Pkce.generate_verifier()), scope: "profile.name native.broker", state: "store-browser-request"}
    session = visit(context.session, "/oauth/start?" <> URI.encode_query(params))
    assert_has(session, Query.css(".oauth-consent h1"))
    {:ok, Map.put(context, :session, session)}
  end

  step "the native broker permission explains access to already approved apps", context do
    assert_has(context.session, Query.css(".oauth-consent li", text: "Let Private Store sign you into apps you have already approved on this device."))
    assert_has(context.session, Query.button("Allow"))
    :ok
  end
end
