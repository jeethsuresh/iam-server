defmodule LakehouseWeb.Bdd.SessionSteps do
  use Cucumber.StepDefinition
  import ExUnit.Assertions
  import Phoenix.ConnTest
  import Wallaby.Browser
  alias LakehouseIam.Apps.Pkce
  alias Wallaby.Query
  @endpoint LakehouseWeb.Endpoint

  defp request_params do
    previous = Application.get_env(:lakehouse_iam, :relaxed_callback_urls)
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)

    ExUnit.Callbacks.on_exit(fn ->
      Application.put_env(:lakehouse_iam, :relaxed_callback_urls, previous)
    end)

    %{
      "callerURL" => "http://127.0.0.1:4102/",
      "redirectURL" => "http://127.0.0.1:4102/oauth/callback",
      "codeChallenge" => Pkce.challenge(Pkce.generate_verifier()),
      "scope" => "profile.name",
      "state" => "application-owned-state"
    }
  end

  step "I request silent application login without a base session", context do
    conn = get(build_conn(), "/oauth/start", Map.put(request_params(), "prompt", "none"))
    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "I request silent application login with the base session for {string}",
       %{args: [username]} = context do
    conn =
      build_conn()
      |> init_test_session(user_jwt: LakehouseWeb.MatrixFixtures.browser_token(username))
      |> get("/oauth/start", Map.put(request_params(), "prompt", "none"))

    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "the app callback reports {string} with its original state", %{args: [error]} = context do
    uri = URI.parse(redirected_to(context.last_conn))
    assert uri.host == "127.0.0.1" and uri.port == 4102 and uri.path == "/oauth/callback"
    query = URI.decode_query(uri.query)
    assert query["error"] == error
    assert query["state"] == "application-owned-state"
    refute query["code"]
    :ok
  end

  step "I request the service API with an expired token for {string}",
       %{args: [username]} = context do
    token = with_expired_tokens(fn -> LakehouseIam.Auth.Token.issue(username) end)

    conn =
      build_conn()
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> token)
      |> get("/api/v1/services")

    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "the expired API request is rejected without a browser redirect", context do
    assert json_response(context.last_conn, 401) == "Invalid token"
    assert Plug.Conn.get_resp_header(context.last_conn, "location") == []
    :ok
  end

  step "I open the groups page while signed out", context do
    session = visit(context.session, "/groups")
    assert_has(session, Query.button("Sign in"))
    {:ok, Map.put(context, :session, session)}
  end

  step "I sign in again on the current form as {string}", %{args: [username]} = context do
    session = submit_login(context.session, username)
    {:ok, Map.put(context, :session, session)}
  end

  step "I sign in with an already expired session as {string}", %{args: [username]} = context do
    session = submit_login(context.session, username)
    assert_has(session, Query.css(".chat-master__title", text: "Groups"))
    {:ok, user} = LakehouseIam.Accounts.fetch_user(username)
    LakehouseIam.Auth.Sessions.revoke_for_principal(user.id)
    session = visit(session, "/groups")

    {:ok, Map.put(context, :session, session)}
  end

  step "I refresh the API session", context do
    original = json_response(context.last_conn, 200)["refresh_token"]
    conn = LakehouseWeb.Test.Api.IamClient.refresh(original)
    {:ok, Map.merge(context, %{last_conn: conn, original_refresh: original})}
  end

  step "the API returns a rotated refresh token", context do
    body = json_response(context.last_conn, 200)
    assert body["refresh_token"] != context.original_refresh
    assert {:ok, _} = LakehouseIam.Auth.Token.verify(body["token"])
    {:ok, Map.put(context, :refreshed_pair, body)}
  end

  step "I reuse the original refresh token", context do
    {:ok,
     Map.put(
       context,
       :last_conn,
       LakehouseWeb.Test.Api.IamClient.refresh(context.original_refresh)
     )}
  end

  step "the renewed API access is revoked", context do
    assert :error = LakehouseIam.Auth.Token.verify(context.refreshed_pair["token"])
    :ok
  end

  step "my browser access expires but its refresh session remains valid", context do
    previous = Application.fetch_env!(:lakehouse_iam, :token_ttl_seconds)
    Application.put_env(:lakehouse_iam, :token_ttl_seconds, 3)

    try do
      session = submit_login(context.session, "browserrenew")
      assert_has(session, Query.css(".chat-master__title", text: "Groups"))
      Process.sleep(3100)
      {:ok, Map.put(context, :session, session)}
    after
      Application.put_env(:lakehouse_iam, :token_ttl_seconds, previous)
    end
  end

  step "I reopen the groups page without signing in again", context do
    {:ok, Map.put(context, :session, visit(context.session, "/groups"))}
  end

  step "I should see the friendly expired-session prompt", context do
    assert_has(
      context.session,
      Query.css(".flash--error", text: "Please sign in again to continue.")
    )

    :ok
  end

  defp submit_login(session, username) do
    session
    |> fill_in(Query.text_field("Username"), with: username)
    |> fill_in(Query.text_field("Password"), with: "password123")
    |> click(Query.button("Sign in"))
  end

  defp with_expired_tokens(fun) do
    previous = Application.fetch_env!(:lakehouse_iam, :token_ttl_seconds)
    Application.put_env(:lakehouse_iam, :token_ttl_seconds, -1)

    try do
      fun.()
    after
      Application.put_env(:lakehouse_iam, :token_ttl_seconds, previous)
    end
  end

  step "I open a username-free application login", context do
    session = visit(context.session, "/oauth/start?" <> URI.encode_query(request_params()))
    assert_has(session, Query.css(".oauth-consent h1"))
    {:ok, Map.put(context, :session, session)}
  end

  step "I open application registration", context do
    params = Map.put(request_params(), "screen", "register")
    session = visit(context.session, "/oauth/start?" <> URI.encode_query(params))
    assert_has(session, Query.css("h1", text: "Create account"))
    sid = URI.decode_query(URI.parse(current_url(session)).query)["sessionID"]
    {:ok, Map.merge(context, %{session: session, application_session_id: sid})}
  end

  step "I register from the application flow as {string}", %{args: [username]} = context do
    session =
      context.session
      |> fill_in(Query.text_field("Username"), with: username)
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> fill_in(Query.text_field("Registration key"), with: "test-invitation-key")
      |> click(Query.button("Register"))

    assert_has(session, Query.css(".flash--info", text: "administrator must approve"))
    {:ok, Map.put(context, :session, session)}
  end

  step "the application sign-in form retains its request", context do
    assert URI.decode_query(URI.parse(current_url(context.session)).query)["sessionID"] ==
             context.application_session_id

    assert page_source(context.session) =~ ~s(name="sessionID")
    assert page_source(context.session) =~ context.application_session_id
    :ok
  end

  step "I complete the application sign-in as {string}", %{args: [username]} = context do
    session =
      context.session
      |> fill_in(Query.text_field("Username"), with: username)
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.button("Sign in"))

    assert_has(session, Query.css(".oauth-consent h1"))
    {:ok, Map.put(context, :session, session)}
  end
end
