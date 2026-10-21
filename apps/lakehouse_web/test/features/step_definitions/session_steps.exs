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
      |> init_test_session(user_jwt: LakehouseIam.Auth.Token.issue(username))
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
