defmodule LakehouseWeb.Bdd.LogoutSteps do
  use Cucumber.StepDefinition
  import ExUnit.Assertions
  import Phoenix.ConnTest
  import Ecto.Query
  import Wallaby.Browser
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseIam.Apps.{Grants, Pkce, Tokens}
  alias LakehouseIam.Schema.Session
  alias LakehouseWeb.Test.Api.OAuthClient
  alias Wallaby.Query

  step "two apps share my Gravitas browser login as {string}", %{args: [username]} = context do
    {:ok, user} = Accounts.fetch_user(username)
    old = Application.get_env(:lakehouse_iam, :relaxed_callback_urls)
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)

    ExUnit.Callbacks.on_exit(fn ->
      Application.put_env(:lakehouse_iam, :relaxed_callback_urls, old)
    end)

    {conn, pairs} =
      Enum.reduce([4102, 4103], {OAuthClient.browser_login(username, "password123"), []}, fn port,
                                                                                             {conn,
                                                                                              pairs} ->
        origin = "http://127.0.0.1:#{port}"
        {:ok, _} = Grants.upsert(user.id, origin, ["profile.name"], :all, [])
        verifier = Pkce.generate_verifier()

        conn =
          OAuthClient.browser_start(conn, %{
            callerURL: origin,
            redirectURL: origin <> "/callback",
            codeChallenge: Pkce.challenge(verifier),
            scope: "profile.name",
            state: "slo-state",
            prompt: "none"
          })

        code =
          conn
          |> redirected_to()
          |> URI.parse()
          |> Map.fetch!(:query)
          |> URI.decode_query()
          |> Map.fetch!("code")

        pair =
          OAuthClient.token(%{
            grant_type: "authorization_code",
            code: code,
            code_verifier: verifier,
            redirect_uri: origin <> "/callback"
          })
          |> json_response(200)

        assert OAuthClient.session_check(pair["session_check_token"]).status == 200
        {conn, [pair | pairs]}
      end)

    {:ok, Map.merge(context, %{logout_conn: conn, logout_pairs: pairs, logout_user: user})}
  end

  step "I sign out of that Gravitas browser login", context do
    assert redirected_to(OAuthClient.browser_logout(context.logout_conn)) == "/"
    :ok
  end

  step "both services reject their old sessions and refresh tokens", context do
    for pair <- context.logout_pairs do
      assert OAuthClient.session_check(pair["session_check_token"]).status == 401
      assert OAuthClient.me(pair["access_token"]).status == 401

      assert OAuthClient.token(%{
               grant_type: "refresh_token",
               refresh_token: pair["refresh_token"]
             }).status == 400
    end

    assert length(Grants.list_for_principal(context.logout_user.id)) == 2
    :ok
  end

  step "two test services are linked to the browser login for {string}",
       %{args: [username]} = context do
    assert_has(context.session, Query.css(".global-sidebar"))
    {:ok, user} = Accounts.fetch_user(username)

    family =
      Repo.one!(
        from s in Session,
          where: s.principal_id == ^user.id and s.kind == :browser and is_nil(s.revoked_at)
      )

    pairs =
      for origin <- ["https://notes.example", "https://files.example"] do
        {:ok, grant} = Grants.upsert(user.id, origin, ["profile.name"], :all, [])
        {:ok, pair} = Tokens.issue(grant, family.id)
        pair
      end

    {:ok, Map.merge(context, %{browser_logout_pairs: pairs, logout_user: user})}
  end

  step "I sign out of Gravitas from Settings", context do
    session =
      context.session
      |> visit("/settings")
      |> click(Query.css(".settings-section form[action='/web/logout'] button[type='submit']"))

    assert_has(session, Query.button("Sign in"))
    {:ok, Map.put(context, :session, session)}
  end

  step "the connected test services are signed out but still connected", context do
    for pair <- context.browser_logout_pairs,
        do: assert({:error, :invalid} == Tokens.check_session(pair.session_check_token))

    assert length(Grants.list_for_principal(context.logout_user.id)) == 2
    :ok
  end
end
