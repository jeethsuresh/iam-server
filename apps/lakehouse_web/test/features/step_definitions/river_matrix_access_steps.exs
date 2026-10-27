defmodule LakehouseWeb.Bdd.RiverMatrixAccessSteps do
  use Cucumber.StepDefinition
  import Wallaby.Browser
  alias LakehouseIam.Apps.Pkce
  alias Wallaby.Query

  step "I review River's full Matrix login request", context do
    old = Application.get_env(:lakehouse_iam, :relaxed_callback_urls)
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)

    ExUnit.Callbacks.on_exit(fn ->
      Application.put_env(:lakehouse_iam, :relaxed_callback_urls, old)
    end)

    params = %{
      callerURL: "http://127.0.0.1:4102",
      redirectURL: "http://127.0.0.1:4102/oauth/callback",
      codeChallenge: Pkce.challenge(Pkce.generate_verifier()),
      scope: "profile.name matrix.full chats.list chats.read chats.write",
      state: "river-matrix-browser"
    }

    session = visit(context.session, "/oauth/start?" <> URI.encode_query(params))
    {:ok, Map.put(context, :session, session)}
  end

  step "River requires access to all Matrix spaces and conversations", context do
    assert_has(context.session, Query.css("h2", text: "Full Matrix access required"))

    assert_has(
      context.session,
      Query.css("p", text: "all your current and future Matrix spaces and conversations")
    )

    refute_has(context.session, Query.css("input[name=all_rooms]"))
    refute_has(context.session, Query.css("input[name='room_ids[]']"))
    assert_has(context.session, Query.button("Allow"))
    :ok
  end
end
