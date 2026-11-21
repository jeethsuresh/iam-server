defmodule LakehouseWeb.Bdd.RiverMatrixAccessSteps do
  use Cucumber.StepDefinition
  import Wallaby.Browser
  import Phoenix.ConnTest, only: [json_response: 2]
  alias LakehouseIam.Apps.{Pkce, Tokens}
  alias LakehouseWeb.Test.Api.OAuthClient
  alias Wallaby.Query

  @caller "http://127.0.0.1:4102"
  @callback @caller <> "/"

  step "I review River's full Matrix login request", context do
    old = Application.get_env(:lakehouse_iam, :relaxed_callback_urls)
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)

    ExUnit.Callbacks.on_exit(fn ->
      Application.put_env(:lakehouse_iam, :relaxed_callback_urls, old)
    end)

    {:ok, start_request(context)}
  end

  step "I review River's full Matrix login request again", context do
    {:ok, start_request(context)}
  end

  step "River requires access to all Matrix spaces and conversations", context do
    assert_has(context.session, Query.css("h2", text: "Full Matrix access required"))

    assert_has(
      context.session,
      Query.css("p", text: "all your current and future Matrix spaces and conversations")
    )

    refute_has(context.session, Query.css("input[name=all_rooms]"))
    refute_has(context.session, Query.css("input[name='room_ids[]']"))
    assert_has(context.session, Query.button("Grant access"))
    :ok
  end

  step "I cancel River's access request", context do
    {:ok, %{context | session: click(context.session, Query.button("Cancel"))}}
  end

  step "River receives a denial without an authorization code", context do
    params = callback_params(context)
    assert params["error"] == "access_denied"
    refute Map.has_key?(params, "code")
    :ok
  end

  step "I grant River access", context do
    {:ok, %{context | session: click(context.session, Query.button("Grant access"))}}
  end

  step "River can exchange the callback code once for full Matrix access", context do
    assert %{"code" => code} = callback_params(context)

    params = %{
      "grant_type" => "authorization_code",
      "code" => code,
      "code_verifier" => context.verifier,
      "redirect_uri" => @callback
    }

    assert %{"access_token" => access, "scope" => scope} =
             params |> OAuthClient.token() |> json_response(200)

    assert "matrix.full" in String.split(scope)
    assert {:ok, %{grant: %{room_mode: :all}}} = Tokens.verify_access(access)

    assert %{"error" => "invalid_grant"} = params |> OAuthClient.token() |> json_response(400)

    :ok
  end

  defp start_request(context) do
    verifier = Pkce.generate_verifier()
    state = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)

    params = %{
      callerURL: @caller,
      redirectURL: @callback,
      codeChallenge: Pkce.challenge(verifier),
      scope: "profile.name matrix.full chats.list chats.read chats.write",
      state: state
    }

    # The second request starts on the callback origin, so always use IAM's URL.
    url = LakehouseWeb.Endpoint.url() <> "/oauth/start?" <> URI.encode_query(params)
    session = visit(context.session, url)
    Map.merge(context, %{session: session, verifier: verifier, state: state})
  end

  defp callback_params(context) do
    url = context.session |> current_url() |> URI.parse()
    assert URI.to_string(%{url | query: nil}) == @callback
    params = URI.decode_query(url.query)
    assert params["state"] == context.state
    params
  end
end
