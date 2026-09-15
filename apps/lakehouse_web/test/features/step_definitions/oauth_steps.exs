defmodule LakehouseWeb.Bdd.OAuthSteps do
  use Cucumber.StepDefinition
  import ExUnit.Assertions
  import Phoenix.ConnTest

  alias LakehouseIam.Apps.Pkce
  alias LakehouseWeb.Test.Api.OAuthClient

  step "I register a PKCE backend session for {string} at origin {string}",
       %{args: [username, origin]} = context do
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)
    LakehouseIam.Federated.reset!()
    v = Pkce.generate_verifier()

    conn =
      OAuthClient.backend_register(%{
        "username" => username,
        "callerURL" => origin <> "/",
        "redirectURL" => origin <> "/oauth/callback",
        "codeChallenge" => Pkce.challenge(v),
        "codeChallengeMethod" => "S256",
        "scope" => "profile.name chats.list"
      })

    {:ok, Map.merge(context, %{last_conn: conn, pkce_verifier: v})}
  end

  step "I register a PKCE backend session for {string} with mismatched origins",
       %{args: [username]} = context do
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)
    v = Pkce.generate_verifier()

    conn =
      OAuthClient.backend_register(%{
        "username" => username,
        "callerURL" => "http://127.0.0.1:4102/",
        "redirectURL" => "http://127.0.0.1:9999/oauth/callback",
        "codeChallenge" => Pkce.challenge(v),
        "codeChallengeMethod" => "S256",
        "scope" => "profile.name"
      })

    {:ok, Map.put(context, :last_conn, conn)}
  end

  step "the backend register response has a sessionID", context do
    body = json_response(context.last_conn, 200)
    assert is_binary(body["sessionID"])
    :ok
  end

  step "the backend register response has no publicKey", context do
    body = json_response(context.last_conn, 200)
    refute Map.has_key?(body, "publicKey")
    :ok
  end
end
