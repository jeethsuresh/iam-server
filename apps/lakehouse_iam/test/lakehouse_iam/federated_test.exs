defmodule LakehouseIam.FederatedTest do
  use ExUnit.Case, async: false

  alias LakehouseIam.Apps.Pkce
  alias LakehouseIam.Federated

  setup do
    Federated.reset!()
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)
    :ok
  end

  test "register stores PKCE session without public key" do
    v = Pkce.generate_verifier()
    c = Pkce.challenge(v)

    assert {:ok, sid, "alice"} =
             Federated.register(%{
               username: "Alice",
               caller_url: "http://127.0.0.1:4100/",
               redirect_url: "http://127.0.0.1:4100/oauth/callback",
               code_challenge: c,
               code_challenge_method: "S256",
               scope: "profile.name chats.list"
             })

    sess = Federated.fetch(sid)
    assert sess.username == "alice"
    assert sess.app_origin == "http://127.0.0.1:4100"
    assert sess.scopes == ["profile.name", "chats.list"]
    refute Map.has_key?(sess, :private_jwk)
  end

  test "rejects cross-origin caller and redirect" do
    v = Pkce.generate_verifier()

    assert {:error, msg} =
             Federated.register(%{
               username: "alice",
               caller_url: "http://127.0.0.1:4100/",
               redirect_url: "http://127.0.0.1:9999/callback",
               code_challenge: Pkce.challenge(v),
               code_challenge_method: "S256",
               scope: "profile.name"
             })

    assert msg =~ "same origin"
  end

  test "code is single-use" do
    Federated.put_code("abc", %{grant_id: "g1", code_challenge: "x", code_challenge_method: "S256"})
    assert Federated.take_code("abc")
    assert Federated.take_code("abc") == nil
  end
end
