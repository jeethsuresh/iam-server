defmodule LakehouseIam.DiscoveryTest do
  use ExUnit.Case, async: false
  alias LakehouseIam.Discovery

  setup do
    keys = [:identity_domain, :public_url, :relaxed_callback_urls]
    old = Map.new(keys, &{&1, Application.get_env(:lakehouse_iam, &1)})
    Application.put_env(:lakehouse_iam, :identity_domain, "example.com")
    Application.put_env(:lakehouse_iam, :public_url, "https://iam.example.com")
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, false)

    on_exit(fn ->
      Enum.each(old, fn {key, value} -> Application.put_env(:lakehouse_iam, key, value) end)
    end)
  end

  test "WebFinger maps the identity domain to its IAM issuer, without enumerating users" do
    assert {:ok, body} = Discovery.webfinger("acct:alice@example.com")
    assert body["subject"] == "acct:alice@example.com"
    assert [%{"rel" => rel, "href" => "https://iam.example.com"}] = body["links"]
    assert rel == Discovery.issuer_rel()
    assert {:ok, %{"links" => []}} = Discovery.webfinger("acct:alice@example.com", ["unknown"])
    assert {:error, :not_found} = Discovery.webfinger("acct:alice@elsewhere.example")
  end

  test "client follows redirects and reads endpoints from the discovered issuer" do
    fetch = fn url ->
      uri = URI.parse(url)

      cond do
        uri.host == "example.com" ->
          assert URI.decode_query(uri.query)["resource"] == "acct:alice@example.com"

          {:ok,
           %{
             status: 307,
             headers: %{"location" => ["https://iam.example.com" <> uri.path <> "?" <> uri.query]}
           }}

        uri.path == "/.well-known/webfinger" ->
          {:ok, body} = Discovery.webfinger("acct:alice@example.com")
          {:ok, %{status: 200, body: body}}

        true ->
          {:ok, %{status: 200, body: Discovery.configuration()}}
      end
    end

    assert {:ok, %{username: "alice", domain: "example.com"}, metadata} =
             Discovery.resolve("@alice:example.com", fetch: fetch, validate: fn _ -> :ok end)

    assert metadata["token_endpoint"] == "https://iam.example.com/oauth/token"
  end

  test "rejects loops and mismatched subjects and endpoint origins" do
    loop = fn _ ->
      {:ok,
       %{status: 302, headers: %{"location" => ["https://example.com/.well-known/webfinger"]}}}
    end

    assert {:error, "too many discovery redirects"} =
             Discovery.resolve("@alice:example.com", fetch: loop, validate: fn _ -> :ok end)

    malformed = fn _ ->
      {:ok, %{status: 200, body: %{"subject" => "acct:mallory@example.com", "links" => []}}}
    end

    assert {:error, _} =
             Discovery.resolve("@alice:example.com", fetch: malformed, validate: fn _ -> :ok end)

    fetch = fn url ->
      if String.contains?(url, "webfinger") do
        {:ok, body} = Discovery.webfinger("acct:alice@example.com")
        {:ok, %{status: 200, body: body}}
      else
        {:ok,
         %{
           status: 200,
           body:
             Map.put(Discovery.configuration(), "token_endpoint", "https://evil.example/token")
         }}
      end
    end

    assert {:error, "discovered endpoints must belong to the issuer"} =
             Discovery.resolve("@alice:example.com", fetch: fetch, validate: fn _ -> :ok end)
  end

  test "discovery forbids HTTP, credentials, and private network targets" do
    for url <- [
          "http://example.com/",
          "https://u:p@example.com/",
          "https://127.0.0.1/",
          "https://169.254.169.254/",
          "https://192.168.1.1/",
          "https://[::1]/",
          "https://[fd00::1]/"
        ] do
      assert {:error, _} = Discovery.validate_url(url), url
    end
  end
end
  test "discovery advertises exactly the implemented delegated scopes" do
    scopes = Discovery.configuration()["scopes_supported"]
    assert Enum.sort(scopes) == Enum.sort(LakehouseIam.Apps.Scopes.known())
    for scope <- ~w(groups.create groups.manage groups.join spaces.channels friends.read friends.manage native.broker) do
      assert scope in scopes
    end
  end

