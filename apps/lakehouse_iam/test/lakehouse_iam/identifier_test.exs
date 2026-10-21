defmodule LakehouseIam.IdentifierTest do
  use ExUnit.Case, async: false
  alias LakehouseIam.{Accounts, Identifier}

  setup do
    old = Application.get_env(:lakehouse_iam, :identity_domain)
    Application.put_env(:lakehouse_iam, :identity_domain, "example.com")
    on_exit(fn -> Application.put_env(:lakehouse_iam, :identity_domain, old) end)
  end

  test "separates and normalizes username and domain" do
    assert {:ok, %{username: "alice", domain: "example.com", user_id: "@alice:example.com"}} =
             Identifier.parse(" @Alice:EXAMPLE.com ")

    assert Accounts.normalize_username("@Alice:example.com") == "alice"
    assert :ok = Accounts.validate_login_form("@alice:example.com", "secret")
    assert :ok = Accounts.validate_signup_username("@alice:example.com")
  end

  test "bare usernames identify the same local account as a full address" do
    assert Identifier.local_username(" JeEtH ") == Identifier.local_username("@jeeth:example.com")
    assert {:ok, "jeeth"} = Identifier.local_username("jeeth")
    assert Identifier.format(Accounts.normalize_username("jeeth")) == "@jeeth:example.com"
  end

  test "a foreign domain cannot authenticate a local account with the same name" do
    assert {:error, _} = Identifier.local_username("@alice:evil.example")
    assert {:error, _} = Accounts.validate_login_form("@alice:evil.example", "secret")
    refute Accounts.normalize_username("@alice:evil.example") == "alice"
  end

  test "rejects email syntax, malformed domains and URL injection" do
    for input <- [
          "alice@example.com",
          "@alice:",
          "@:example.com",
          "@a:example.com/path",
          "@a:example.com?x=1",
          "@a:example.com#fragment",
          "@a:example.com@evil.example",
          "@a:example..com",
          "@a:example.com.",
          "@a:-example.com",
          "@a:example.com:999999"
        ] do
      assert {:error, _} = Identifier.parse(input), input
    end
  end
end
