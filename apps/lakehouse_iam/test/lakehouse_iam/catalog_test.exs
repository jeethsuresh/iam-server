defmodule LakehouseIam.Apps.CatalogTest do
  use LakehouseIam.DataCase
  alias LakehouseIam.Apps.{Catalog, Grants}
  alias LakehouseIam.Accounts

  defp attrs(extra \\ %{}),
    do:
      Map.merge(
        %{
          name: "Notes",
          description: "A place to think",
          home_url: "https://notes.example.com/",
          login_url: "https://notes.example.com/auth/gravitas/start?next=%2Fnotes"
        },
        extra
      )

  test "catalog is shared, connections are per principal and revoked grants return to available" do
    {:ok, alice} = Accounts.register_user("catalogalice", "password123", approve: true)
    {:ok, bob} = Accounts.register_user("catalogbob", "password123", approve: true)
    {:ok, service} = Catalog.create(attrs())
    assert Catalog.dashboard(alice.id).available == [service]
    {:ok, grant} = Grants.upsert(alice.id, service.origin, ["profile.name"], :selected)
    assert Catalog.dashboard(alice.id).connected == [service]
    assert Catalog.dashboard(bob.id).available == [service]
    assert :ok = Grants.revoke(grant.id)
    assert Catalog.dashboard(alice.id).available == [service]
  end

  test "origins are unique and unsafe or cross-origin sign-in links are rejected" do
    {:ok, _} = Catalog.create(attrs())
    assert {:error, _} = Catalog.create(attrs())

    for url <- [
          "javascript:alert(1)",
          "//notes.example.com/login",
          "http://notes.example.com/login",
          "https://user:pass@notes.example.com/login",
          "https://notes.example.com/login#token",
          "https://evil.example/login",
          "https://notes.example.com/\\evil"
        ] do
      assert {:error, _} = Catalog.create(attrs(%{login_url: url}))
    end

    assert Catalog.get("invalid") == nil
  end

  test "launch includes a qualified login hint and preserves non-secret app parameters" do
    service = %LakehouseIam.Schema.Service{
      login_url: "https://notes.example.com/start?next=%2Fnotes"
    }

    uri = Catalog.launch_url(service, "alice") |> URI.parse()

    assert URI.decode_query(uri.query) == %{
             "next" => "/notes",
             "login_hint" => LakehouseIam.Identifier.format("alice")
           }
  end
end
