defmodule LakehouseWeb.Bdd.ContactsSteps do
  use Cucumber.StepDefinition
  import ExUnit.Assertions
  import Wallaby.Browser
  alias Wallaby.Query
  alias LakehouseIam.{Accounts, Contacts}
  alias LakehouseIam.Apps.Grants
  alias LakehouseMatrix.Social

  step "I send a Gravitas contact request to {string} in the browser", %{args: [username]} = context do
    session = context.session |> click(Query.link("Contacts"))
      |> fill_in(Query.text_field("Gravitas username"), with: username)
      |> click(Query.button("Send contact request"))
    assert_has(session, Query.css(".contact-list", text: username))
    {:ok, Map.put(context, :session, session)}
  end

  step "the Gravitas contact request is still pending", _ do
    {:ok, a} = Accounts.fetch_user("contactbrowseralice")
    {:ok, b} = Accounts.fetch_user("contactbrowserbob")
    refute Contacts.connected?(a.id, b.id)
    assert {:ok, %{requests: [%{direction: "incoming"}]}} = Contacts.owner_list(b.id)
    :ok
  end

  step "I sign out from the contacts page", context do
    session = context.session |> click(Query.css(".sidebar-signout button"))
    assert_has(session, Query.text_field("Username"))
    {:ok, Map.put(context, :session, session)}
  end

  step "I accept the Gravitas contact request from {string} in the browser", %{args: [username]} = context do
    session = context.session |> click(Query.link("Contacts"))
    assert_has(session, Query.css(".contact-list", text: username))
    session = session |> click(Query.button("Accept"))
    assert_has(session, Query.button("Remove contact everywhere"))
    {:ok, Map.put(context, :session, session)}
  end

  step "those contacts become River friends after approving River contacts access", _ do
    {:ok, a} = Accounts.fetch_user("contactbrowseralice")
    {:ok, b} = Accounts.fetch_user("contactbrowserbob")
    assert Contacts.connected?(a.id, b.id)
    {:ok, ga} = Grants.upsert(a.id, "https://chat.gravitas.cool", ~w(contacts.read contacts.manage), :selected)
    {:ok, gb} = Grants.upsert(b.id, "https://chat.gravitas.cool", ~w(contacts.read contacts.manage), :selected)
    assert {:ok, %{friends: [%{username: "contactbrowserbob"}], requests: []}} = Social.list(ga)
    assert {:ok, %{friends: [%{username: "contactbrowseralice"}], requests: []}} = Social.list(gb)
    :ok
  end
end
