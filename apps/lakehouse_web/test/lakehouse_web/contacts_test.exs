defmodule LakehouseWeb.ContactsTest do
  use LakehouseWeb.ConnCase
  import Ecto.Query
  alias LakehouseIam.{Accounts, Contacts, Identifier, Repo}
  alias LakehouseIam.Apps.{Grants, Scopes, Tokens}
  alias LakehouseIam.Schema.{AppGrant, AppToken, Contact, ContactEvent}
  alias LakehouseMatrix.{DelegatedGroups, Identity, Social}
  alias LakehouseMatrix.Schema.{RiverFriendship, RiverSocialEvent}
  alias LakehouseWeb.MatrixFixtures

  @river "https://chat.gravitas.cool"
  @other "https://contacts.example"
  @scopes ~w(profile.name contacts.read contacts.manage chats.list chats.read chats.write groups.create groups.manage groups.join)
  setup do
    a = MatrixFixtures.user_fixture("contactalice")
    b = MatrixFixtures.user_fixture("contactbob")
    c = MatrixFixtures.user_fixture("contactcarol")
    {:ok, ga} = Grants.upsert(a.id, @other, ~w(contacts.read contacts.manage), :selected)
    {:ok, gb} = Grants.upsert(b.id, @other, ~w(contacts.read contacts.manage), :selected)
    %{a: a, b: b, c: c, ga: ga, gb: gb}
  end
  defp act(g, p, action, txn), do: Contacts.act(g, %{"username" => p.username, "action" => action, "txn_id" => txn})
  defp connected(ga, gb, a, b) do
    assert {:ok, _} = act(ga, b, "request", "request")
    assert {:ok, _} = act(gb, a, "accept", "accept")
  end
  defp connection(g) do
    {:ok, token} = Tokens.issue(g)
    build_conn() |> put_req_header("authorization", "Bearer " <> token.access_token)
  end
  defp browser(user), do: build_conn() |> init_test_session(user_jwt: MatrixFixtures.browser_token(user.username))

  test "shared contacts become River friends on consent with no copy or automatic acceptance", ctx do
    %{a: a, b: b, c: c, ga: ga, gb: gb} = ctx
    connected(ga, gb, a, b)
    assert {:ok, %{contacts: [%{username: "contactbob", uses_app: true}]}} = Contacts.list(ga)
    {:ok, ra} = Grants.upsert(a.id, @river, @scopes, :all)
    assert {:ok, %{friends: [], other_contacts: [%{username: "contactbob"}]}} = Social.list(ra)
    assert {:error, :forbidden} = DelegatedGroups.direct(ra, %{"user_id" => Identity.user_id(b.username)})
    # An unrelated app grant or legacy permission does not opt a person in.
    {:ok, _} = Grants.upsert(b.id, @river, ~w(profile.name friends.read), :all)
    assert {:ok, %{friends: []}} = Social.list(ra)
    {:ok, rb} = Grants.upsert(b.id, @river, @scopes, :all)
    for _ <- 1..3 do
      assert {:ok, %{friends: [%{username: "contactbob"}], requests: []}} = Social.list(ra)
      assert {:ok, %{friends: [%{username: "contactalice"}], requests: []}} = Social.list(rb)
    end
    assert Repo.aggregate(Contact, :count) == 1
    assert Repo.aggregate(ContactEvent, :count) == 2
    assert {:ok, _} = DelegatedGroups.direct(ra, %{"user_id" => Identity.user_id(b.username)})
    {:ok, rc} = Grants.upsert(c.id, @river, @scopes, :all)
    assert {:ok, _} = act(ra, c, "request", "pending")
    assert {:ok, %{friends: [], requests: [%{direction: "incoming"}]}} = Social.list(rc)
    refute Contacts.connected?(a.id, c.id)
  end

  test "app presence is limited to accepted contacts and the calling app, and revocation is immediate", %{a: a, b: b, ga: ga, gb: gb} do
    connected(ga, gb, a, b)
    {:ok, ra} = Grants.upsert(a.id, @river, @scopes, :all)
    {:ok, rb} = Grants.upsert(b.id, @river, @scopes, :all)
    assert get(connection(ra), "/app/v1/contacts?app_origin=https://contacts.example") |> json_response(200) |> get_in(["contacts", Access.at(0), "uses_app"])
    :ok = Grants.revoke(rb.id)
    data = get(connection(ra), "/app/v1/contacts?app_origin=https://contacts.example") |> json_response(200)
    assert [%{"uses_app" => false}] = data["contacts"]
    assert {:ok, %{friends: [], other_contacts: [_]}} = Social.list(ra)
    {:ok, _} = Grants.upsert(b.id, @river, @scopes, :all)
    {:ok, _} = Accounts.set_active(b.id, false)
    assert {:ok, %{contacts: []}} = Contacts.list(ra)
  end

  test "only new contact scopes authorize access and old token snapshots cannot inherit them", %{a: a, b: b, ga: ga} do
    {:ok, legacy} = Grants.upsert(a.id, @river, ~w(profile.name friends.read friends.manage), :selected)
    old_conn = connection(legacy)
    for path <- ["/app/v1/contacts", "/app/v1/contacts/events", "/app/v1/friends"] do
      assert get(old_conn, path).status == 403
    end
    assert {:ok, upgraded} = Grants.upsert(a.id, @river, @scopes, :selected)
    assert get(old_conn, "/app/v1/contacts").status == 403
    refute "contacts.read" in Tokens.effective_scopes(%AppToken{scopes: nil}, upgraded)
    refute "contacts.manage" in Tokens.effective_scopes(%AppToken{scopes: nil}, upgraded)
    read_only = %{ga | scopes: ["contacts.read"]}
    assert get(connection(read_only), "/app/v1/contacts").status == 200
    assert post(connection(read_only), "/app/v1/contacts", %{"username" => b.username, "action" => "request", "txn_id" => "scope"}).status == 403
    assert {:error, :insufficient_scope} = Contacts.list(%{ga | scopes: ["contacts.manage"]})
    conn = connection(ga)
    :ok = Grants.revoke(ga.id)
    assert get(conn, "/app/v1/contacts").status == 401
    assert post(conn, "/app/v1/contacts", %{"username" => b.username, "action" => "request", "txn_id" => "revoked"}).status == 401
    assert {:ok, scopes} = Scopes.parse("contacts.read contacts.manage")
    assert Enum.sort(scopes) == ~w(contacts.manage contacts.read)
  end

  test "legacy relationship rows and historical event types remain intact", %{a: a, b: b} do
    [low, high] = Enum.sort([a.id, b.id])
    legacy = Repo.insert!(%RiverFriendship{low_id: low, high_id: high, requested_by: a.id, status: "accepted"})
    historic = Repo.insert!(%RiverSocialEvent{actor_id: a.id, target_id: b.id, app_origin: @river, txn_id: "historic", action: "request"})
    {:ok, ra} = Grants.upsert(a.id, @river, @scopes, :selected)
    {:ok, _} = Grants.upsert(b.id, @river, @scopes, :selected)
    assert {:ok, %{friends: [%{username: "contactbob"}]}} = Social.list(ra)
    assert Repo.get!(Contact, legacy.id).status == "accepted"
    assert {:ok, %{events: [%{event_id: id, type: "cool.gravitas.river.friend.v1"}]}} = Contacts.events(ra)
    assert id == "$" <> historic.id
    assert {:ok, event} = act(ra, b, "remove", "remove")
    assert event.type == "cool.gravitas.contact.v1"
    assert event.content.version == 1
    assert Repo.get!(ContactEvent, historic.id).type == "cool.gravitas.river.friend.v1"
  end

  test "cross-app changes propagate and blocks never revive a removed relationship", %{a: a, b: b, ga: ga, gb: gb} do
    connected(ga, gb, a, b)
    {:ok, ra} = Grants.upsert(a.id, @river, @scopes, :all)
    {:ok, rb} = Grants.upsert(b.id, @river, @scopes, :all)
    {:ok, dm} = DelegatedGroups.direct(ra, %{"user_id" => Identity.user_id(b.username)})
    assert {:ok, _} = act(gb, a, "block", "block")
    assert {:ok, %{friends: [], requests: []}} = Social.list(ra)
    assert {:error, :forbidden} = DelegatedGroups.send(Grants.get(a.id, @river), dm.id, "m.room.message", "blocked", %{"body" => "Denied"})
    assert {:error, :forbidden} = act(ra, b, "request", "blocked-request")
    assert {:ok, %{blocked: [%{username: "contactalice"}]}} = Social.list(rb)
    assert {:ok, %{events: events}} = Contacts.events(ga)
    refute Enum.any?(events, &(&1.content.action == "block"))
    # A foreign app's actions are not an app-usage discovery endpoint.
    assert {:ok, %{events: []}} = Contacts.events(ra)
    {:ok, _} = act(gb, a, "unblock", "unblock")
    assert {:ok, %{friends: []}} = Social.list(ra)
    assert {:error, :invalid_membership} = act(gb, a, "accept", "no-revival")
  end

  test "HTTP mutations are actor-bound, recipient-approved and retry-safe", %{a: a, b: b, c: c, ga: ga, gb: gb} do
    params = %{"username" => b.username, "action" => "request", "txn_id" => "http", "principal_id" => c.id}
    first = post(connection(ga), "/app/v1/contacts", params) |> json_response(200)
    assert post(connection(ga), "/app/v1/contacts", params) |> json_response(200) == first
    assert first["sender"] == Identifier.format(a.username)
    assert first["type"] == "cool.gravitas.contact.v1"
    assert post(connection(ga), "/app/v1/contacts", %{params | "action" => "accept"}).status == 409
    assert {:error, :invalid_membership} = act(ga, b, "accept", "self-accept")
    assert {:ok, _} = act(gb, a, "accept", "recipient-accept")
    assert {:error, :invalid_request} = act(ga, a, "request", "self")
    assert {:error, :invalid_request} = Contacts.act(ga, %{"user_id" => "@contactbob:foreign.example", "action" => "request", "txn_id" => "foreign"})
  end

  test "Gravitas contacts page manages the signed-in person's graph", %{a: a, b: b} do
    assert redirected_to(get(build_conn(), "/contacts")) == "/"
    page = get(browser(a), "/contacts") |> html_response(200)
    assert page =~ "Add a contact"
    assert page =~ "Contacts"
    assert page =~ "_csrf_token"
    params = %{"username" => b.username, "action" => "request", "txn_id" => "browser-request", "principal_id" => b.id}
    assert redirected_to(post(browser(a), "/contacts", params)) == "/contacts"
    assert get(browser(b), "/contacts") |> html_response(200) =~ "contactalice"
    assert redirected_to(post(browser(b), "/contacts", %{"username" => a.username, "action" => "accept", "txn_id" => "browser-accept"})) == "/contacts"
    assert Contacts.connected?(a.id, b.id)
    assert get(browser(a), "/contacts") |> html_response(200) =~ "Remove contact everywhere"
  end
end
