defmodule LakehouseWeb.RiverChannelsSocialTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.{Apps.Grants, Apps.Tokens}
  alias LakehouseIam.Schema.AppToken
  alias LakehouseMatrix.{DelegatedGroups, Social, Matrix, Memberships, Identity, State}
  alias LakehouseWeb.MatrixFixtures
  @scopes ~w(profile.name chats.list chats.read chats.write groups.create groups.manage groups.join spaces.channels friends.read friends.manage)

  setup do
    a = MatrixFixtures.user_fixture("chanalice")
    b = MatrixFixtures.user_fixture("chanbob")
    c = MatrixFixtures.user_fixture("chancharlie")
    grants = for u <- [a, b, c] do
      {:ok, g} = Grants.upsert(u.id, "https://chat.gravitas.cool", @scopes, :selected, [])
      g
    end
    %{a: a, b: b, c: c, ga: Enum.at(grants, 0), gb: Enum.at(grants, 1), gc: Enum.at(grants, 2)}
  end
  defp fresh(g), do: Grants.get(g.principal_id, g.app_origin)
  defp room(g, txn \\ "space"), do: DelegatedGroups.create(g, %{"name" => "Space " <> txn, "kind" => "space", "txn_id" => txn})
  defp social(g, u, action, txn), do: Social.act(g, %{"user_id" => Identity.user_id(u.username), "action" => action, "txn_id" => txn})
  defp invite(g, id, u), do: DelegatedGroups.membership(g, id, %{"action" => "invite", "user_id" => Identity.user_id(u.username)})
  defp connection(g) do
    {:ok, token} = Tokens.issue(g)
    build_conn() |> put_req_header("authorization", "Bearer " <> token.access_token)
  end

  test "channels are distinct Matrix rooms with canonical parent and initial lobby/lounge", %{ga: g} do
    {:ok, space} = room(g)
    g = fresh(g)
    {:ok, %{channels: channels}} = DelegatedGroups.channels(g, space.id)
    assert Enum.sort(Enum.map(channels, & &1.name)) == ["The Lounge", "lobby"]
    assert Enum.all?(channels, &(&1.id != space.id && &1.parent_id == space.id))
    child = hd(channels)
    assert State.get(space.id, "m.space.child", child.room_id)["content"]["via"] == [Identity.homeserver_domain()]
    assert State.get(child.id, "m.space.parent", space.room_id)["content"]["canonical"]
    assert {:ok, ^space} = room(g)
    assert {:error, :transaction_conflict} = DelegatedGroups.create_channel(g, space.id, %{"name" => "Changed", "kind" => "text", "txn_id" => "default-lobby"})
  end

  test "parent invites, acceptance, new children and removal propagate with no independent child joins", %{ga: ga, gb: gb, b: b, gc: gc} do
    {:ok, space} = room(ga)
    ga = fresh(ga)
    {:ok, %{channels: [child | _]}} = DelegatedGroups.channels(ga, space.id)
    assert {:error, :forbidden} = DelegatedGroups.timeline(gb, child.id, %{})
    assert {:error, :forbidden} = invite(gc, space.id, b)
    assert {:ok, _} = invite(ga, space.id, b)
    assert Enum.any?(DelegatedGroups.list(gb), &(&1.id == space.id && &1.membership == "invite"))
    assert {:ok, _} = DelegatedGroups.membership(gb, space.id, %{"action" => "accept"})
    gb = fresh(gb)
    assert Memberships.joined?(child.id, b.id)
    assert {:ok, _} = DelegatedGroups.timeline(gb, child.id, %{})
    assert {:error, :forbidden} = DelegatedGroups.timeline(%{gb | scopes: Enum.reject(gb.scopes, &(&1 == "spaces.channels"))}, child.id, %{})
    assert {:error, _} = DelegatedGroups.membership(ga, child.id, %{"action" => "remove", "user_id" => Identity.user_id(b.username)})
    assert {:error, _} = Matrix.leave_room(b.id, child.room_id)
    assert {:error, :forbidden} = DelegatedGroups.create_channel(gb, space.id, %{"name" => "No", "kind" => "text", "txn_id" => "no"})
    {:ok, later} = DelegatedGroups.create_channel(ga, space.id, %{"name" => "later", "kind" => "text", "txn_id" => "later"})
    assert Memberships.joined?(later.id, b.id)
    assert {:ok, _} = Matrix.remove_member(ga.principal_id, space.room_id, b.username)
    refute Memberships.joined?(child.id, b.id)
    refute Memberships.joined?(later.id, b.id)
    assert {:error, :forbidden} = DelegatedGroups.timeline(gb, child.id, %{})
    assert {:error, :forbidden} = Matrix.join_room(b.id, child.room_id)
    assert {:error, :forbidden} = Matrix.send_message(b.id, child.id, "removed", %{"body" => "No"})
  end

  test "separate channel timelines cannot cross-relate and leaving root removes every child", %{ga: g} do
    {:ok, space} = room(g)
    g = fresh(g)
    {:ok, %{channels: [a, b]}} = DelegatedGroups.channels(g, space.id)
    {:ok, e} = DelegatedGroups.send(g, a.id, "m.room.message", "a", %{"body" => "A"})
    assert {:ok, %{events: []}} = DelegatedGroups.timeline(g, b.id, %{})
    assert {:error, :invalid_relation} = DelegatedGroups.send(g, b.id, "m.reaction", "b", %{"m.relates_to" => %{"event_id" => e["event_id"], "rel_type" => "m.annotation", "key" => "👍"}})
    assert {:ok, _} = DelegatedGroups.membership(g, space.id, %{"action" => "leave"})
    assert DelegatedGroups.list(g) == []
    refute Memberships.joined?(a.id, g.principal_id)
  end

  test "cursor pagination has no overlap and private read position never moves backwards", %{ga: g, gb: bg, b: b} do
    {:ok, space} = room(g)
    g = fresh(g)
    {:ok, _} = invite(g, space.id, b)
    {:ok, _} = DelegatedGroups.membership(bg, space.id, %{"action" => "accept"})
    bg = fresh(bg)
    {:ok, %{channels: [child | _]}} = DelegatedGroups.channels(g, space.id)
    sent = for n <- 1..7 do
      {:ok, e} = DelegatedGroups.send(bg, child.id, "m.room.message", "message#{n}", %{"body" => "Message #{n}"})
      e
    end
    assert Enum.find(DelegatedGroups.list(g), &(&1.id == child.id)).unread_count == 7
    {:ok, page} = DelegatedGroups.timeline(g, child.id, %{"limit" => 3})
    {:ok, older} = DelegatedGroups.timeline(g, child.id, %{"limit" => 3, "before" => page.next_cursor})
    {:ok, oldest} = DelegatedGroups.timeline(g, child.id, %{"limit" => 3, "before" => older.next_cursor})
    ids = Enum.map(page.events ++ older.events ++ oldest.events, & &1["event_id"])
    assert length(Enum.uniq(ids)) == 7
    assert oldest.next_cursor == nil
    assert {:error, :invalid_cursor} = DelegatedGroups.timeline(g, child.id, %{"before" => "$foreign"})
    assert {:ok, _} = DelegatedGroups.mark_read(g, child.id, %{"event_id" => List.last(sent)["event_id"]})
    assert {:ok, _} = DelegatedGroups.mark_read(g, child.id, %{"event_id" => hd(sent)["event_id"]})
    assert Enum.find(DelegatedGroups.list(g), &(&1.id == child.id)).unread_count == 0
  end

  test "friend requests require recipient acceptance and both private lists agree", %{ga: ga, gb: gb, gc: gc, a: a, b: b} do
    assert {:ok, first} = social(ga, b, "request", "one")
    assert {:ok, ^first} = social(ga, b, "request", "one")
    assert {:error, :transaction_conflict} = social(ga, b, "accept", "one")
    assert {:error, :invalid_membership} = social(ga, b, "accept", "sender-cannot")
    assert {:ok, %{friends: [], requests: [%{direction: "incoming"}]}} = Social.list(gb)
    assert {:ok, %{friends: [], requests: [%{direction: "outgoing"}]}} = Social.list(ga)
    assert {:ok, %{friends: [], requests: []}} = Social.list(gc)
    assert {:ok, %{events: []}} = Social.events(gc)
    assert {:ok, _} = social(gb, a, "accept", "accept")
    assert {:ok, %{friends: [%{username: "chanalice"}], requests: []}} = Social.list(gb)
    assert {:ok, %{friends: [%{username: "chanbob"}], requests: []}} = Social.list(ga)
    assert {:error, :invalid_request} = social(ga, a, "request", "self")
  end

  test "cancel, ignore, removal and blocking cannot restore an old relationship", %{ga: ga, gb: gb, a: a, b: b} do
    {:ok, _} = social(ga, b, "request", "one")
    assert {:ok, _} = social(ga, b, "cancel", "cancel")
    assert {:error, :invalid_membership} = social(gb, a, "accept", "late")
    {:ok, _} = social(ga, b, "request", "two")
    assert {:ok, _} = social(gb, a, "ignore", "ignore")
    {:ok, _} = social(ga, b, "request", "three")
    {:ok, _} = social(gb, a, "accept", "accept")
    assert {:ok, _} = social(ga, b, "remove", "remove")
    {:ok, _} = social(ga, b, "request", "four")
    {:ok, _} = social(gb, a, "block", "block")
    assert {:error, :forbidden} = social(ga, b, "request", "blocked")
    assert {:ok, %{blocked: [%{username: "chanalice"}], friends: [], requests: []}} = Social.list(gb)
    {:ok, %{events: visible}} = Social.events(ga)
    refute Enum.any?(visible, &(&1.content.action == "block"))
    {:ok, _} = social(gb, a, "unblock", "unblock")
    assert {:error, :invalid_membership} = social(gb, a, "accept", "no-revival")
  end

  test "messaging friends reuses one room in both directions and honors block and consent", %{ga: ga, gb: gb, gc: gc, a: a, b: b, c: c} do
    assert {:error, :forbidden} = DelegatedGroups.direct(ga, %{"user_id" => Identity.user_id(b.username)})
    {:ok, _} = social(ga, b, "request", "request")
    {:ok, _} = social(gb, a, "accept", "accept")
    {:ok, first} = DelegatedGroups.direct(ga, %{"user_id" => Identity.user_id(b.username)})
    assert first.kind == "dm"
    assert {:error, :forbidden} = DelegatedGroups.direct(%{fresh(ga) | room_ids: []}, %{"user_id" => Identity.user_id(b.username)})
    assert Memberships.invited?(first.id, b.id)
    {:ok, other} = DelegatedGroups.direct(gb, %{"user_id" => Identity.user_id(a.username)})
    assert first.id == other.id
    assert Memberships.joined?(first.id, b.id)
    assert {:error, :forbidden} = DelegatedGroups.direct(gc, %{"user_id" => Identity.user_id(a.username)})
    assert {:error, :forbidden} = invite(fresh(ga), first.id, c)
    {:ok, _} = social(gb, a, "block", "block")
    assert {:error, :forbidden} = DelegatedGroups.direct(ga, %{"user_id" => Identity.user_id(b.username)})
    assert {:error, :forbidden} = DelegatedGroups.send(fresh(ga), first.id, "m.room.message", "no-block", %{"body" => "No"})
  end

  test "HTTP scope checks and legacy token snapshots protect private friend data", %{ga: ga, b: b} do
    assert get(connection(ga), "/app/v1/friends").status == 200
    old_grant = %{ga | scopes: ["profile.name"]}
    assert get(connection(old_grant), "/app/v1/friends").status == 403
    assert {:error, :insufficient_scope} = social(old_grant, b, "request", "scope")
    assert {:error, :insufficient_scope} = Social.events(old_grant)
    assert Tokens.effective_scopes(%AppToken{scopes: nil}, ga) -- ~w(profile.name chats.list chats.read chats.write groups.create groups.manage) == []
    post_conn = connection(ga) |> put_req_header("content-type", "application/json")
    assert post(post_conn, "/app/v1/friends", %{"action" => "request", "user_id" => Identity.user_id(b.username), "txn_id" => "http"}).status == 200
    existing = connection(ga)
    :ok = Grants.revoke(ga.id)
    assert get(existing, "/app/v1/friends").status == 401
  end
end
