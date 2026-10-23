defmodule LakehouseWeb.DelegatedGroupsTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.Apps.{Grants, Tokens}
  alias LakehouseMatrix.{DelegatedGroups, Matrix, Memberships, Identity, State}
  alias LakehouseWeb.MatrixFixtures
  @scopes ~w(profile.name chats.list chats.read chats.write groups.create groups.manage)
  setup do
    alice = MatrixFixtures.user_fixture("riveralice")
    bob = MatrixFixtures.user_fixture("riverbob")
    {:ok, g} = Grants.upsert(alice.id, "https://chat.gravitas.cool", @scopes, :selected, [])
    %{alice: alice, bob: bob, grant: g}
  end
  defp create(g, txn \\ "one"), do: DelegatedGroups.create(g, %{"name" => "River space", "kind" => "space", "txn_id" => txn})
  defp fresh(g), do: Grants.get(g.principal_id, g.app_origin)
  defp conn_for(g) do
    {:ok, t} = Tokens.issue(g)
    build_conn() |> put_req_header("authorization", "Bearer " <> t.access_token)
  end
  test "create is scoped, idempotent and extends only new room access", %{grant: g} do
    assert {:error, :insufficient_scope} = create(%{g | scopes: []})
    assert {:ok, group} = create(g)
    assert {:ok, ^group} = create(g)
    assert fresh(g).room_ids == [group.id]
    assert State.get(group.id, "m.room.create")["content"]["type"] == "m.space"
    assert group.membership == "join"
    assert length(DelegatedGroups.list(fresh(g))) == 1
    assert {:error, :transaction_conflict} = DelegatedGroups.create(g, %{"name" => "Changed", "kind" => "space", "txn_id" => "one"})
  end
  test "allowlist, membership and owner checks are all required", %{grant: g, alice: a, bob: b} do
    {:ok, group} = create(g)
    {:ok, bg} = Grants.upsert(b.id, "https://chat.gravitas.cool", @scopes, :all, [])
    assert {:error, :forbidden} = DelegatedGroups.timeline(bg, group.id, %{})
    assert {:error, :forbidden} = Matrix.join_room(b.id, group.room_id)
    assert {:error, :forbidden} = DelegatedGroups.update(bg, group.id, %{"name" => "No"})
    g = fresh(g)
    assert {:ok, _} = DelegatedGroups.membership(g, group.id, %{"action" => "invite", "user_id" => Identity.user_id(b.username)})
    assert {:error, :forbidden} = DelegatedGroups.timeline(bg, group.id, %{})
    assert {:ok, _} = DelegatedGroups.membership(bg, group.id, %{"action" => "accept"})
    assert Memberships.joined?(group.id, b.id)
    assert {:error, :forbidden} = Matrix.invite(b.id, group.room_id, a.username)
    assert {:ok, _} = DelegatedGroups.membership(g, group.id, %{"action" => "remove", "user_id" => Identity.user_id(b.username)})
    assert {:error, :forbidden} = DelegatedGroups.timeline(bg, group.id, %{})
    assert {:error, :forbidden} = DelegatedGroups.timeline(%{g | room_ids: []}, group.id, %{})
  end
  test "distinct events preserve relations, retries and immutable delegation audit", %{grant: g} do
    {:ok, group} = create(g)
    g = fresh(g)
    body = %{"body" => "Hello", "msgtype" => "m.text"}
    assert {:ok, msg} = DelegatedGroups.send(g, group.id, "m.room.message", "txn1", body)
    assert {:ok, ^msg} = DelegatedGroups.send(g, group.id, "m.room.message", "txn1", body)
    assert {:error, :transaction_conflict} = DelegatedGroups.send(g, group.id, "m.room.message", "txn1", %{"body" => "Different"})
    assert {:ok, _} = DelegatedGroups.send(g, group.id, "cool.gravitas.river.post.v1", "post1", %{"version" => 1, "title" => "Post", "body" => "Body"})
    assert {:ok, _} = DelegatedGroups.send(g, group.id, "cool.gravitas.river.discussion.v1", "discussion1", %{"version" => 1, "title" => "Discuss", "body" => "Body"})
    assert {:ok, _} = DelegatedGroups.send(g, group.id, "m.room.message", "reply1", %{"body" => "Reply", "m.relates_to" => %{"m.in_reply_to" => %{"event_id" => msg["event_id"]}}})
    reaction = %{"m.relates_to" => %{"rel_type" => "m.annotation", "event_id" => msg["event_id"], "key" => "👍"}}
    assert {:ok, _} = DelegatedGroups.send(g, group.id, "m.reaction", "react1", reaction)
    assert {:error, :invalid_relation} = DelegatedGroups.send(g, group.id, "m.room.message", "badreply", %{"body" => "Invalid", "m.relates_to" => %{"event_id" => "$other", "rel_type" => "m.thread"}})
    assert {:ok, %{events: events}} = DelegatedGroups.timeline(g, group.id, %{})
    assert length(events) == 6
    assert Enum.any?(events, &(&1["type"] == "cool.gravitas.delegation.v1"))
    assert Enum.all?(Enum.reject(events, &(&1["type"] == "cool.gravitas.delegation.v1")), &(get_in(&1, ["content", "cool.gravitas.delegation", "app_origin"]) == g.app_origin))
  end
  test "HTTP API enforces revoked tokens, filtered list and invalid identifiers", %{grant: g} do
    {:ok, group} = create(g)
    assert json_response(get(conn_for(fresh(g)), "/app/v1/groups"), 200)["groups"] != []
    assert get(conn_for(fresh(g)), "/app/v1/groups/not-a-uuid/events").status == 403
    assert json_response(get(conn_for(g), "/app/v1/chats"), 200)["chats"] != []
    {:ok, other} = Grants.upsert(g.principal_id, "https://other.example", ["chats.list"], :selected, [])
    assert json_response(get(conn_for(other), "/app/v1/chats"), 200)["chats"] == []
    c = conn_for(fresh(g))
    :ok = Grants.revoke(g.id)
    assert get(c, "/app/v1/groups").status == 401
    refute is_nil(group.id)
  end
  test "removed members cannot receive events on an existing legacy socket", %{grant: g, bob: b} do
    {:ok, group} = create(g)
    g = fresh(g)
    {:ok, bg} = Grants.upsert(b.id, "https://chat.gravitas.cool", @scopes, :all, [])
    {:ok, _} = DelegatedGroups.membership(g, group.id, %{"action" => "invite", "user_id" => Identity.user_id(b.username)})
    {:ok, _} = DelegatedGroups.membership(bg, group.id, %{"action" => "accept"})
    socket = %Phoenix.Socket{assigns: %{room_db_id: group.id, principal_id: b.id}}
    {:ok, _} = DelegatedGroups.membership(g, group.id, %{"action" => "remove", "user_id" => Identity.user_id(b.username)})
    assert {:stop, :normal, ^socket} = LakehouseWeb.RoomChannel.handle_info({:room_event, group.id, %{"content" => %{"body" => "private"}}}, socket)
    assert {:stop, :normal, ^socket} = LakehouseWeb.RoomChannel.handle_info({:room_ephemeral, group.id, %{}}, socket)
    assert {:stop, :normal, ^socket} = LakehouseWeb.RoomChannel.handle_info({:room_presence, group.id, %{}}, socket)
  end

end
