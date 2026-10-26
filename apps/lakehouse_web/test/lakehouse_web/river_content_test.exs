defmodule LakehouseWeb.RiverContentTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.{Repo, Apps.Grants}
  alias LakehouseMatrix.{DelegatedGroups, RiverContent, Identity}
  alias LakehouseMatrix.Schema.RoomEvent
  alias LakehouseWeb.MatrixFixtures
  @scopes ~w(chats.list chats.read chats.write groups.create groups.manage groups.join spaces.channels)
  setup do
    a = MatrixFixtures.user_fixture("contentalice")
    b = MatrixFixtures.user_fixture("contentbob")
    {:ok, ga} = Grants.upsert(a.id, "https://chat.gravitas.cool", @scopes, :all, [])
    {:ok, gb} = Grants.upsert(b.id, "https://chat.gravitas.cool", @scopes, :all, [])
    {:ok, room} = DelegatedGroups.create(ga, %{"name" => "Content", "kind" => "dm", "txn_id" => "content"})
    {:ok, _} = DelegatedGroups.membership(ga, room.id, %{"action" => "invite", "user_id" => Identity.user_id(b.username)})
    {:ok, _} = DelegatedGroups.membership(gb, room.id, %{"action" => "accept"})
    %{ga: ga, gb: gb, room: room}
  end
  defp message(g, id, txn, body \\ "Message"), do: DelegatedGroups.send(g, id, "m.room.message", txn, %{"body" => body})
  defp react(g, id, target, active, txn), do: RiverContent.reaction(g, id, %{"event_id" => target, "key" => "👍", "active" => active, "txn_id" => txn})
  defp summary(g, id, event) do
    {:ok, %{events: events}} = DelegatedGroups.timeline(g, id, %{})
    Enum.find(events, &(&1["event_id"] == event))["reaction_summary"]
  end

  test "reaction toggles aggregate people and old removal retries cannot remove a later reaction", %{ga: a, gb: b, room: r} do
    {:ok, e} = message(a, r.id, "message")
    {:ok, _} = react(a, r.id, e["event_id"], true, "add-a")
    {:ok, _} = react(a, r.id, e["event_id"], true, "add-a-again")
    {:ok, _} = react(b, r.id, e["event_id"], true, "add-b")
    assert [%{key: "👍", count: 2, mine: true}] = summary(a, r.id, e["event_id"])
    {:ok, removed} = react(a, r.id, e["event_id"], false, "remove-a")
    assert [%{key: "👍", count: 1, mine: false}] = summary(a, r.id, e["event_id"])
    {:ok, _} = react(a, r.id, e["event_id"], true, "add-a-new")
    assert {:ok, ^removed} = react(a, r.id, e["event_id"], false, "remove-a")
    assert [%{count: 2, mine: true}] = summary(a, r.id, e["event_id"])
    assert {:error, :transaction_conflict} = react(a, r.id, e["event_id"], true, "remove-a")
  end

  test "sticker reactions aggregate, remove idempotently and reject unsafe URLs", %{ga: a, gb: b, room: r} do
    {:ok, event} = message(a, r.id, "sticker-target")
    key = "sticker:https://images.example.test/" <> String.duplicate("a", 160) <> ".gif?size=200"
    params = %{"event_id" => event["event_id"], "key" => key, "active" => true, "txn_id" => "sticker-add"}
    assert {:ok, first} = RiverContent.reaction(a, r.id, params)
    assert {:ok, ^first} = RiverContent.reaction(a, r.id, params)
    assert {:ok, _} = RiverContent.reaction(b, r.id, %{params | "txn_id" => "sticker-b"})
    assert [%{key: ^key, count: 2, mine: true}] = summary(a, r.id, event["event_id"])
    remove = %{params | "active" => false, "txn_id" => "sticker-remove"}
    assert {:ok, removed} = RiverContent.reaction(a, r.id, remove)
    assert [%{key: ^key, count: 1, mine: false}] = summary(a, r.id, event["event_id"])
    assert {:ok, _} = RiverContent.reaction(a, r.id, %{params | "txn_id" => "sticker-readd"})
    assert {:ok, ^removed} = RiverContent.reaction(a, r.id, remove)
    assert [%{count: 2}] = summary(a, r.id, event["event_id"])
    for invalid <- ["sticker:file:///secret", "sticker:javascript:alert(1)", "sticker:https://u:p@host/x.gif", "sticker:https://host/a b.gif", "sticker:https://host/" <> String.duplicate("a", 2048)] do
      assert {:error, :invalid_event} = RiverContent.reaction(a, r.id, %{params | "key" => invalid, "txn_id" => "invalid-sticker"})
    end
  end

  test "nested thread replies keep standard root and quoted-parent relations", %{ga: a, gb: b, room: r} do
    {:ok, root} = message(a, r.id, "root", "Original")
    {:ok, first} = DelegatedGroups.send(b, r.id, "m.room.message", "reply", %{"body" => "Reply",
      "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => root["event_id"], "m.in_reply_to" => %{"event_id" => root["event_id"]}}})
    {:ok, _} = DelegatedGroups.send(a, r.id, "m.room.message", "nested", %{"body" => "Nested reply",
      "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => root["event_id"], "m.in_reply_to" => %{"event_id" => first["event_id"]}}})
    assert {:ok, %{root: rendered, events: replies}} = RiverContent.thread(a, r.id, %{"event_id" => root["event_id"]})
    assert rendered["reply_count"] == 2
    assert length(replies) == 2
    assert {:ok, %{root: canonical}} = RiverContent.thread(a, r.id, %{"event_id" => first["event_id"]})
    assert canonical["event_id"] == root["event_id"]
    assert {:error, :invalid_relation} = DelegatedGroups.send(a, r.id, "m.room.message", "noncanonical-root", %{"body" => "Invalid",
      "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => first["event_id"]}})
    assert {:error, :invalid_relation} = DelegatedGroups.send(a, r.id, "m.room.message", "missing-root", %{"body" => "Invalid",
      "m.relates_to" => %{"rel_type" => "m.thread", "m.in_reply_to" => %{"event_id" => root["event_id"]}}})
    {:ok, unrelated} = message(a, r.id, "unrelated", "Another thread")
    assert {:error, :invalid_relation} = DelegatedGroups.send(a, r.id, "m.room.message", "unrelated-parent", %{"body" => "Invalid",
      "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => root["event_id"], "m.in_reply_to" => %{"event_id" => unrelated["event_id"]}}})
    assert {:error, :invalid_relation} = DelegatedGroups.send(a, r.id, "m.room.message", "foreign-parent", %{"body" => "Invalid",
      "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => root["event_id"], "m.in_reply_to" => %{"event_id" => "$foreign"}}})
  end

  test "entry edits require the original author and retain the immutable source", %{ga: a, gb: b, room: r} do
    {:ok, post} = DelegatedGroups.send(a, r.id, "cool.gravitas.river.post.v1", "post", %{"version" => 1, "title" => "Before", "body" => "Original"})
    params = %{"event_id" => post["event_id"], "txn_id" => "edit", "title" => "After", "body" => "Edited"}
    assert {:error, :forbidden} = RiverContent.edit(b, r.id, params)
    assert {:ok, edit} = RiverContent.edit(a, r.id, params)
    assert {:ok, ^edit} = RiverContent.edit(a, r.id, params)
    assert Repo.get_by!(RoomEvent, event_id: post["event_id"]).content["body"] == "Original"
    {:ok, %{events: events}} = DelegatedGroups.timeline(a, r.id, %{})
    projected = Enum.find(events, &(&1["event_id"] == post["event_id"]))
    assert projected["content"]["body"] == "Original"
    assert projected["rendered_content"]["body"] == "Edited"
    assert projected["edited"]
    {:ok, %{recent: recent}} = DelegatedGroups.overview(a)
    assert Enum.find(recent, &(&1["event_id"] == post["event_id"]))["rendered_content"]["title"] == "After"
    assert {:error, :transaction_conflict} = RiverContent.edit(a, r.id, %{params | "body" => "Conflicting"})
  end

  test "thread and reaction endpoints cannot cross room ACL or event ownership", %{ga: a, gb: b, room: r} do
    {:ok, private} = DelegatedGroups.create(a, %{"name" => "Private", "kind" => "dm", "txn_id" => "private"})
    {:ok, target} = message(a, private.id, "target")
    assert {:error, :forbidden} = RiverContent.thread(b, private.id, %{"event_id" => target["event_id"]})
    assert {:error, :invalid_relation} = RiverContent.thread(b, r.id, %{"event_id" => target["event_id"]})
    assert {:error, :invalid_relation} = react(b, r.id, target["event_id"], false, "foreign")
    assert {:error, :insufficient_scope} = RiverContent.thread(%{a | scopes: []}, r.id, %{"event_id" => "$anything"})
    {:ok, _} = DelegatedGroups.membership(b, r.id, %{"action" => "leave"})
    assert {:error, :forbidden} = RiverContent.reaction(b, r.id, %{"event_id" => target["event_id"], "key" => "👍", "active" => true, "txn_id" => "left"})
  end

  test "history pages stay within relay budgets without skipping large events", %{ga: a, room: r} do
    for n <- 1..70 do
      {:ok, _} = DelegatedGroups.send(a, r.id, "cool.gravitas.river.post.v1", "large#{n}",
        %{"version" => 1, "title" => "Post #{n}", "body" => String.duplicate("x", 16000)})
    end
    {:ok, overview} = DelegatedGroups.overview(a)
    assert byte_size(Jason.encode!(overview)) < 1_100_000
    {:ok, first} = DelegatedGroups.timeline(a, r.id, %{"limit" => 100})
    assert byte_size(Jason.encode!(first)) < 1_100_000
    assert is_binary(first.next_cursor)
    {:ok, second} = DelegatedGroups.timeline(a, r.id, %{"limit" => 100, "before" => first.next_cursor})
    posts = Enum.filter(first.events ++ second.events, &(&1["type"] == "cool.gravitas.river.post.v1"))
    assert length(posts) == 70
    assert length(Enum.uniq_by(posts, & &1["event_id"])) == 70
  end
end
