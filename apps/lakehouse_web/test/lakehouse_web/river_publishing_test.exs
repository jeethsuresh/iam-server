defmodule LakehouseWeb.RiverPublishingTest do
  use LakehouseWeb.ConnCase
  alias LakehouseIam.{Repo, Apps.Grants}
  alias LakehouseMatrix.{DelegatedGroups, RiverPublishing, RiverContent, Matrix, Memberships, Identity}
  alias LakehouseMatrix.Schema.RoomEvent
  alias LakehouseWeb.MatrixFixtures
  @scopes ~w(chats.list chats.read chats.write groups.create groups.manage groups.join spaces.channels posts.publish)
  setup do
    people = for name <- ~w(publishalice publishbob publishcarol), do: MatrixFixtures.user_fixture(name)
    [ga, gb, gc] = for p <- people do
      {:ok, g} = Grants.upsert(p.id, "https://chat.gravitas.cool", @scopes, :all, [])
      g
    end
    {:ok, room} = DelegatedGroups.create(ga, %{"name" => "Members", "kind" => "space", "txn_id" => "space"})
    [_, b, _] = people
    {:ok, _} = DelegatedGroups.membership(ga, room.id, %{"action" => "invite", "user_id" => Identity.user_id(b.username)})
    {:ok, _} = DelegatedGroups.membership(gb, room.id, %{"action" => "accept"})
    {:ok, post} = DelegatedGroups.send(ga, room.id, "cool.gravitas.river.post.v1", "post", %{"version" => 1, "title" => "Private title", "body" => "Private draft"})
    %{people: people, grants: [ga, gb, gc], room: room.id, post: post["event_id"]}
  end
  defp publish(g, room, post, comments \\ "public", txn \\ "publish"), do: RiverPublishing.policy(g, room, %{"event_id" => post, "visibility" => "public", "comments_policy" => comments, "txn_id" => txn})
  test "publishing uses the rendered post and never exposes private history", %{grants: [ga, gb, _], room: room, post: post} do
    {:ok, _} = DelegatedGroups.send(gb, room, "m.room.message", "secret", %{"body" => "Private comment", "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => post}})
    assert {:error, :not_found} = RiverPublishing.show(nil, post)
    {:ok, _} = RiverContent.edit(ga, room, %{"event_id" => post, "title" => "Public title", "body" => "Publish this", "txn_id" => "edit"})
    assert {:ok, %{publication: p}} = publish(ga, room, post)
    refute p["thread_id"] == room
    assert {:ok, response} = RiverPublishing.show(nil, post)
    assert response.entry["content"]["body"] == "Publish this"
    assert response.comments == []
    refute Jason.encode!(response) =~ "Private"
    assert {:ok, member} = RiverPublishing.show(gb, post)
    assert hd(member.comments)["content"]["body"] == "Private comment"
    assert {:ok, %{posts: [item]}} = RiverPublishing.blog(nil, room, %{})
    assert item.title == "Public title"
  end
  test "outsider comments are isolated, nested, idempotent and cannot quote private events", %{grants: [ga, gb, gc], room: room, post: post} do
    {:ok, %{publication: policy}} = publish(ga, room, post)
    params = %{"body" => "Public comment", "txn_id" => "public-comment"}
    assert {:ok, first} = RiverPublishing.comment(gc, post, params)
    assert {:ok, ^first} = RiverPublishing.comment(gc, post, params)
    assert Memberships.joined?(policy["thread_id"], gc.principal_id)
    refute Memberships.joined?(room, gc.principal_id)
    assert {:ok, second} = RiverPublishing.comment(gb, post, %{"body" => "Nested", "audience"=>"public", "parent_id" => first["event_id"], "txn_id" => "nested"})
    assert get_in(second, ["content", "m.relates_to", "event_id"]) == policy["anchor_id"]
    assert {:ok, result} = RiverPublishing.show(nil, post)
    assert length(result.comments) == 2
    assert {:error, :forbidden} = DelegatedGroups.timeline(gc, room, %{})
    {:ok, private} = DelegatedGroups.send(gb, room, "m.room.message", "private-reply", %{"body" => "Secret", "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => post}})
    assert {:error, _} = RiverPublishing.comment(gc, post, %{"body" => "Quote private", "parent_id" => private["event_id"], "txn_id" => "forged"})
    assert {:error, :invalid_cursor} = RiverPublishing.show(nil, post, %{"before" => private["event_id"]})
    assert {:ok, _} = RiverPublishing.reaction(gc, post, %{"key" => "👍", "active" => true, "txn_id" => "react"})
    assert {:ok, %{reaction_summary: [%{count: 1}]}} = RiverPublishing.show(nil, post)
  end

  test "a saved members-only post persists its public comment room when published", %{grants: [ga, gb, gc], room: room, post: post} do
    # River's editor always saves an initial publication policy, even for a
    # private post. Publishing later must update this existing database row.
    assert {:ok, _} = RiverPublishing.policy(ga, room, %{"event_id" => post,
      "visibility" => "members", "comments_policy" => "members", "txn_id" => "save-private"})
    assert is_nil(Repo.get!(LakehouseMatrix.Schema.RiverPublication, post).thread_id)
    assert {:ok, _} = RiverPublishing.comment(gb, post, %{"body" => "Earlier private comment",
      "audience" => "members", "txn_id" => "private-before-publication"})

    assert {:ok, %{publication: policy}} = publish(ga, room, post)
    assert is_binary(policy["thread_id"]) and policy["thread_id"] != room
    assert is_binary(policy["anchor_id"])
    stored = Repo.get!(LakehouseMatrix.Schema.RiverPublication, post)
    assert stored.thread_id == policy["thread_id"]
    assert stored.anchor_id == policy["anchor_id"]
    assert {:ok, comment} = RiverPublishing.comment(gc, post, %{"body" => "Outside public comment",
      "audience" => "public", "txn_id" => "public-after-private"})
    assert get_in(comment, ["content", "m.relates_to", "event_id"]) == stored.anchor_id
    assert {:ok, _} = RiverPublishing.reaction(gc, post, %{"key" => "👍", "active" => true, "txn_id" => "public-after-private-reaction"})
    assert {:ok, response} = RiverPublishing.show(nil, post)
    assert length(response.comments) == 1
    assert hd(response.comments)["content"]["body"] == "Outside public comment"
    refute Jason.encode!(response) =~ "Earlier private comment"
    assert [%{key: "👍", count: 1}] = response.reaction_summary

    assert {:ok, %{publication: same}} = publish(ga, room, post, "public", "publish-again")
    assert same["thread_id"] == stored.thread_id and same["anchor_id"] == stored.anchor_id
    refute Memberships.joined?(room, gc.principal_id)
  end
  test "author permissions, members-only comments, disabling and unpublishing are enforced on every write path", %{grants: [ga, gb, gc], room: room, post: post} do
    assert {:error, :forbidden} = publish(gb, room, post)
    assert {:error, :insufficient_scope} = publish(%{ga | scopes: ga.scopes -- ["posts.publish"]}, room, post)
    assert {:ok, %{publication: p}} = publish(ga, room, post, "members")
    assert {:error, :forbidden} = RiverPublishing.comment(gc, post, %{"body" => "No", "txn_id" => "no"})
    assert {:ok, _} = RiverPublishing.comment(gb, post, %{"body" => "Members", "txn_id" => "members"})
    assert {:ok, _} = RiverPublishing.reaction(gc, post, %{"key" => "👍", "active" => true, "txn_id" => "restricted-reaction"})
    assert {:error, :forbidden} = DelegatedGroups.timeline(gc, p["thread_id"], %{})
    assert {:ok, _} = publish(ga, room, post, "public", "temporarily-open")
    assert {:ok, _} = RiverPublishing.comment(gc, post, %{"body" => "Was public", "txn_id" => "before-restrict"})
    assert {:ok, _} = publish(ga, room, post, "disabled", "disable")
    assert {:error, :forbidden} = DelegatedGroups.timeline(gc, p["thread_id"], %{})
    assert {:error, _} = Matrix.room_messages(gc.principal_id, p["thread_id"]) |> then(fn v -> if v["errcode"] == "M_FORBIDDEN", do: {:error,:forbidden}, else: {:ok,v} end)

    assert {:error, :forbidden} = RiverPublishing.comment(gb, post, %{"body" => "No", "txn_id" => "disabled"})
    assert {:error, :invalid_relation} = Matrix.send_message(gb.principal_id, room, "matrix-bypass", %{"body" => "No", "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => post}})
    assert {:ok, _} = publish(ga, room, post, "public", "reopen")
    assert {:ok, _} = RiverPublishing.comment(gc, post, %{"body" => "Public", "txn_id" => "public"})
    assert {:ok, _} = RiverPublishing.policy(ga, room, %{"event_id" => post, "visibility" => "members", "comments_policy" => "members", "txn_id" => "unpublish"})
    assert {:error, :not_found} = RiverPublishing.show(nil, post)
    refute Memberships.joined?(p["thread_id"], gc.principal_id)
    assert {:error, _} = DelegatedGroups.send(gc, p["thread_id"], "m.room.message", "late", %{"body" => "No", "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => p["anchor_id"]}})
    assert {:ok, _} = publish(ga, room, post, "members")
    assert {:error, :not_found} = RiverPublishing.show(nil, post)
    assert Repo.get_by!(RoomEvent, event_id: post).content["body"] == "Private draft"
  end
  test "post feeds and combined comment pages retain older content without exposing private cursors", %{grants: [ga, gb, gc], room: room, post: post} do
    {:ok, _} = publish(ga, room, post)
    for n <- 1..103 do
      {:ok, _} = RiverPublishing.comment(gc, post, %{"body" => "Comment #{n}", "txn_id" => "page-#{n}"})
    end
    {:ok, first} = RiverPublishing.show(nil, post)
    assert length(first.comments) == 100 and is_binary(first.next_cursor)
    {:ok, second} = RiverPublishing.show(nil, post, %{"before" => first.next_cursor})
    assert length(second.comments) == 3 and is_nil(second.next_cursor)
    assert MapSet.disjoint?(MapSet.new(first.comments, & &1["event_id"]), MapSet.new(second.comments, & &1["event_id"]))
    for n <- 1..105 do
      {:ok, _} = DelegatedGroups.send(gb,room,"m.room.message","chat-#{n}",%{"body" => "Chat #{n}"})
    end
    assert {:ok, %{events: [%{"event_id" => ^post}], next_cursor: nil}} = RiverContent.entries(gb,room,%{"kind"=>"post"})
    assert {:error, :forbidden} = RiverContent.entries(gc,room,%{"kind"=>"post"})
  end

  test "editing public content still requires the explicit publish permission", %{grants: [ga | _], room: room, post: post} do
    {:ok, _} = publish(ga,room,post)
    params=%{"event_id"=>post,"title"=>"Edit","body"=>"New public content","txn_id"=>"scope-edit"}
    assert {:error, :insufficient_scope} = RiverContent.edit(%{ga | scopes: ga.scopes -- ["posts.publish"]},room,params)
    assert {:ok, _} = RiverPublishing.policy(%{ga | scopes: ga.scopes -- ["posts.publish"]},room,%{"event_id"=>post,"visibility"=>"members","comments_policy"=>"members","txn_id"=>"private-first"})
    assert {:ok, _} = RiverContent.edit(%{ga | scopes: ga.scopes -- ["posts.publish"]},room,params)
    assert {:error, :not_found} = RiverPublishing.show(nil,post)
  end

  test "an explicit member draft never becomes public when the comment policy changes", %{grants: [ga, gb, gc],room: room,post: post} do
    {:ok, _} = publish(ga,room,post,"members")
    {:ok, _} = publish(ga,room,post,"public","broaden")
    assert {:ok, private} = RiverPublishing.comment(gb,post,%{"body"=>"Member draft","audience"=>"members","txn_id"=>"private-draft"})
    assert {:ok, outside} = RiverPublishing.show(nil,post)
    refute Jason.encode!(outside) =~ "Member draft"
    {:ok, public} = RiverPublishing.comment(gc,post,%{"body"=>"Public parent","audience"=>"public","txn_id"=>"public-parent"})
    {:ok, _} = publish(ga,room,post,"members","restrict")
    assert {:error,:forbidden} = RiverPublishing.comment(gb,post,%{"body"=>"Public draft","audience"=>"public","txn_id"=>"public-draft"})
    assert {:ok, nested} = RiverPublishing.comment(gb,post,%{"body"=>"Private follow-up","audience"=>"members","parent_id"=>public["event_id"],"txn_id"=>"private-nested"})
    assert nested["content"]["cool.gravitas.river.reply"]["event_id"] == public["event_id"]
    assert nested["content"]["m.relates_to"]["event_id"] == post
    assert Repo.get_by!(RoomEvent, event_id: private["event_id"]).room_id == room
  end

  test "post feed and detail share canonical reactions and include public comment counts", %{grants: [ga, gb, gc], room: room, post: post} do
    {:ok, _} = RiverPublishing.reaction(gb, post, %{"key"=>"❤️", "active"=>true, "txn_id"=>"private-react"})
    {:ok, _} = publish(ga, room, post)
    {:ok, _} = RiverPublishing.reaction(gc, post, %{"key"=>"👍", "active"=>true, "txn_id"=>"public-react"})
    {:ok, _} = RiverPublishing.comment(gc, post, %{"body"=>"Public reply", "audience"=>"public", "txn_id"=>"public-reply"})
    {:ok, _} = RiverPublishing.comment(gb, post, %{"body"=>"Private reply", "audience"=>"members", "txn_id"=>"private-reply"})
    {:ok, %{events: [feed]}} = RiverContent.entries(gb, room, %{"kind"=>"post"})
    {:ok, detail} = RiverPublishing.show(gb, post)
    assert feed["reaction_summary"] == detail.reaction_summary
    assert feed["reply_count"] == 2
    assert [%{key: "👍", count: 1}] = detail.reaction_summary
    {:ok, outside} = RiverPublishing.show(nil, post)
    assert length(outside.comments) == 1
    refute Jason.encode!(outside) =~ "Private reply"
    refute Jason.encode!(outside) =~ "❤️"
    {:ok, _} = RiverPublishing.policy(ga, room, %{"event_id"=>post,"visibility"=>"members","comments_policy"=>"members","txn_id"=>"hide-post"})
    {:ok, private} = RiverPublishing.show(gb, post)
    assert [%{key: "❤️", count: 1}] = private.reaction_summary
    assert {:error, :not_found} = RiverPublishing.show(nil, post)
  end

end
