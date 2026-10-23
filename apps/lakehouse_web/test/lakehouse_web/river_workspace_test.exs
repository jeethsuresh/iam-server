defmodule LakehouseWeb.RiverWorkspaceTest do
  use LakehouseWeb.ConnCase
  import Ecto.Query
  alias LakehouseIam.{Contacts, Changes, Repo, Apps.Grants}
  alias LakehouseMatrix.{DelegatedGroups, RiverWorkspace, Identity, Memberships}
  alias LakehouseMatrix.Schema.RoomEvent
  alias LakehouseWeb.MatrixFixtures
  @scopes ~w(chats.list chats.read chats.write groups.create groups.manage groups.join spaces.channels contacts.read contacts.manage)
  setup do
    people = for name <- ~w(workalice workbob workcarol workoutsider), do: MatrixFixtures.user_fixture(name)
    grants = for p <- people do
      {:ok, grant} = Grants.upsert(p.id, "https://chat.gravitas.cool", @scopes, :all, [])
      grant
    end
    [a, b, c, _] = people
    for peer <- [b, c] do
      {:ok, _} = Contacts.owner_act(a.id, %{"username" => peer.username, "action" => "request", "txn_id" => "request-#{peer.username}"})
      {:ok, _} = Contacts.owner_act(peer.id, %{"username" => a.username, "action" => "accept", "txn_id" => "accept"})
    end
    %{people: people, grants: grants}
  end
  test "friend-selected groups are idempotent and retain Matrix invite acceptance", %{people: [a, b, c, _], grants: [ga, gb, _, _]} do
    params = %{"name" => "Study group", "member_ids" => Enum.map([b,c], &Identity.user_id(&1.username)), "txn_id" => "group"}
    assert {:ok, room} = RiverWorkspace.conversation(ga, params)
    assert room.kind == "group"
    assert Memberships.membership(room.id, a.id) == "join"
    assert Memberships.membership(room.id, b.id) == "invite"
    assert {:ok, retry} = RiverWorkspace.conversation(ga, params)
    assert room.id == retry.id
    assert {:ok, _} = DelegatedGroups.membership(gb, room.id, %{"action" => "accept"})
    assert Memberships.membership(room.id, b.id) == "join"
    assert {:error, :transaction_conflict} = RiverWorkspace.conversation(ga, %{params | "name" => "Changed"})
  end
  test "unaccepted friends, missing scopes and blocked people cannot be added", %{people: [a, b, _, outsider], grants: [ga, _, _, _]} do
    params = %{"name" => "Group", "member_ids" => Enum.map([b, outsider], &Identity.user_id(&1.username)), "txn_id" => "unauthorized"}
    assert {:error, :forbidden} = RiverWorkspace.conversation(ga, params)
    assert {:error, :invalid_request} = RiverWorkspace.conversation(%{ga | scopes: []}, params)
    {:ok, _} = Contacts.owner_act(a.id, %{"username" => b.username, "action" => "block", "txn_id" => "block"})
    assert {:error, :forbidden} = RiverWorkspace.conversation(ga, %{params | "member_ids" => [Identity.user_id(b.username)]})
  end
  test "invitation cards require both ACLs and never autojoin recipients", %{people: [_, b, _, _], grants: [ga, gb, _, go]} do
    {:ok, dm} = DelegatedGroups.direct(ga, %{"user_id" => Identity.user_id(b.username)})
    {:ok, space} = DelegatedGroups.create(ga, %{"name" => "Workshop", "kind" => "space", "description" => "A place to build", "txn_id" => "space"})
    params = %{"space_id" => space.id, "txn_id" => "invitation"}
    assert {:ok, card} = RiverWorkspace.invite(ga, dm.id, params)
    assert card["type"] == "cool.gravitas.river.invitation.v1"
    assert Memberships.membership(space.id, b.id) == "invite"
    assert {:ok, ^card} = RiverWorkspace.invite(ga, dm.id, params)
    assert {:error, :forbidden} = RiverWorkspace.invite(go, dm.id, params)
    assert {:ok, _} = DelegatedGroups.membership(gb, space.id, %{"action" => "accept"})
    {:ok, %{channels: channels}} = DelegatedGroups.channels(gb, space.id)
    assert length(channels) == 2
    assert Enum.all?(channels, &(&1.membership == "join"))
    assert Enum.find(DelegatedGroups.list(ga), &(&1.id == space.id)).description == "A place to build"
  end
  test "catch-up reads are independent per entry and per user; participating old threads remain discoverable", %{grants: [ga, gb, _, _], people: [_, b, _, _]} do
    {:ok, dm} = DelegatedGroups.direct(ga, %{"user_id" => Identity.user_id(b.username)})
    {:ok, _} = DelegatedGroups.membership(gb, dm.id, %{"action" => "accept"})
    {:ok, post} = DelegatedGroups.send(ga, dm.id, "cool.gravitas.river.post.v1", "post", %{"version" => 1, "title" => "News", "body" => "Read this"})
    {:ok, _} = DelegatedGroups.send(gb, dm.id, "m.room.message", "reply", %{"body" => "Following", "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => post["event_id"]}})
    {:ok, home} = RiverWorkspace.home(gb)
    assert Enum.any?(home.catch_up, &(&1["event_id"] == post["event_id"]))
    assert Enum.any?(home.threads, &(&1["event_id"] == post["event_id"]))
    assert {:ok, _} = RiverWorkspace.read_entry(gb, dm.id, %{"event_id" => post["event_id"]})
    {:ok, home} = RiverWorkspace.home(gb)
    assert home.catch_up == []
    assert length(home.threads) == 1
    assert Repo.get_by!(RoomEvent, event_id: post["event_id"]).content["body"] == "Read this"
    {:ok, _} = DelegatedGroups.membership(gb, dm.id, %{"action" => "leave"})
    assert {:error, :forbidden} = RiverWorkspace.read_entry(gb, dm.id, %{"event_id" => post["event_id"]})
    {:ok, home} = RiverWorkspace.home(gb)
    assert home.threads == []
  end
  test "presence is origin scoped and bounded", %{people: [a | _]} do
    assert :ok = Changes.subscribe(a.id, "https://chat.gravitas.cool")
    assert Changes.online?(a.id, "https://chat.gravitas.cool")
    refute Changes.online?(a.id, "https://other.gravitas.cool")
    for _ <- 1..7, do: assert(:ok == Changes.subscribe(a.id, "https://chat.gravitas.cool"))
    assert {:error, :too_many_connections} = Changes.subscribe(a.id, "https://chat.gravitas.cool")
  end
  test "catch-up excludes acknowledged entries before applying its page bound", %{grants: [ga, gb | _], people: [_, b | _]} do
    {:ok, dm} = DelegatedGroups.direct(ga,%{"user_id" => Identity.user_id(b.username)})
    {:ok, _} = DelegatedGroups.membership(gb,dm.id,%{"action"=>"accept"})
    posts = for n <- 1..201 do
      {:ok, post} = DelegatedGroups.send(ga,dm.id,"cool.gravitas.river.post.v1","catchup-#{n}",%{"version"=>1,"title"=>"Entry #{n}","body"=>"Body"})
      post["event_id"]
    end
    for id <- Enum.drop(posts,1), do: Repo.insert!(%LakehouseMatrix.Schema.RiverEntryRead{principal_id: gb.principal_id,event_id: id})
    {:ok, home} = RiverWorkspace.home(gb)
    assert Enum.map(home.catch_up,& &1["event_id"]) == [hd(posts)]
  end
  test "Unicode titles and descriptions use character limits with a bounded byte budget", %{grants: [ga | _]} do
    title = String.duplicate("🌊",80)
    {:ok, space} = DelegatedGroups.create(ga,%{"name"=>title,"kind"=>"space","txn_id"=>"unicode","description"=>String.duplicate("🌊",500)})
    assert space.name == title
    assert {:ok, _} = DelegatedGroups.send(ga,space.id,"cool.gravitas.river.post.v1","unicode-post",%{"version"=>1,"title"=>String.duplicate("🌊",160),"body"=>String.duplicate("🌊",40000)})
  end

  test "authored roots count as participation and sidebar activity is capped per room", %{grants: [ga, gb | _], people: [_, b | _]} do
    {:ok, dm} = DelegatedGroups.direct(ga, %{"user_id" => Identity.user_id(b.username)})
    {:ok, _} = DelegatedGroups.membership(gb, dm.id, %{"action" => "accept"})
    for n <- 1..9 do
      {:ok, root} = DelegatedGroups.send(ga, dm.id, "m.room.message", "root-#{n}", %{"body" => "Root #{n}"})
      {:ok, _} = DelegatedGroups.send(gb, dm.id, "m.room.message", "reply-#{n}", %{"body" => "Following", "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => root["event_id"]}})
    end
    {:ok, home} = RiverWorkspace.home(ga)
    assert length(home.threads) == 7
    old = DateTime.add(DateTime.utc_now(), -48 * 3600, :second)
    Repo.update_all(Ecto.Query.from(e in RoomEvent, where: e.room_id == ^dm.id), set: [inserted_at: old])
    {:ok, home} = RiverWorkspace.home(ga)
    assert length(home.threads) == 5
    old = DateTime.add(DateTime.utc_now(), -73 * 3600, :second)
    Repo.update_all(Ecto.Query.from(e in RoomEvent, where: e.room_id == ^dm.id), set: [inserted_at: old])
    {:ok, home} = RiverWorkspace.home(ga)
    assert home.threads == []
  end

end
