defmodule LakehouseMatrix.RiverPublishing do
  @moduledoc "Explicit post publication. Public discussion has a separate Gravitas group so private space history never becomes public."
  import Ecto.Query
  alias LakehouseIam.{Repo, Contacts}
  alias LakehouseIam.Schema.AppGrant
  alias LakehouseMatrix.{DelegatedGroups, Memberships, Identity, RiverContent}
  alias LakehouseMatrix.Schema.{RiverPublication, RoomEvent, Room}
  @post "cool.gravitas.river.post.v1"
  @policy "cool.gravitas.river.publication.v1"
  @defaults %{"visibility" => "members", "comments_policy" => "members"}
  def summaries(ids), do: Repo.all(from p in RiverPublication, where: p.id in ^ids) |> Map.new(&{&1.id, summary(&1)})
  def thread_record(id), do: Repo.get_by(RiverPublication, thread_id: id)
  def public_join?(id) do
    case thread_record(id) do
      %{visibility: "public"} -> true
      _ -> false
    end
  end
  def reader_allowed?(id, actor) do
    case thread_record(id) do
      nil -> true
      p -> Memberships.joined?(p.space_id, actor) or (p.visibility == "public" and p.comments_policy == "public")
    end
  end
  def writer_allowed?(id, actor) do
    case thread_record(id) do
      nil -> true
      p -> (p.visibility == "public" or Memberships.joined?(p.space_id, actor)) and not Contacts.blocked?(p.author_id, actor)
    end
  end
  def valid_send?(room, type, content, actor) do
    case thread_record(room) do
      nil -> true
      p ->
        if type == "m.room.message" do
          p.comments_policy != "disabled" and (p.comments_policy == "public" or Memberships.joined?(p.space_id, actor)) and
            get_in(content, ["m.relates_to", "rel_type"]) == "m.thread" and get_in(content, ["m.relates_to", "event_id"]) == p.anchor_id
        else
          type == "m.reaction"
        end
    end
  end
  def replies_allowed?(%{type: @post, event_id: id}) do
    case Repo.get(RiverPublication, id) do
      %{comments_policy: "disabled"} -> false
      _ -> true
    end
  end
  def replies_allowed?(_), do: true

  def policy(g, room, p) do
    locked_grant(g, fn ->
    unwrap!(DelegatedGroups.with_room(g, room, "chats.write", fn ->
      original = post!(p["event_id"])
      unless original.room_id == room and original.principal_id == g.principal_id, do: Repo.rollback(:forbidden)
      unless p["visibility"] in ~w(members public) and p["comments_policy"] in ~w(members public disabled) and txn?(p["txn_id"]), do: Repo.rollback(:invalid_request)
      if p["comments_policy"] == "public" and p["visibility"] != "public", do: Repo.rollback(:invalid_request)
      if p["visibility"] == "public" and "posts.publish" not in g.scopes, do: Repo.rollback(:insufficient_scope)
      content = %{"version" => 1, "visibility" => p["visibility"], "comments_policy" => p["comments_policy"],
        "m.relates_to" => %{"rel_type" => "m.reference", "event_id" => original.event_id}}
      action_id = "$river_content_" <> digest("#{g.principal_id}|#{g.app_origin}|#{room}|#{@policy}|#{p["txn_id"]}")
      previous = Repo.get_by(RoomEvent, event_id: action_id)
      action = DelegatedGroups.content_event!(g, room, @policy, content, p["txn_id"])
      unless previous do
        publication = Repo.get(RiverPublication, original.event_id) || %RiverPublication{id: original.event_id, space_id: room, author_id: g.principal_id}
        prepared = if p["visibility"] == "public" and is_nil(publication.thread_id), do: create_thread!(g, publication, original), else: publication
        # Keep the loaded record unchanged until the changeset tracks new room
        # IDs. Mutating its data first makes Repo.update ignore those fields.
        attrs = %{visibility: p["visibility"], comments_policy: p["comments_policy"],
          thread_id: prepared.thread_id, anchor_id: prepared.anchor_id}
        publication = if Ecto.get_meta(publication, :state) == :built do
          Ecto.Changeset.change(publication, attrs) |> Repo.insert!()
        else
          Ecto.Changeset.change(publication, attrs) |> Repo.update!()
        end
        if publication.thread_id do
          public = p["visibility"] == "public"
          DelegatedGroups.template_state!(g, publication.thread_id, "m.room.join_rules", %{"join_rule" => if(public, do: "public", else: "invite")}, "")
          DelegatedGroups.template_state!(g, publication.thread_id, "m.room.history_visibility", %{"history_visibility" => if(public and p["comments_policy"] == "public", do: "world_readable", else: "joined")}, "")
          unless public do
            for {principal, status} <- Memberships.membership_map(publication.thread_id), status in ["join", "invite"], not Memberships.joined?(room, principal) do
              DelegatedGroups.template_state!(g, publication.thread_id, "m.room.member", %{"membership" => "leave"}, mxid(principal))
            end
          end
        end
      end
      %{event_id: action["event_id"], publication: summary(Repo.get!(RiverPublication, original.event_id))}
    end))
    end)
  end
  defp create_thread!(g, publication, original) do
    unless "groups.create" in g.scopes, do: Repo.rollback(:insufficient_scope)
    projected = hd(RiverContent.decorate([original], g.principal_id))
    name = ((projected["rendered_content"] || projected["content"])["title"]) |> String.slice(0, 65)
    group = unwrap!(DelegatedGroups.create(g, %{"kind" => "post_comments", "name" => "Post: " <> name, "txn_id" => "publish-" <> digest(original.event_id)}, true))
    anchor = DelegatedGroups.content_event!(g, group.id, "m.room.message", %{"body" => "Comments on " <> name, "msgtype" => "m.text",
      "cool.gravitas.river.post" => %{"version" => 1, "room_id" => Identity.room_id(original.room_id), "event_id" => original.event_id}}, "post-anchor")
    %{publication | thread_id: group.id, anchor_id: anchor["event_id"]}
  end

  def show(g, event, params \\ %{}) do
    Repo.transaction(fn ->
      original = post!(event)
      Repo.one(from r in Room, where: r.id == ^original.room_id, lock: "FOR SHARE") || Repo.rollback(:not_found)
      publication = Repo.get(RiverPublication, event)
      member = member?(g, original.room_id)
      unless member or (publication && publication.visibility == "public"), do: Repo.rollback(:not_found)
      actor = if g, do: g.principal_id, else: "00000000-0000-0000-0000-000000000000"
      projected = hd(RiverContent.decorate([original], actor))
      content = projected["rendered_content"] || projected["content"]
      public_event = projected |> Map.take(~w(event_id type sender origin_server_ts edited)) |> Map.put("content", Map.take(content, ~w(version title body)))
      targets = if member, do: [{original.room_id, original.event_id, "members"}], else: []
      targets = if publication && publication.thread_id && (member or publication.comments_policy == "public"),
        do: targets ++ [{publication.thread_id, publication.anchor_id, "public"}], else: targets
      {comments, cursor} = comments_page(targets, actor, params)
      reactions = projected["reaction_summary"]
      policy = if publication, do: summary(publication), else: @defaults
      %{entry: public_event, space: %{id: original.room_id, name: LakehouseMatrix.Rooms.get_room(original.room_id).name},
        publication: policy, comments: comments, next_cursor: cursor, reaction_summary: reactions, member: member,
        can_comment: not is_nil(g) and "chats.write" in g.scopes and policy["comments_policy"] != "disabled" and (member or (policy["visibility"] == "public" and policy["comments_policy"] == "public")),
        can_view_comments: member or policy["comments_policy"] == "public"}
    end)
  end
  def comment(g, event, p) do
    original = Repo.get_by(RoomEvent, event_id: event)
    if is_nil(original) or original.type != @post do
      {:error, :not_found}
    else
      locked_grant(g, fn ->
        Repo.one(from r in Room, where: r.id == ^original.room_id, lock: "FOR UPDATE") || Repo.rollback(:not_found)
        publication = Repo.get(RiverPublication, event)
        policy = if publication, do: summary(publication), else: @defaults
        member = member?(g, original.room_id)
        unless policy["comments_policy"] != "disabled" and (member or (policy["visibility"] == "public" and policy["comments_policy"] == "public")), do: Repo.rollback(:forbidden)
        unless is_binary(p["body"]) and String.trim(p["body"]) != "" and byte_size(p["body"]) <= 64_000 and String.length(p["body"]) <= 16_000 and txn?(p["txn_id"]), do: Repo.rollback(:invalid_request)
        if Contacts.blocked?(original.principal_id, g.principal_id), do: Repo.rollback(:forbidden)
        parent = if is_binary(p["parent_id"]), do: Repo.get_by(RoomEvent, event_id: p["parent_id"])
        audience = p["audience"] || if(member, do: "members", else: "public")
        unless audience in ~w(members public), do: Repo.rollback(:invalid_request)
        public = audience == "public"
        if public and not (not is_nil(publication) and publication.visibility == "public" and policy["comments_policy"] == "public"), do: Repo.rollback(:forbidden)
        if not public and not member, do: Repo.rollback(:forbidden)
        room = if public, do: publication.thread_id, else: original.room_id
        root = if public, do: publication.anchor_id, else: original.event_id
        moved_parent = member and not public and not is_nil(parent) and not is_nil(publication) and parent.room_id == publication.thread_id and
          (parent.event_id == publication.anchor_id || get_in(parent.content, ["m.relates_to", "event_id"]) == publication.anchor_id)
        if parent && not moved_parent && (parent.room_id != room or (parent.event_id != root and get_in(parent.content, ["m.relates_to", "event_id"]) != root)), do: Repo.rollback(:invalid_relation)
        if is_binary(p["parent_id"]) and is_nil(parent), do: Repo.rollback(:invalid_relation)
        if public and not Memberships.joined?(room, g.principal_id), do: unwrap!(DelegatedGroups.membership(g, room, %{"action" => "public_join"}))
        refreshed = if public, do: %{g | room_ids: Enum.uniq(g.room_ids ++ [room])}, else: g
        content = %{"body" => p["body"], "msgtype" => "m.text", "cool.gravitas.river.comment" => %{"version" => 1, "post_event_id" => event, "audience" => audience},
          "m.relates_to" => %{"rel_type" => "m.thread", "event_id" => root, "is_falling_back" => false, "m.in_reply_to" => %{"event_id" => if(parent && not moved_parent, do: parent.event_id, else: root)}}}
        content = if moved_parent, do: Map.put(content, "cool.gravitas.river.reply", %{"version"=>1,"event_id"=>parent.event_id,"room_id"=>Identity.room_id(parent.room_id)}), else: content
        unwrap!(DelegatedGroups.send(refreshed, room, "m.room.message", p["txn_id"], content))
      end)
    end
  end
  def reaction(g, event, params) do
    locked_grant(g, fn ->
      original = post!(event)
      Repo.one(from r in Room, where: r.id == ^original.room_id, lock: "FOR UPDATE") || Repo.rollback(:not_found)
      p = Repo.get(RiverPublication, event)
      unless member?(g, original.room_id) or (p && p.visibility == "public"), do: Repo.rollback(:not_found)
      if Contacts.blocked?(original.principal_id, g.principal_id), do: Repo.rollback(:forbidden)
      room = if p && p.thread_id && p.visibility == "public", do: p.thread_id, else: original.room_id
      target = if p && p.thread_id && p.visibility == "public", do: p.anchor_id, else: event
      if not is_nil(p) and p.visibility == "public" and not Memberships.joined?(room, g.principal_id), do: unwrap!(DelegatedGroups.membership(g, room, %{"action" => "public_join"}))
      refreshed = if p && p.visibility == "public", do: %{g | room_ids: Enum.uniq(g.room_ids ++ [room])}, else: g
      unless "chats.write" in refreshed.scopes and LakehouseIam.IAM.can?(g.principal_id, "matrix.room.send", Identity.resource_arn(room)), do: Repo.rollback(:forbidden)
      RiverContent.reaction_authorized!(refreshed, room, Map.put(params, "event_id", target))
    end)
  end
  def blog(g, space, params) do
    with {:ok, _} <- Ecto.UUID.cast(space) do
      Repo.transaction(fn ->
        Repo.one(from r in Room, where: r.id == ^space, lock: "FOR SHARE") || Repo.rollback(:not_found)
        unwrap!(blog_query(g, space, params))
      end)
    else
      _ -> {:error, :not_found}
    end
  end
  defp blog_query(g, space, params) do
    with {:ok, _} <- Ecto.UUID.cast(space) do
      member = member?(g, space)
      query = from e in RoomEvent, left_join: p in RiverPublication, on: p.id == e.event_id,
        where: e.room_id == ^space and e.type == ^@post and (^member or p.visibility == "public"), order_by: [desc: e.inserted_at, desc: e.id], limit: 51
      query = if is_binary(params["before"]) do
        case Repo.one(from e in query, where: e.event_id == ^params["before"]) do
          nil -> from e in query, where: false
          cursor -> from e in query, where: e.inserted_at < ^cursor.inserted_at or (e.inserted_at == ^cursor.inserted_at and e.id < ^cursor.id)
        end
      else
        query
      end
      rows = Repo.all(query)
      if rows == [] and not member do
        {:error, :not_found}
      else
        posts = for row <- Enum.take(rows,50) do
          event = hd(RiverContent.decorate([row], if(g, do: g.principal_id, else: "00000000-0000-0000-0000-000000000000")))
          c = event["rendered_content"] || event["content"]
          %{event_id: row.event_id, title: c["title"], preview: String.slice(c["body"],0,300), sender: row.sender, created_at: row.origin_server_ts}
        end
        {:ok, %{space: %{id: space, name: LakehouseMatrix.Rooms.get_room(space).name}, posts: posts, next_cursor: if(length(rows)>50, do: Enum.at(rows,49).event_id)}}
      end
    else
      _ -> {:error, :not_found}
    end
  end
  defp comments_page(targets, actor, params) do
    condition = Enum.reduce(targets, dynamic(false), fn {room, root, _}, acc ->
      dynamic([e], ^acc or (e.room_id == ^room and e.type == "m.room.message" and
        (fragment("? #>> '{m.relates_to,event_id}'", e.content) == ^root or fragment("? #>> '{m.relates_to,m.in_reply_to,event_id}'", e.content) == ^root)))
    end)
    query = from e in RoomEvent, where: ^condition, order_by: [desc: e.inserted_at, desc: e.id]
    query = if is_binary(params["before"]) do
      cursor = Repo.one(from e in query, where: e.event_id == ^params["before"])
      unless cursor, do: Repo.rollback(:invalid_cursor)
      from e in query, where: e.inserted_at < ^cursor.inserted_at or (e.inserted_at == ^cursor.inserted_at and e.id < ^cursor.id)
    else
      query
    end
    rows = Repo.all(from e in query, limit: 101)
    projection = rows |> Enum.take(100) |> Enum.group_by(& &1.room_id) |> Enum.flat_map(fn {room, events} ->
      audience = Enum.find_value(targets, fn {id, _, a} -> if id == room, do: a end)
      for e <- RiverContent.decorate(events, actor), do: e |> Map.put("comment_room", room) |> Map.put("audience", audience)
    end) |> Map.new(&{&1["event_id"], &1})
    events = rows |> Enum.take(100) |> Enum.map(&projection[&1.event_id]) |> RiverContent.budget(600_000)
    cursor = if length(rows) > length(events), do: List.last(events)["event_id"]
    {Enum.reverse(events), cursor}
  end
  defp locked_grant(g, fun) do
    Repo.transaction(fn ->
      LakehouseMatrix.ClientStore.lock!()
      Repo.one(from a in AppGrant, where: a.id == ^g.id, lock: "FOR UPDATE") || Repo.rollback(:forbidden)
      fun.()
    end)
  end
  defp member?(nil, _), do: false
  defp member?(g, room), do: DelegatedGroups.authorized?(g, room, "chats.read")
  defp post!(event) when is_binary(event) and byte_size(event) <= 512 do
    Repo.get_by(RoomEvent, event_id: event, type: @post) || Repo.rollback(:not_found)
  end
  defp post!(_), do: Repo.rollback(:not_found)
  defp summary(p), do: %{"visibility" => p.visibility, "comments_policy" => p.comments_policy, "thread_id" => p.thread_id, "anchor_id" => p.anchor_id}
  defp mxid(id), do: Repo.get!(LakehouseIam.Schema.Principal, id).username |> Identity.user_id()
  defp unwrap!({:ok, value}), do: value
  defp unwrap!({:error, reason}), do: Repo.rollback(reason)
  defp digest(value), do: :crypto.hash(:sha256, value) |> Base.url_encode64(padding: false)
  defp txn?(v), do: is_binary(v) and String.match?(v, ~r/^[a-zA-Z0-9_-]{1,128}$/)
end
