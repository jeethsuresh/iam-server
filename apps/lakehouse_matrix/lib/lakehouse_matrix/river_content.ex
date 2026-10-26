defmodule LakehouseMatrix.RiverContent do
  @moduledoc "Thread views, author edits and reversible reactions over immutable Matrix events."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{DelegatedGroups, Events}
  alias LakehouseMatrix.Schema.RoomEvent

  @entry_types ~w(cool.gravitas.river.post.v1 cool.gravitas.river.discussion.v1)
  @edit "cool.gravitas.river.entry.edit.v1"
  @reaction_action "cool.gravitas.river.reaction.v1"

  def thread(g, id, p) do
    DelegatedGroups.with_room(g, id, "chats.read", fn ->
      root = target!(id, p["event_id"]) |> LakehouseMatrix.Erasure.record(g.principal_id)
      unless root.type in ["m.room.message" | @entry_types], do: Repo.rollback(:invalid_event)
      root = thread_root(id, root) |> LakehouseMatrix.Erasure.record(g.principal_id)
      unless root.type in ["m.room.message" | @entry_types], do: Repo.rollback(:invalid_event)

      query =
        from e in LakehouseMatrix.Erasure.event_query(g.principal_id),
          where:
            e.room_id == ^id and e.type == "m.room.message" and
              (fragment("? #>> '{m.relates_to,event_id}'", e.content) == ^root.event_id or
                 fragment("? #>> '{m.relates_to,m.in_reply_to,event_id}'", e.content) ==
                   ^root.event_id),
          order_by: [desc: e.inserted_at, desc: e.id]

      {events, cursor} = page(query, id, p, g.principal_id)
      %{root: hd(decorate([root], g.principal_id)), events: events, next_cursor: cursor}
    end)
  end

  def entries(g, id, p) do
    DelegatedGroups.with_room(g, id, "chats.read", fn ->
      type =
        case p["kind"] do
          "post" -> "cool.gravitas.river.post.v1"
          "discussion" -> "cool.gravitas.river.discussion.v1"
          _ -> Repo.rollback(:invalid_request)
        end

      query =
        from e in RoomEvent,
          where: e.room_id == ^id and e.type == ^type,
          order_by: [desc: e.inserted_at, desc: e.id]

      {events, cursor} = page(query, id, p, g.principal_id)
      %{events: events, next_cursor: cursor}
    end)
  end

  def edit(g, id, p) do
    DelegatedGroups.with_room(g, id, "chats.write", fn ->
      original = target!(id, p["event_id"])

      unless original.type in @entry_types and original.principal_id == g.principal_id,
        do: Repo.rollback(:forbidden)

      published = Repo.get(LakehouseMatrix.Schema.RiverPublication, original.event_id)

      if published && published.visibility == "public" && "posts.publish" not in g.scopes,
        do: Repo.rollback(:insufficient_scope)

      unless valid_text?(p["title"], 160) and valid_text?(p["body"], 40000) and
               String.length(p["body"]) <= 40000 and txn?(p["txn_id"]),
             do: Repo.rollback(:invalid_event)

      DelegatedGroups.content_event!(
        g,
        id,
        @edit,
        %{
          "version" => 1,
          "m.relates_to" => %{"rel_type" => "m.replace", "event_id" => original.event_id},
          "m.new_content" => %{"version" => 1, "title" => p["title"], "body" => p["body"]}
        },
        p["txn_id"]
      )
    end)
  end

  def reaction(g, id, p) do
    DelegatedGroups.with_room(g, id, "chats.write", fn -> reaction_authorized!(g, id, p) end)
  end

  @doc false
  def reaction_authorized!(g, id, p) do
    target = target!(id, p["event_id"])

    unless target.type in ["m.room.message", "m.sticker" | @entry_types] and
             LakehouseMatrix.RiverReactions.valid?(p["key"]) and
             is_boolean(p["active"]) and txn?(p["txn_id"]),
           do: Repo.rollback(:invalid_event)

    action = %{
      "version" => 1,
      "event_id" => target.event_id,
      "key" => p["key"],
      "active" => p["active"]
    }

    # The action event is the transaction ledger, including no-op removals. A
    # retried removal cannot delete a later activation made in a new transaction.
    previous = DelegatedGroups.request_event(action_id(g, id, p["txn_id"]))

    if previous do
      expected =
        Map.put(action, "cool.gravitas.delegation", %{
          "version" => 1,
          "app_origin" => g.app_origin
        })

      unless previous.type == @reaction_action and previous.content == expected,
        do: Repo.rollback(:transaction_conflict)

      Events.to_client_event(previous)
    else
      mine = active_reactions(id, target.event_id, g.principal_id, p["key"])

      cond do
        p["active"] and mine == [] ->
          DelegatedGroups.content_event!(
            g,
            id,
            "m.reaction",
            %{
              "m.relates_to" => %{
                "rel_type" => "m.annotation",
                "event_id" => target.event_id,
                "key" => p["key"]
              }
            },
            p["txn_id"] <> "-add"
          )

        not p["active"] ->
          for e <- mine do
            DelegatedGroups.content_event!(
              g,
              id,
              "m.room.redaction",
              %{"redacts" => e.event_id},
              p["txn_id"] <> "-remove-" <> digest(e.event_id)
            )
          end

        true ->
          :ok
      end

      DelegatedGroups.content_event!(g, id, @reaction_action, action, p["txn_id"])
    end
  end

  @doc "Read-model fields never replace the signed/original event content."
  def decorate([], _), do: []

  def decorate(rows, actor) do
    rows = Enum.map(rows, &LakehouseMatrix.Erasure.record(&1, actor))
    room = hd(rows).room_id
    ids = Enum.map(rows, & &1.event_id)
    publications = LakehouseMatrix.RiverPublishing.summaries(ids)

    edits =
      Repo.all(
        from e in LakehouseMatrix.Erasure.event_query(actor),
          where:
            e.room_id == ^room and e.type == ^@edit and
              fragment("? #>> '{m.relates_to,event_id}'", e.content) in ^ids,
          order_by: [asc: e.inserted_at, asc: e.id]
      )
      |> Map.new(fn e -> {get_in(e.content, ["m.relates_to", "event_id"]), e} end)

    # Published posts use their public anchor for reactions in every River view.
    # Earlier member-only reactions stay in the private event history.
    linked = Map.filter(publications, fn {_, p} -> not is_nil(p["anchor_id"]) end)
    public = Map.filter(linked, fn {_, p} -> p["visibility"] == "public" end)
    targets = ids ++ Enum.map(linked, fn {_, p} -> p["anchor_id"] end)
    rooms = [room | Enum.map(linked, fn {_, p} -> p["thread_id"] end)] |> Enum.uniq()

    room_uuids =
      Enum.map(rooms, fn id ->
        {:ok, uuid} = Ecto.UUID.dump(id)
        uuid
      end)

    {:ok, actor_uuid} = Ecto.UUID.dump(actor)

    sql = """
    SELECT matrix_view_content(r.event_id, $3) #>> '{m.relates_to,event_id}', matrix_view_content(r.event_id, $3) #>> '{m.relates_to,key}',
           COUNT(DISTINCT r.sender), BOOL_OR(r.principal_id = $3)
    FROM room_events r
    WHERE r.room_id = ANY($1::uuid[]) AND r.type = 'm.reaction'
      AND matrix_view_content(r.event_id, $3) #>> '{m.relates_to,event_id}' = ANY($2::text[])
      AND NOT EXISTS (SELECT 1 FROM room_events d WHERE d.room_id = r.room_id
        AND d.type = 'm.room.redaction' AND d.content->>'redacts' = r.event_id)
    GROUP BY 1, 2 ORDER BY 1, 2
    """

    reactions =
      Repo.query!(sql, [room_uuids, targets, actor_uuid]).rows
      |> Enum.group_by(&hd/1, fn [_id, key, count, mine] ->
        %{key: key, count: count, mine: mine || false}
      end)

    replies =
      Repo.all(
        from e in LakehouseMatrix.Erasure.event_query(actor),
          where:
            e.room_id in ^rooms and e.type == "m.room.message" and
              fragment(
                "COALESCE(? #>> '{m.relates_to,event_id}', ? #>> '{m.relates_to,m.in_reply_to,event_id}')",
                e.content,
                e.content
              ) in ^targets,
          group_by:
            fragment(
              "COALESCE(? #>> '{m.relates_to,event_id}', ? #>> '{m.relates_to,m.in_reply_to,event_id}')",
              e.content,
              e.content
            ),
          select:
            {fragment(
               "COALESCE(? #>> '{m.relates_to,event_id}', ? #>> '{m.relates_to,m.in_reply_to,event_id}')",
               e.content,
               e.content
             ), count(e.id)}
      )
      |> Map.new()

    for e <- rows do
      edit = edits[e.event_id]

      Events.to_client_event(e, actor)
      |> Map.put(
        "publication",
        Map.get(publications, e.event_id, %{
          "visibility" => "members",
          "comments_policy" => "members"
        })
      )
      |> Map.put(
        "reaction_summary",
        Map.get(
          reactions,
          if(public[e.event_id], do: public[e.event_id]["anchor_id"], else: e.event_id),
          []
        )
      )
      |> Map.put(
        "reply_count",
        Map.get(replies, e.event_id, 0) +
          if(linked[e.event_id],
            do: Map.get(replies, linked[e.event_id]["anchor_id"], 0),
            else: 0
          )
      )
      |> Map.put("unsigned", %{
        "cool.gravitas.stream_order" => "#{DateTime.to_unix(e.inserted_at, :microsecond)}:#{e.id}"
      })
      |> then(fn event ->
        if edit && edit.principal_id == e.principal_id do
          Map.merge(event, %{
            "rendered_content" => Map.merge(e.content, edit.content["m.new_content"]),
            "edited" => true
          })
        else
          Map.put(event, "edited", false)
        end
      end)
    end
  end

  defp active_reactions(id, target, actor, key) do
    rows =
      Repo.all(
        from e in RoomEvent,
          where:
            e.room_id == ^id and e.type == "m.reaction" and
              e.principal_id == ^actor and
              fragment("? #>> '{m.relates_to,event_id}'", e.content) == ^target and
              fragment("? #>> '{m.relates_to,key}'", e.content) == ^key
      )

    ids = Enum.map(rows, & &1.event_id)

    redacted =
      Repo.all(
        from e in RoomEvent,
          where:
            e.room_id == ^id and e.type == "m.room.redaction" and
              fragment("?->>'redacts'", e.content) in ^ids,
          select: fragment("?->>'redacts'", e.content)
      )
      |> MapSet.new()

    Enum.reject(rows, &MapSet.member?(redacted, &1.event_id))
  end

  defp thread_root(id, e) do
    case get_in(e.content, ["m.relates_to", "rel_type"]) do
      "m.thread" -> target!(id, get_in(e.content, ["m.relates_to", "event_id"]))
      _ -> e
    end
  end

  defp target!(id, target) when is_binary(target) and byte_size(target) <= 512 do
    Repo.one(
      from e in RoomEvent,
        where: e.room_id == ^id and e.event_id == ^target and is_nil(e.state_key)
    ) || Repo.rollback(:invalid_relation)
  end

  defp target!(_, _), do: Repo.rollback(:invalid_relation)

  def budget(events, max_bytes \\ 1_000_000) do
    {kept, _} =
      Enum.reduce_while(events, {[], 0}, fn event, {acc, size} ->
        bytes = byte_size(Jason.encode!(event))

        if acc != [] and size + bytes > max_bytes do
          {:halt, {acc, size}}
        else
          {:cont, {[event | acc], size + bytes}}
        end
      end)

    Enum.reverse(kept)
  end

  defp page(query, id, params, actor) do
    limit = 100

    query =
      if is_nil(params["before"]) do
        query
      else
        c = target!(id, params["before"])

        from e in query,
          where:
            e.inserted_at < ^c.inserted_at or (e.inserted_at == ^c.inserted_at and e.id < ^c.id)
      end

    all = Repo.all(from e in query, limit: ^(limit + 1))
    candidates = Enum.take(all, limit)
    events = decorate(candidates, actor) |> budget(800_000)
    rows = Enum.take(candidates, length(events))
    {Enum.reverse(events), if(length(all) > length(rows), do: List.last(rows).event_id)}
  end

  defp action_id(g, id, txn),
    do:
      "$river_content_" <>
        digest("#{g.principal_id}|#{g.app_origin}|#{id}|#{@reaction_action}|#{txn}")

  defp digest(s), do: :crypto.hash(:sha256, s) |> Base.url_encode64(padding: false)

  defp valid_text?(s, max),
    do:
      is_binary(s) and byte_size(s) <= max * 4 and String.length(s) <= max and
        String.trim(s) != ""

  defp txn?(s), do: is_binary(s) and String.match?(s, ~r/^[a-zA-Z0-9_-]{1,128}$/)
end
