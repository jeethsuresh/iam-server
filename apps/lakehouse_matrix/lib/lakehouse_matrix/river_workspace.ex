defmodule LakehouseMatrix.RiverWorkspace do
  @moduledoc "Orbit workspace features projected from Gravitas ACLs and immutable Matrix events."
  import Ecto.Query
  alias LakehouseIam.{Repo, Contacts, Accounts}
  alias LakehouseIam.Schema.{Principal, AppGrant}
  alias LakehouseMatrix.{DelegatedGroups, Identity, Memberships, State, RiverContent}
  alias LakehouseMatrix.Schema.{RoomEvent, RoomMembership, RiverEntryRead}
  @entries ~w(cool.gravitas.river.post.v1 cool.gravitas.river.discussion.v1)

  def conversation(g, p) do
    with true <- is_list(p["member_ids"]) and length(p["member_ids"]) in 1..24,
         true <- is_binary(p["txn_id"]) and is_binary(p["name"]),
         true <- "contacts.read" in g.scopes and "groups.manage" in g.scopes do
      LakehouseMatrix.Protocol.Policy.transaction(fn ->
        LakehouseMatrix.ClientStore.lock!()
        peers = p["member_ids"] |> Enum.map(&person!/1) |> Enum.uniq() |> Enum.sort()
        unless g.principal_id not in peers, do: Repo.rollback(:invalid_member)
        ids = Enum.sort([g.principal_id | peers])

        Repo.all(
          from a in Principal, where: a.id in ^ids, order_by: a.id, lock: "FOR NO KEY UPDATE"
        )

        unless Enum.all?(
                 peers,
                 &(Contacts.connected?(g.principal_id, &1) and
                     Contacts.available_in_app?(&1, g.app_origin))
               ),
               do: Repo.rollback(:forbidden)

        Repo.one(from a in AppGrant, where: a.id == ^g.id, lock: "FOR UPDATE") ||
          Repo.rollback(:forbidden)

        if length(peers) == 1 do
          unwrap!(DelegatedGroups.direct(g, %{"user_id" => mxid(hd(peers))}))
        else
          room =
            unwrap!(
              DelegatedGroups.create(g, %{
                "name" => p["name"],
                "kind" => "group",
                "txn_id" => p["txn_id"]
              })
            )

          unwrap!(
            DelegatedGroups.with_room(g, room.id, "chats.write", fn ->
              # The immutable ledger binds the request's participant set on retry.
              DelegatedGroups.content_event!(
                g,
                room.id,
                "cool.gravitas.river.conversation.v1",
                %{"version" => 1, "members" => Enum.map(peers, &mxid/1)},
                "participants"
              )

              for id <- peers, Memberships.membership(room.id, id) not in ["join", "invite"] do
                unwrap!(
                  DelegatedGroups.membership(g, room.id, %{
                    "action" => "invite",
                    "user_id" => mxid(id)
                  })
                )
              end

              room
            end)
          )
        end
      end)
    else
      _ -> {:error, :invalid_request}
    end
  end

  def invite(g, conversation, p) do
    DelegatedGroups.with_room(g, conversation, "chats.write", fn ->
      space = p["space_id"]
      unless match?({:ok, _}, Ecto.UUID.cast(space)), do: Repo.rollback(:invalid_request)
      # Authoritative member invite checks below require the space owner, and
      # the shared invitation card is visible only to this conversation's ACL.
      members =
        Memberships.membership_map(conversation)
        |> Enum.filter(fn {id, m} -> m in ["join", "invite"] and id != g.principal_id end)

      if members == [], do: Repo.rollback(:invalid_member)

      unwrap!(
        DelegatedGroups.with_room(g, space, "chats.read", fn ->
          unless get_in(State.get(space, "cool.gravitas.river.group.v1") || %{}, [
                   "content",
                   "kind"
                 ]) == "space",
                 do: Repo.rollback(:invalid_request)

          unless LakehouseMatrix.Matrix.creator?(space, g.principal_id),
            do: Repo.rollback(:forbidden)

          for {id, _} <- members, Memberships.membership(space, id) not in ["join", "invite"] do
            unless Contacts.connected?(g.principal_id, id), do: Repo.rollback(:forbidden)

            unwrap!(
              DelegatedGroups.membership(g, space, %{"action" => "invite", "user_id" => mxid(id)})
            )
          end
        end)
      )

      unless valid_txn?(p["txn_id"]), do: Repo.rollback(:invalid_request)

      DelegatedGroups.content_event!(
        g,
        conversation,
        "cool.gravitas.river.invitation.v1",
        %{
          "version" => 1,
          "space_id" => space,
          "room_id" => Identity.room_id(space),
          "body" => "Invitation to #{LakehouseMatrix.Rooms.get_room(space).name}"
        },
        p["txn_id"]
      )
    end)
  end

  def home(g) do
    with "chats.read" <- Enum.find(g.scopes, &(&1 == "chats.read")),
         {:ok, overview} <- DelegatedGroups.overview(g) do
      groups = overview.groups
      ids = for x <- groups, x.membership == "join", do: x.id

      roots =
        Enum.flat_map(@entries, fn type ->
          Repo.all(
            from e in RoomEvent,
              join: m in RoomMembership,
              on: m.room_id == e.room_id and m.principal_id == ^g.principal_id,
              left_join: r in RiverEntryRead,
              on: r.event_id == e.event_id and r.principal_id == ^g.principal_id,
              where:
                e.room_id in ^ids and e.type == ^type and e.principal_id != ^g.principal_id and
                  is_nil(r.event_id) and e.inserted_at >= m.updated_at,
              order_by: [desc: e.inserted_at, desc: e.id],
              limit: 20
          )
        end)

      projected =
        roots
        |> Enum.group_by(& &1.room_id)
        |> Enum.flat_map(fn {id, rows} ->
          name = Enum.find(groups, &(&1.id == id)).name

          for event <- RiverContent.decorate(rows, g.principal_id),
              do:
                event |> Map.put("group_id", id) |> Map.put("group_name", name) |> entry_preview()
        end)
        |> Map.new(&{&1["event_id"], &1})

      entries = Enum.map(roots, &projected[&1.event_id])
      # Thread participation includes older roots, rather than only the latest
      # home timeline page. Thread reads are still checked against current ACLs.
      targets = recent_threads(ids, g.principal_id)

      threads =
        for {room, target} <- targets,
            e = Repo.get_by(RoomEvent, room_id: room, event_id: target),
            not is_nil(e),
            do: Map.put(hd(RiverContent.decorate([e], g.principal_id)), "group_id", room)

      recent_entries =
        Enum.flat_map(@entries, fn type ->
          rows =
            Repo.all(
              from e in RoomEvent,
                where: e.room_id in ^ids and e.type == ^type,
                order_by: [desc: e.inserted_at, desc: e.id],
                limit: 6
            )

          projected =
            rows
            |> Enum.group_by(& &1.room_id)
            |> Enum.flat_map(fn {id, events} ->
              name = Enum.find(groups, &(&1.id == id)).name

              for event <- RiverContent.decorate(events, g.principal_id),
                  do:
                    event
                    |> Map.put("group_id", id)
                    |> Map.put("group_name", name)
                    |> entry_preview()
            end)
            |> Map.new(&{&1["event_id"], &1})

          Enum.map(rows, &projected[&1.event_id])
        end)

      {:ok,
       %{
         catch_up: entries,
         recent_entries: RiverContent.budget(recent_entries, 200_000),
         threads: RiverContent.budget(threads, 200_000)
       }}
    else
      _ -> {:error, :insufficient_scope}
    end
  end

  # Home only needs a preview. A few long posts must not exhaust its response
  # budget and hide the independent discussions/unread sections.
  defp entry_preview(event) do
    content = event["rendered_content"] || event["content"]

    content =
      Map.take(content, ~w(version title body))
      |> Map.update("body", "", &String.slice(&1, 0, 300))

    event |> Map.put("content", content) |> Map.delete("rendered_content")
  end

  # Orbit keeps five recent threads per channel, plus two when active within
  # 24 hours. A root author participates even without posting a reply.
  defp recent_threads(ids, actor) do
    room_ids =
      Enum.map(ids, fn id ->
        {:ok, value} = Ecto.UUID.dump(id)
        value
      end)

    {:ok, principal} = Ecto.UUID.dump(actor)
    now = DateTime.utc_now()
    cutoff = now |> DateTime.add(-72 * 3600, :second) |> DateTime.to_naive()
    extra = now |> DateTime.add(-24 * 3600, :second) |> DateTime.to_naive()

    sql = """
    WITH recent AS (
      SELECT root.room_id, root.event_id, MAX(reply.inserted_at) AS activity
      FROM room_events root JOIN room_events reply ON reply.room_id = root.room_id
        AND reply.type = 'm.room.message'
        AND reply.content #>> '{m.relates_to,rel_type}' = 'm.thread'
        AND reply.content #>> '{m.relates_to,event_id}' = root.event_id
      WHERE root.room_id = ANY($1::uuid[])
        AND (root.principal_id = $2 OR EXISTS (
          SELECT 1 FROM room_events mine WHERE mine.room_id = root.room_id
            AND mine.principal_id = $2 AND mine.type = 'm.room.message'
            AND mine.content #>> '{m.relates_to,rel_type}' = 'm.thread'
            AND mine.content #>> '{m.relates_to,event_id}' = root.event_id))
      GROUP BY root.room_id, root.event_id HAVING MAX(reply.inserted_at) >= $3
    ), ranked AS (
      SELECT *, ROW_NUMBER() OVER (PARTITION BY room_id ORDER BY activity DESC, event_id) AS position
      FROM recent
    ) SELECT room_id, event_id FROM ranked
      WHERE position <= 5 OR (position <= 7 AND activity >= $4)
      ORDER BY activity DESC, event_id
    """

    for [room, event] <- Repo.query!(sql, [room_ids, principal, cutoff, extra]).rows do
      {:ok, id} = Ecto.UUID.load(room)
      {id, event}
    end
  end

  def read_entry(g, id, p) do
    DelegatedGroups.with_room(g, id, "chats.read", fn ->
      e = Repo.get_by(RoomEvent, room_id: id, event_id: p["event_id"])
      unless e && e.type in @entries, do: Repo.rollback(:invalid_event)

      Repo.insert!(%RiverEntryRead{principal_id: g.principal_id, event_id: e.event_id},
        on_conflict: :nothing
      )

      LakehouseIam.Changes.notify(%{"principal_id" => g.principal_id})
      %{ok: true}
    end)
  end

  defp person!(value) do
    with {:ok, username} <- Identity.parse_user_id(value),
         {:ok, p} <- Accounts.fetch_user(username),
         true <- p.active do
      p.id
    else
      _ -> Repo.rollback(:invalid_member)
    end
  end

  defp mxid(id), do: Repo.get!(Principal, id).username |> Identity.user_id()
  defp unwrap!({:ok, x}), do: x
  defp unwrap!({:error, e}), do: Repo.rollback(e)
  defp valid_txn?(v), do: is_binary(v) and String.match?(v, ~r/^[a-zA-Z0-9_-]{1,128}$/)
end
