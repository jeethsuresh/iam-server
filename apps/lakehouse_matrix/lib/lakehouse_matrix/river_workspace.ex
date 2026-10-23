defmodule LakehouseMatrix.RiverWorkspace do
  @moduledoc "Orbit workspace features projected from Gravitas ACLs and immutable Matrix events."
  import Ecto.Query
  alias LakehouseIam.{Repo, Contacts, Accounts}
  alias LakehouseIam.Schema.{Principal, AppGrant}
  alias LakehouseMatrix.{DelegatedGroups, Identity, Memberships, State, RiverContent}
  alias LakehouseMatrix.Schema.{RoomEvent, RiverEntryRead}
  @entries ~w(cool.gravitas.river.post.v1 cool.gravitas.river.discussion.v1)

  def conversation(g, p) do
    with true <- is_list(p["member_ids"]) and length(p["member_ids"]) in 1..24,
         true <- is_binary(p["txn_id"]) and is_binary(p["name"]),
         true <- "contacts.read" in g.scopes and "groups.manage" in g.scopes do
      Repo.transaction(fn ->
        peers = p["member_ids"] |> Enum.map(&person!/1) |> Enum.uniq() |> Enum.sort()
        unless g.principal_id not in peers, do: Repo.rollback(:invalid_member)
        ids = Enum.sort([g.principal_id | peers])
        Repo.all(from a in Principal, where: a.id in ^ids, order_by: a.id, lock: "FOR NO KEY UPDATE")
        unless Enum.all?(peers, &(Contacts.connected?(g.principal_id, &1) and Contacts.available_in_app?(&1, g.app_origin))), do: Repo.rollback(:forbidden)
        Repo.one(from a in AppGrant, where: a.id == ^g.id, lock: "FOR UPDATE") || Repo.rollback(:forbidden)
        if length(peers) == 1 do
          unwrap!(DelegatedGroups.direct(g, %{"user_id" => mxid(hd(peers))}))
        else
          room = unwrap!(DelegatedGroups.create(g, %{"name" => p["name"], "kind" => "group", "txn_id" => p["txn_id"]}))
          unwrap!(DelegatedGroups.with_room(g, room.id, "chats.write", fn ->
            # The immutable ledger binds the request's participant set on retry.
            DelegatedGroups.content_event!(g, room.id, "cool.gravitas.river.conversation.v1",
              %{"version" => 1, "members" => Enum.map(peers, &mxid/1)}, "participants")
            for id <- peers, Memberships.membership(room.id, id) not in ["join", "invite"] do
              unwrap!(DelegatedGroups.membership(g, room.id, %{"action" => "invite", "user_id" => mxid(id)}))
            end
            room
          end))
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
      members = Memberships.membership_map(conversation) |> Enum.filter(fn {id, m} -> m in ["join", "invite"] and id != g.principal_id end)
      if members == [], do: Repo.rollback(:invalid_member)
      unwrap!(DelegatedGroups.with_room(g, space, "chats.read", fn ->
        unless get_in(State.get(space, "cool.gravitas.river.group.v1") || %{}, ["content", "kind"]) == "space", do: Repo.rollback(:invalid_request)
        unless LakehouseMatrix.Matrix.creator?(space, g.principal_id), do: Repo.rollback(:forbidden)
        for {id, _} <- members, Memberships.membership(space, id) not in ["join", "invite"] do
          unless Contacts.connected?(g.principal_id, id), do: Repo.rollback(:forbidden)
          unwrap!(DelegatedGroups.membership(g, space, %{"action" => "invite", "user_id" => mxid(id)}))
        end
      end))
      unless valid_txn?(p["txn_id"]), do: Repo.rollback(:invalid_request)
      DelegatedGroups.content_event!(g, conversation, "cool.gravitas.river.invitation.v1",
        %{"version" => 1, "space_id" => space, "room_id" => Identity.room_id(space), "body" => "Invitation to #{LakehouseMatrix.Rooms.get_room(space).name}"}, p["txn_id"])
    end)
  end

  def home(g) do
    with "chats.read" <- Enum.find(g.scopes, &(&1 == "chats.read")),
         {:ok, overview} <- DelegatedGroups.overview(g) do
      groups = overview.groups
      ids = for x <- groups, x.membership == "join", do: x.id
      reads = Repo.all(from r in RiverEntryRead, where: r.principal_id == ^g.principal_id, select: r.event_id) |> MapSet.new()
      roots = Repo.all(from e in RoomEvent, where: e.room_id in ^ids and e.type in ^@entries and e.principal_id != ^g.principal_id,
        order_by: [desc: e.inserted_at, desc: e.id], limit: 200)
        |> Enum.reject(&MapSet.member?(reads, &1.event_id))
      entries = roots |> Enum.group_by(& &1.room_id) |> Enum.flat_map(fn {id, rows} ->
        for event <- RiverContent.decorate(rows, g.principal_id), do: Map.put(event, "group_id", id)
      end) |> RiverContent.budget(400_000)
      # Thread participation includes older roots, rather than only the latest
      # home timeline page. Thread reads are still checked against current ACLs.
      targets = Repo.all(from e in RoomEvent, where: e.room_id in ^ids and e.principal_id == ^g.principal_id and e.type == "m.room.message" and
        fragment("? #>> '{m.relates_to,rel_type}'", e.content) == "m.thread",
        order_by: [desc: e.inserted_at, desc: e.id], limit: 100,
        select: {e.room_id, fragment("? #>> '{m.relates_to,event_id}'", e.content)}) |> Enum.uniq() |> Enum.take(40)
      threads = for {room, target} <- targets,
        e = Repo.get_by(RoomEvent, room_id: room, event_id: target), not is_nil(e),
        do: Map.put(hd(RiverContent.decorate([e], g.principal_id)), "group_id", room)
      {:ok, %{catch_up: entries, threads: RiverContent.budget(threads, 200_000)}}
    else
      _ -> {:error, :insufficient_scope}
    end
  end

  def read_entry(g, id, p) do
    DelegatedGroups.with_room(g, id, "chats.read", fn ->
      e = Repo.get_by(RoomEvent, room_id: id, event_id: p["event_id"])
      unless e && e.type in @entries, do: Repo.rollback(:invalid_event)
      Repo.insert!(%RiverEntryRead{principal_id: g.principal_id, event_id: e.event_id}, on_conflict: :nothing)
      LakehouseIam.Changes.notify(%{"principal_id" => g.principal_id})
      %{ok: true}
    end)
  end
  defp person!(value) do
    with {:ok, username} <- Identity.parse_user_id(value), {:ok, p} <- Accounts.fetch_user(username), true <- p.active do
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
