defmodule LakehouseMatrix.Social do
  @moduledoc "Private, consent-scoped friend relationships and immutable account events."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseIam.Schema.Principal
  alias LakehouseMatrix.Identity
  alias LakehouseMatrix.Schema.{RiverFriendship, RiverFriendBlock, RiverSocialEvent}

  @actions ~w(request accept ignore cancel remove block unblock)

  def list(g) do
    with :ok <- scope(g, "friends.read") do
      actor = g.principal_id
      relations = Repo.all(from f in RiverFriendship,
        where: (f.low_id == ^actor or f.high_id == ^actor) and f.status != "none",
        order_by: [desc: f.updated_at])
      visible = Enum.reject(relations, &blocked?(actor, other(&1, actor)))
      friends = for f <- visible, f.status == "accepted", p = Repo.get!(Principal, other(f, actor)), p.active,
        do: person(p)
      requests = for f <- visible, f.status == "pending", p = Repo.get!(Principal, other(f, actor)), p.active,
        do: Map.merge(person(p), %{id: f.id, direction: if(f.requested_by == actor, do: "outgoing", else: "incoming")})
      blocked = Repo.all(from b in RiverFriendBlock, join: p in Principal, on: p.id == b.target_id,
        where: b.owner_id == ^actor, order_by: p.username, select: p) |> Enum.map(&person/1)
      {:ok, %{friends: friends, requests: requests, blocked: blocked}}
    end
  end

  def events(g) do
    with :ok <- scope(g, "friends.read") do
      events = Repo.all(from e in RiverSocialEvent,
        where: e.actor_id == ^g.principal_id or
          (e.target_id == ^g.principal_id and e.action not in ["block", "unblock"]),
        order_by: [desc: e.inserted_at, desc: e.id], limit: 100)
        |> Enum.reverse() |> Enum.map(&event/1)
      {:ok, %{events: events}}
    end
  end

  def act(g, p) do
    with :ok <- scope(g, "friends.manage"),
         true <- p["action"] in @actions and valid_txn?(p["txn_id"]),
         {:ok, username} <- Identity.parse_user_id(p["user_id"]),
         {:ok, target} <- Accounts.fetch_user(username),
         true <- target.active and target.type == :user and target.id != g.principal_id do
      Repo.transaction(fn ->
        # All changes of a pair (including first insert and reciprocal requests)
        # lock both identities in the same order. Concurrent accepts cannot race blocks.
        ids = Enum.sort([g.principal_id, target.id])
        Repo.all(from u in Principal, where: u.id in ^ids, order_by: u.id, lock: "FOR NO KEY UPDATE")
        existing = Repo.get_by(RiverSocialEvent, actor_id: g.principal_id,
          app_origin: g.app_origin, txn_id: p["txn_id"])
        if existing do
          unless existing.target_id == target.id and existing.action == p["action"],
            do: Repo.rollback(:transaction_conflict)
          event(existing)
        else
          [low, high] = ids
          relation = Repo.get_by(RiverFriendship, low_id: low, high_id: high)
          change!(g.principal_id, target.id, relation, p["action"], low, high)
          Repo.insert!(%RiverSocialEvent{actor_id: g.principal_id, target_id: target.id,
            app_origin: g.app_origin, txn_id: p["txn_id"], action: p["action"]}) |> event()
        end
      end)
    else
      {:error, e} -> {:error, e}
      _ -> {:error, :invalid_request}
    end
  end

  def friends?(a, b) do
    [low, high] = Enum.sort([a, b])
    Repo.exists?(from f in RiverFriendship,
      where: f.low_id == ^low and f.high_id == ^high and f.status == "accepted") and not blocked?(a, b)
  end

  def blocked?(a, b), do: Repo.exists?(from x in RiverFriendBlock,
    where: (x.owner_id == ^a and x.target_id == ^b) or (x.owner_id == ^b and x.target_id == ^a))

  defp change!(actor, target, relation, action, low, high) do
    cond do
      action == "block" ->
        Repo.insert!(%RiverFriendBlock{owner_id: actor, target_id: target}, on_conflict: :nothing)
        if relation, do: status!(relation, "none")
      action == "unblock" ->
        Repo.delete_all(from b in RiverFriendBlock, where: b.owner_id == ^actor and b.target_id == ^target)
      blocked?(actor, target) -> Repo.rollback(:forbidden)
      action == "request" and (is_nil(relation) or relation.status == "none") ->
        pending = Repo.aggregate(from(f in RiverFriendship,
          where: f.requested_by == ^actor and f.status == "pending"), :count)
        if pending >= 100, do: Repo.rollback(:too_many_requests)
        if relation do
          Ecto.Changeset.change(relation, status: "pending", requested_by: actor) |> Repo.update!()
        else
          Repo.insert!(%RiverFriendship{low_id: low, high_id: high, requested_by: actor, status: "pending"})
        end
      action == "accept" and not is_nil(relation) and relation.status == "pending" and relation.requested_by != actor ->
        status!(relation, "accepted")
      action == "ignore" and not is_nil(relation) and relation.status == "pending" and relation.requested_by != actor ->
        status!(relation, "none")
      action == "cancel" and not is_nil(relation) and relation.status == "pending" and relation.requested_by == actor ->
        status!(relation, "none")
      action == "remove" and not is_nil(relation) and relation.status == "accepted" ->
        status!(relation, "none")
      true -> Repo.rollback(:invalid_membership)
    end
  end

  defp status!(r, status), do: Ecto.Changeset.change(r, status: status) |> Repo.update!()
  defp other(f, actor), do: if(f.low_id == actor, do: f.high_id, else: f.low_id)
  defp person(p), do: %{principal_id: p.id, username: p.username, user_id: Identity.user_id(p.username)}
  defp event(e), do: %{event_id: "$" <> e.id, type: "cool.gravitas.river.friend.v1",
    sender: Identity.user_id(Repo.get!(Principal, e.actor_id).username),
    origin_server_ts: DateTime.to_unix(e.inserted_at, :millisecond),
    content: %{version: 1, action: e.action, user_id: Identity.user_id(Repo.get!(Principal, e.target_id).username),
      app_origin: e.app_origin}}
  defp scope(g, s), do: if(s in g.scopes, do: :ok, else: {:error, :insufficient_scope})
  defp valid_txn?(t), do: is_binary(t) and String.match?(t, ~r/^[a-zA-Z0-9_-]{1,128}$/)
end
