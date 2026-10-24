defmodule LakehouseIam.Contacts do
  @moduledoc """
  Mutual Gravitas contacts, shared by consenting apps. The existing River tables
  remain the storage contract so relationships, blocks and audit IDs are preserved.
  App membership means an active account with a current contacts.read consent grant,
  not online presence. Requests are never accepted by signing into an app.
  """
  import Ecto.Query
  alias LakehouseIam.{Accounts, Discovery, Identifier, Repo}
  alias LakehouseIam.Schema.{AppGrant, Principal, Contact, ContactBlock, ContactEvent}

  @actions ~w(request accept ignore cancel remove block unblock)

  def owner_list(principal_id), do: list(owner(principal_id))
  def owner_act(principal_id, params), do: act(owner(principal_id), params)
  defp owner(id), do: %{principal_id: id, app_origin: Discovery.public_url(), scopes: ~w(contacts.read contacts.manage)}

  def list(g) do
    with :ok <- scope(g, "contacts.read") do
      actor = g.principal_id
      relations = Repo.all(from c in Contact,
        where: (c.low_id == ^actor or c.high_id == ^actor) and c.status != "none",
        order_by: [desc: c.updated_at, desc: c.id])
      blocks = Repo.all(from b in ContactBlock, where: b.owner_id == ^actor or b.target_id == ^actor)
      hidden = MapSet.new(blocks, &if(&1.owner_id == actor, do: &1.target_id, else: &1.owner_id))
      ids = Enum.uniq(Enum.map(relations, &other(&1, actor)) ++ Enum.map(blocks, & &1.target_id))
      people = Repo.all(from p in Principal, where: p.id in ^ids and p.active and p.type == :user)
        |> Map.new(&{&1.id, &1})
      visible = Enum.reject(relations, &MapSet.member?(hidden, other(&1, actor)))
      accepted = for c <- visible, c.status == "accepted", Map.has_key?(people, other(c, actor)), do: other(c, actor)
      app_users = Repo.all(from a in AppGrant,
        where: a.app_origin == ^g.app_origin and a.principal_id in ^accepted and "contacts.read" in a.scopes,
        select: a.principal_id) |> MapSet.new()
      contacts = for c <- visible, c.status == "accepted", p = people[other(c, actor)], not is_nil(p),
        do: Map.put(person(p), :uses_app, MapSet.member?(app_users, p.id))
      requests = for c <- visible, c.status == "pending", p = people[other(c, actor)], not is_nil(p),
        do: Map.merge(person(p), %{id: c.id, direction: if(c.requested_by == actor, do: "outgoing", else: "incoming")})
      blocked = for b <- blocks, b.owner_id == actor, p = people[b.target_id], not is_nil(p), do: person(p)
      {:ok, %{contacts: contacts, requests: requests, blocked: Enum.sort_by(blocked, & &1.username)}}
    end
  end

  # The app sees its own attributed actions. It cannot use contact audit history
  # to discover which unrelated apps a contact has used. Lists reflect all apps.
  def events(g) do
    with :ok <- scope(g, "contacts.read") do
      events = Repo.all(from e in ContactEvent,
        where: e.app_origin == ^g.app_origin and (e.actor_id == ^g.principal_id or
          (e.target_id == ^g.principal_id and e.action not in ["block", "unblock"])),
        order_by: [desc: e.inserted_at, desc: e.id], limit: 100)
        |> Enum.reverse() |> Enum.map(&event/1)
      {:ok, %{events: events}}
    end
  end

  def act(g, p) do
    with :ok <- scope(g, "contacts.manage"),
         true <- p["action"] in @actions and valid_txn?(p["txn_id"]),
         {:ok, username} <- Identifier.local_username(p["user_id"] || p["username"]),
         {:ok, target} <- Accounts.fetch_user(username),
         true <- target.active and target.type == :user and target.id != g.principal_id do
      Repo.transaction(fn ->
        ids = Enum.sort([g.principal_id, target.id])
        locked = Repo.all(from u in Principal, where: u.id in ^ids, order_by: u.id, lock: "FOR NO KEY UPDATE")
        unless length(locked) == 2 and Enum.all?(locked, &(&1.active and &1.type == :user)), do: Repo.rollback(:forbidden)
        if Map.has_key?(g, :id) do
          current = Repo.one(from a in AppGrant, where: a.id == ^g.id, lock: "FOR SHARE")
          unless current && current.principal_id == g.principal_id && current.app_origin == g.app_origin && "contacts.manage" in current.scopes,
            do: Repo.rollback(:insufficient_scope)
        end
        existing = Repo.get_by(ContactEvent, actor_id: g.principal_id, app_origin: g.app_origin, txn_id: p["txn_id"])
        if existing do
          unless existing.target_id == target.id and existing.action == p["action"], do: Repo.rollback(:transaction_conflict)
          event(existing)
        else
          [low, high] = ids
          relation = Repo.get_by(Contact, low_id: low, high_id: high)
          change!(g.principal_id, target.id, relation, p["action"], low, high)
          LakehouseIam.Changes.notify(%{"principals" => ids})
          Repo.insert!(%ContactEvent{actor_id: g.principal_id, target_id: target.id,
            app_origin: g.app_origin, txn_id: p["txn_id"], action: p["action"], type: "cool.gravitas.contact.v1"}) |> event()
        end
      end)
    else
      {:error, e} when is_atom(e) -> {:error, e}
      _ -> {:error, :invalid_request}
    end
  end

  def connected?(a, b) do
    [low, high] = Enum.sort([a, b])
    Repo.exists?(from c in Contact, where: c.low_id == ^low and c.high_id == ^high and c.status == "accepted") and not blocked?(a, b)
  end

  def available_in_app?(principal_id, origin) do
    Repo.exists?(from a in AppGrant, join: p in Principal, on: p.id == a.principal_id,
      where: a.principal_id == ^principal_id and a.app_origin == ^origin and "contacts.read" in a.scopes and p.active and p.type == :user)
  end

  def blocked?(a, b), do: Repo.exists?(from x in ContactBlock,
    where: (x.owner_id == ^a and x.target_id == ^b) or (x.owner_id == ^b and x.target_id == ^a))

  defp change!(actor, target, relation, action, low, high) do
    cond do
      action == "block" ->
        Repo.insert!(%ContactBlock{owner_id: actor, target_id: target}, on_conflict: :nothing)
        if relation, do: status!(relation, "none")
      action == "unblock" ->
        Repo.delete_all(from b in ContactBlock, where: b.owner_id == ^actor and b.target_id == ^target)
      blocked?(actor, target) -> Repo.rollback(:forbidden)
      action == "request" and (is_nil(relation) or relation.status == "none") ->
        pending = Repo.aggregate(from(f in Contact,
          where: f.requested_by == ^actor and f.status == "pending"), :count)
        cutoff = DateTime.add(DateTime.utc_now(), -3600, :second)
        recent = Repo.aggregate(from(e in ContactEvent,
          where: e.actor_id == ^actor and e.action == "request" and e.inserted_at > ^cutoff), :count)
        if pending >= 100 or recent >= 20, do: Repo.rollback(:too_many_requests)
        if relation do
          Ecto.Changeset.change(relation, status: "pending", requested_by: actor) |> Repo.update!()
        else
          Repo.insert!(%Contact{low_id: low, high_id: high, requested_by: actor, status: "pending"})
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
  defp other(c, actor), do: if(c.low_id == actor, do: c.high_id, else: c.low_id)
  defp person(p), do: %{principal_id: p.id, username: p.username, user_id: Identifier.format(p.username)}
  defp event(e), do: %{event_id: "$" <> e.id, type: e.type,
    sender: Identifier.format(Repo.get!(Principal, e.actor_id).username),
    origin_server_ts: DateTime.to_unix(e.inserted_at, :millisecond),
    content: %{version: 1, action: e.action, user_id: Identifier.format(Repo.get!(Principal, e.target_id).username), app_origin: e.app_origin}}
  defp scope(g, s), do: if(s in g.scopes, do: :ok, else: {:error, :insufficient_scope})
  defp valid_txn?(t), do: is_binary(t) and String.match?(t, ~r/^[a-zA-Z0-9_-]{1,128}$/)
end
