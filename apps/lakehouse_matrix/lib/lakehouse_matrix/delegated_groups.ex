defmodule LakehouseMatrix.DelegatedGroups do
  @moduledoc "Delegated, invitation-only groups over the existing Gravitas room ACL."
  import Ecto.Query
  alias LakehouseIam.{Repo, IAM, Accounts}
  alias LakehouseIam.Apps.Grants
  alias LakehouseIam.Schema.{AppGrant, Principal}
  alias LakehouseMatrix.{Rooms, Memberships, Identity, State, Events, Matrix}
  alias LakehouseMatrix.Schema.{Room, RoomEvent}
  alias LakehouseMatrix.Events.Context

  @group "cool.gravitas.river.group.v1"
  @types ~w(m.room.message m.reaction cool.gravitas.river.post.v1 cool.gravitas.river.discussion.v1)

  def list(grant) do
    (Memberships.joined_room_ids(grant.principal_id) ++ Memberships.invited_room_ids(grant.principal_id))
    |> Enum.uniq()
    |> Enum.filter(&Grants.room_allowed?(grant, &1))
    |> Enum.map(&describe(&1, grant.principal_id))
  end

  def create(grant, params) do
    with :ok <- scope(grant, "groups.create"),
         true <- text?(params["name"], 80),
         true <- params["kind"] in ["space", "dm"],
         true <- txn?(params["txn_id"]),
         true <- IAM.can?(grant.principal_id, "matrix.room.create", nil) do
      transact(fn ->
        locked = Repo.one!(from g in AppGrant, where: g.id == ^grant.id, lock: "FOR UPDATE")
        id = uuid("#{grant.principal_id}|#{grant.app_origin}|#{params["txn_id"]}")
        case Rooms.get_room(id) do
          nil ->
            {:ok, room} = Repo.insert(Room.changeset(%Room{id: id}, %{name: String.trim(params["name"])}))
            creator = user_id(grant.principal_id)
            content = %{"creator" => creator, "room_version" => "11"}
            content = if params["kind"] == "space", do: Map.put(content, "type", "m.space"), else: content
            event!(grant, id, "m.room.create", content, "")
            event!(grant, id, "m.room.name", %{"name" => room.name}, "")
            event!(grant, id, "m.room.join_rules", %{"join_rule" => "invite"}, "")
            event!(grant, id, "m.room.history_visibility", %{"history_visibility" => "shared"}, "")
            event!(grant, id, "m.room.power_levels", %{"users" => %{creator => 100}, "users_default" => 0,
              "events_default" => 0, "state_default" => 100, "invite" => 100, "kick" => 100, "ban" => 100}, "")
            event!(grant, id, @group, %{"version" => 1, "kind" => params["kind"], "request_id" => params["txn_id"]}, "")
            member!(grant, id, grant.principal_id, "join")
            if locked.room_mode == :selected do
              locked |> AppGrant.changeset(%{room_ids: Enum.uniq(locked.room_ids ++ [id])}) |> Repo.update!()
            end
            audit!(grant, id, "create", creator)
          _ ->
            unless Matrix.creator?(id, grant.principal_id), do: Repo.rollback(:forbidden)
            meta = metadata(id)
            unless meta["kind"] == params["kind"] && Rooms.get_room(id).name == String.trim(params["name"]),
              do: Repo.rollback(:transaction_conflict)
        end
        describe(id, grant.principal_id)
      end)
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_request}
    end
  end

  def update(grant, id, params) do
    with :ok <- scope(grant, "groups.manage"), :ok <- access(grant, id), true <- text?(params["name"], 80) do
      transact(fn ->
        lock!(id)
        owner!(grant, id)
        {:ok, _} = Rooms.get_room(id) |> Room.changeset(%{name: String.trim(params["name"])}) |> Repo.update()
        event!(grant, id, "m.room.name", %{"name" => String.trim(params["name"])}, "")
        audit!(grant, id, "rename", user_id(grant.principal_id))
        describe(id, grant.principal_id)
      end)
    else
      {:error, e} -> {:error, e}
      _ -> {:error, :invalid_request}
    end
  end

  def membership(grant, id, params) do
    with :ok <- scope(grant, "groups.manage"), :ok <- allowed(grant, id),
         true <- params["action"] in ~w(invite accept leave remove) do
      transact(fn ->
        lock!(id)
        actor = grant.principal_id
        action = params["action"]
        target = if action in ~w(accept leave), do: actor, else: target!(params["user_id"])
        current = Memberships.membership(id, target)
        membership = case action do
          "invite" ->
            owner!(grant, id)
            if target == actor || current in ~w(join invite), do: Repo.rollback(:invalid_membership)
            "invite"
          "accept" ->
            unless current == "invite", do: Repo.rollback(:forbidden)
            "join"
          "leave" ->
            unless current in ~w(join invite), do: Repo.rollback(:forbidden)
            "leave"
          "remove" ->
            owner!(grant, id)
            if target == actor || current not in ~w(join invite), do: Repo.rollback(:invalid_membership)
            "leave"
        end
        member!(grant, id, target, membership)
        audit!(grant, id, action, user_id(target))
        %{membership: membership}
      end)
    else
      {:error, e} -> {:error, e}
      _ -> {:error, :invalid_request}
    end
  end

  def timeline(grant, id, params) do
    with :ok <- scope(grant, "chats.read"), :ok <- access(grant, id) do
      limit = case Integer.parse(to_string(params["limit"] || "100")) do
        {n, ""} -> min(max(n, 1), 200)
        _ -> 100
      end
      events = Repo.all(from e in RoomEvent, where: e.room_id == ^id and is_nil(e.state_key),
        order_by: [desc: e.inserted_at, desc: e.id], limit: ^limit)
        |> Enum.reverse() |> Enum.map(&Events.to_client_event/1)
      {:ok, %{events: events}}
    end
  end

  def send(grant, id, type, txn, content) do
    with :ok <- scope(grant, "chats.write"), :ok <- access(grant, id),
         true <- type in @types && txn?(txn) && is_map(content),
         true <- byte_size(Jason.encode!(content)) <= 32000,
         true <- IAM.can?(grant.principal_id, "matrix.room.send", Identity.resource_arn(id)),
         :ok <- validate(type, content) do
      transact(fn ->
        lock!(id)
        unless Memberships.joined?(id, grant.principal_id), do: Repo.rollback(:forbidden)
        relation!(id, type, content)
        event_id = "$river_" <> digest("#{grant.principal_id}|#{grant.app_origin}|#{id}|#{txn}")
        decorated = Map.put(content, "cool.gravitas.delegation", %{"version" => 1, "app_origin" => grant.app_origin})
        case Repo.get_by(RoomEvent, event_id: event_id) do
          nil -> event!(grant, id, type, decorated, nil, event_id)
          e ->
            unless e.type == type && e.content == decorated, do: Repo.rollback(:transaction_conflict)
            Events.to_client_event(e)
        end
      end)
    else
      {:error, e} -> {:error, e}
      _ -> {:error, :invalid_event}
    end
  end

  defp validate("m.reaction", %{"m.relates_to" => %{"rel_type" => "m.annotation", "event_id" => id, "key" => key}})
       when is_binary(id) and is_binary(key) and byte_size(key) in 1..64, do: :ok
  defp validate(type, %{"body" => body} = c) when type != "m.reaction" do
    valid = text?(body, 16000) && (type == "m.room.message" ||
      (c["version"] == 1 && text?(c["title"], 160)))
    if valid, do: :ok, else: {:error, :invalid_event}
  end
  defp validate(_, _), do: {:error, :invalid_event}

  defp relation!(id, type, content) do
    relation = content["m.relates_to"]
    if relation do
      unless is_map(relation), do: Repo.rollback(:invalid_relation)
      reply = relation["m.in_reply_to"]
      target = relation["event_id"] || (is_map(reply) && reply["event_id"])
      unless is_binary(target) && Repo.exists?(from e in RoomEvent,
        where: e.room_id == ^id and e.event_id == ^target and is_nil(e.state_key)),
        do: Repo.rollback(:invalid_relation)
      unless relation["rel_type"] in [nil, "m.thread", "m.annotation"], do: Repo.rollback(:invalid_relation)
      if type != "m.reaction" && relation["rel_type"] == "m.annotation", do: Repo.rollback(:invalid_relation)
    end
  end

  defp describe(id, principal) do
    r = Rooms.get_room(id)
    %{id: id, room_id: Identity.room_id(id), name: r.name, kind: metadata(id)["kind"] || "group",
      membership: Memberships.membership(id, principal), owner: Matrix.creator?(id, principal),
      members: if(Memberships.joined?(id, principal), do: Memberships.list_members(id), else: [])}
  end
  defp metadata(id), do: get_in(State.get(id, @group) || %{}, ["content"]) || %{}
  defp lock!(id), do: Repo.one(from r in Room, where: r.id == ^id, lock: "FOR UPDATE") || Repo.rollback(:forbidden)
  defp owner!(g, id) do
    unless Memberships.joined?(id, g.principal_id) && Matrix.creator?(id, g.principal_id), do: Repo.rollback(:forbidden)
  end
  defp target!(mxid) do
    with {:ok, username} <- Identity.parse_user_id(mxid),
         {:ok, p} <- Accounts.fetch_user(username), true <- Accounts.active?(p) do
      p.id
    else
      _ -> Repo.rollback(:invalid_member)
    end
  end
  defp member!(g, id, target, membership) do
    event!(g, id, "m.room.member", %{"membership" => membership, "is_direct" => metadata(id)["kind"] == "dm"}, user_id(target))
  end
  defp audit!(g, id, action, target), do: event!(g, id, "cool.gravitas.delegation.v1",
    %{"version" => 1, "action" => action, "target" => target, "app_origin" => g.app_origin}, nil)
  defp event!(g, id, type, content, state_key, event_id \\ nil) do
    ctx = %Context{room_id: id, principal_id: g.principal_id, sender: user_id(g.principal_id),
      event_id: event_id || Identity.new_event_id(), type: type, content: content,
      state_key: state_key, origin_server_ts: System.system_time(:millisecond)}
    if type == "m.room.member" do
      {:ok, target} = Identity.parse_user_id(state_key)
      p = Repo.get_by!(Principal, username: target)
      case Memberships.upsert_membership(id, p.id, content["membership"], ctx) do
        {:ok, _} -> :ok
        {:error, _} -> Repo.rollback(:invalid_membership)
      end
    end
    if is_binary(state_key), do: State.upsert(id, state_key, type, content, ctx.event_id, ctx.origin_server_ts)
    {:ok, e} = Events.persist(ctx, %{"content" => content})
    Events.to_client_event(e)
  end
  defp access(g, id) do
    with :ok <- allowed(g, id), true <- Memberships.joined?(id, g.principal_id) do
      :ok
    else
      _ -> {:error, :forbidden}
    end
  end
  defp allowed(g, id) do
    if match?({:ok, _}, Ecto.UUID.cast(id)) && Grants.room_allowed?(g, id), do: :ok, else: {:error, :forbidden}
  end
  defp scope(g, s), do: if(s in g.scopes, do: :ok, else: {:error, :insufficient_scope})
  defp user_id(id), do: Repo.get!(Principal, id).username |> Identity.user_id()
  defp text?(s, max), do: is_binary(s) && String.trim(s) != "" && byte_size(s) <= max
  defp txn?(s), do: is_binary(s) && byte_size(s) in 1..128 && String.match?(s, ~r/^[a-zA-Z0-9_-]+$/)
  defp digest(s), do: :crypto.hash(:sha256, s) |> Base.url_encode64(padding: false)
  defp uuid(s) do
    <<a::32, b::16, c::12, d::14, e::48, _::bitstring>> = :crypto.hash(:sha256, s)
    Ecto.UUID.load!(<<a::32, b::16, 5::4, c::12, 2::2, d::14, e::48>>)
  end
  defp transact(fun), do: Repo.transaction(fun)
end
