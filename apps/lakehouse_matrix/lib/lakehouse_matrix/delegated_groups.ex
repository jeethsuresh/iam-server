defmodule LakehouseMatrix.DelegatedGroups do
  @moduledoc "Delegated, invitation-only groups over the existing Gravitas room ACL."
  import Ecto.Query
  alias LakehouseIam.{Repo, IAM, Accounts}
  alias LakehouseIam.Apps.Grants
  alias LakehouseIam.Schema.{AppGrant, Principal}
  alias LakehouseMatrix.{Rooms, Memberships, Identity, State, Events, Matrix, Social}
  alias LakehouseMatrix.Schema.{Room, RoomEvent, RiverChannel, RiverRoomRead, RiverDirect}
  alias LakehouseMatrix.Events.Context
  alias LakehouseMatrix.Protocol.Graph

  @group "cool.gravitas.river.group.v1"
  @types ~w(m.room.message m.reaction cool.gravitas.river.post.v1 cool.gravitas.river.discussion.v1)

  def authorized?(g, id, permission) do
    LakehouseMatrix.AccountModeration.check(
      g.principal_id,
      if(permission == "chats.write", do: :write, else: :read)
    ) == :ok and
      permission in g.scopes and access(g, id) == :ok and
      (permission != "chats.write" or
         (is_nil(State.get(id, "m.room.encryption")) and
            LakehouseMatrix.RiverPublishing.writer_allowed?(id, g.principal_id) and
            IAM.can?(g.principal_id, "matrix.room.send", Identity.resource_arn(id)) and
            case Repo.get(RiverDirect, id) do
              nil -> true
              direct -> not Social.blocked?(direct.low_id, direct.high_id)
            end))
  end

  def template_state!(g, id, type, content, key), do: event!(g, id, type, content, key)

  def visible?(g, id),
    do:
      allowed(g, id) == :ok and
        (Memberships.joined?(id, g.principal_id) or Memberships.invited?(id, g.principal_id))

  def list(grant) do
    (Memberships.joined_room_ids(grant.principal_id) ++
       Memberships.invited_room_ids(grant.principal_id))
    |> Enum.uniq()
    |> Enum.filter(&(allowed(grant, &1) == :ok or invitation_allowed?(grant, &1)))
    |> Enum.map(&describe(&1, grant.principal_id))
  end

  def subgroups(grant, id) do
    with :ok <- scope(grant, "chats.list"),
         :ok <- scope(grant, "chats.read"),
         :ok <- access(grant, id) do
      transact(fn ->
        unless access(grant, id) == :ok, do: Repo.rollback(:forbidden)

        groups =
          list(grant) |> Enum.filter(&(&1.membership == "join" and access(grant, &1.id) == :ok))

        LakehouseIam.ParticipantSets.projection(id, groups)
      end)
    end
  end

  def overview(grant) do
    with :ok <- scope(grant, "chats.list") do
      groups = list(grant)
      ids = for g <- groups, g.membership == "join", do: g.id
      space_ids = for g <- groups, g.membership == "join" and g.kind == "space", do: g.id

      recent =
        if "chats.read" in grant.scopes do
          rows =
            Repo.all(
              from e in RoomEvent,
                where: e.room_id in ^ids and is_nil(e.state_key) and e.type in ^@types,
                where: e.type in ["m.room.message", "m.reaction"] or e.room_id in ^space_ids,
                order_by: [desc: e.inserted_at, desc: e.id],
                limit: 200
            )

          projected =
            rows
            |> Enum.group_by(& &1.room_id)
            |> Enum.flat_map(fn {_id, entries} ->
              LakehouseMatrix.RiverContent.decorate(entries, grant.principal_id)
            end)
            |> Map.new(&{&1["event_id"], &1})

          rows
          |> Enum.map(fn e ->
            group = Enum.find(groups, &(&1.id == e.room_id))

            Map.merge(projected[e.event_id], %{
              "group_id" => e.room_id,
              "group_name" => group.name
            })
          end)
          |> LakehouseMatrix.RiverContent.budget()
        else
          []
        end

      {:ok, %{groups: groups, recent: recent}}
    end
  end

  def create(grant, params, internal \\ false) do
    with :ok <- scope(grant, "groups.create"),
         true <- text?(params["name"], 80),
         true <-
           params["kind"] in ["space", "dm", "group"] or
             (internal and params["kind"] in ["post_comments", "call_chat"]),
         true <- txn?(params["txn_id"]),
         true <- IAM.can?(grant.principal_id, "matrix.room.create", nil) do
      transact(fn ->
        locked =
          Repo.one(from g in AppGrant, where: g.id == ^grant.id, lock: "FOR UPDATE") ||
            Repo.rollback(:forbidden)

        id = uuid("#{grant.id}|#{grant.principal_id}|#{grant.app_origin}|#{params["txn_id"]}")

        case Rooms.get_room(id) do
          nil ->
            {:ok, room} =
              Repo.insert(Room.changeset(%Room{id: id}, %{name: String.trim(params["name"])}))

            creator = user_id(grant.principal_id)
            content = %{"creator" => creator, "room_version" => "11"}

            content =
              if params["kind"] in ["call_chat", "post_comments"],
                do: Map.put(content, "m.federate", false),
                else: content

            content =
              if params["kind"] == "space", do: Map.put(content, "type", "m.space"), else: content

            event!(grant, id, "m.room.create", content, "")
            event!(grant, id, "m.room.name", %{"name" => room.name}, "")

            if is_binary(params["description"]) and byte_size(params["description"]) <= 2000 and
                 String.length(params["description"]) <= 500,
               do: event!(grant, id, "m.room.topic", %{"topic" => params["description"]}, "")

            event!(grant, id, "m.room.join_rules", %{"join_rule" => "invite"}, "")

            event!(
              grant,
              id,
              "m.room.history_visibility",
              %{"history_visibility" => "shared"},
              ""
            )

            event!(
              grant,
              id,
              "m.room.power_levels",
              %{
                "users" => %{creator => 100},
                "users_default" => 0,
                "events_default" => 0,
                "state_default" => 100,
                "invite" => 100,
                "kick" => 100,
                "ban" => 100
              },
              ""
            )

            event!(
              grant,
              id,
              @group,
              %{"version" => 1, "kind" => params["kind"], "request_id" => params["txn_id"]},
              ""
            )

            member!(grant, id, grant.principal_id, "join")

            if locked.room_mode == :selected do
              locked
              |> AppGrant.changeset(%{room_ids: Enum.uniq(locked.room_ids ++ [id])})
              |> Repo.update!()
            end

            audit!(grant, id, "create", creator)

          _ ->
            unless Matrix.creator?(id, grant.principal_id), do: Repo.rollback(:forbidden)
            meta = metadata(id)

            unless meta["kind"] == params["kind"] &&
                     Rooms.get_room(id).name == String.trim(params["name"]),
                   do: Repo.rollback(:transaction_conflict)
        end

        if params["kind"] == "space" and "spaces.channels" in grant.scopes and
             "groups.manage" in grant.scopes do
          refreshed = %{grant | room_ids: Enum.uniq(grant.room_ids ++ [id])}

          for {name, kind, suffix} <- [
                {"lobby", "text", "lobby"},
                {"The Lounge", "drop_in", "lounge"}
              ] do
            case create_channel(refreshed, id, %{
                   "name" => name,
                   "kind" => kind,
                   "txn_id" => "default-" <> suffix
                 }) do
              {:ok, _} -> :ok
              {:error, e} -> Repo.rollback(e)
            end
          end
        end

        describe(id, grant.principal_id)
      end)
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_request}
    end
  end

  def direct(grant, params) do
    with :ok <- scope(grant, "groups.create"),
         :ok <- scope(grant, "groups.manage"),
         :ok <- scope(grant, "contacts.read"),
         :ok <- scope(grant, "groups.join"),
         {:ok, username} <- Identity.parse_user_id(params["user_id"]),
         {:ok, person} <- Accounts.fetch_user(username),
         true <- person.active and person.id != grant.principal_id do
      transact(fn ->
        [low, high] = ids = Enum.sort([grant.principal_id, person.id])

        Repo.all(
          from p in Principal, where: p.id in ^ids, order_by: p.id, lock: "FOR NO KEY UPDATE"
        )

        unless Social.friends?(grant.principal_id, person.id) and
                 LakehouseIam.Contacts.available_in_app?(person.id, grant.app_origin),
               do: Repo.rollback(:forbidden)

        locked =
          Repo.one(from g in AppGrant, where: g.id == ^grant.id, lock: "FOR UPDATE") ||
            Repo.rollback(:forbidden)

        direct = Repo.get_by(RiverDirect, low_id: low, high_id: high)

        id =
          if direct do
            lock!(direct.id)
            current = Memberships.membership(direct.id, grant.principal_id)

            unless current == "invite" or
                     (current == "join" and Grants.room_allowed?(grant, direct.id)),
                   do: Repo.rollback(:forbidden)

            if current == "invite" do
              member!(grant, direct.id, grant.principal_id, "join")
              audit!(grant, direct.id, "accept", user_id(grant.principal_id))
            end

            direct.id
          else
            txn = "friend-" <> digest(Enum.join(ids, "|"))

            case create(grant, %{
                   "name" =>
                     "#{Repo.get!(Principal, grant.principal_id).username} & #{person.username}",
                   "kind" => "dm",
                   "txn_id" => txn
                 }) do
              {:ok, group} ->
                Repo.insert!(%RiverDirect{id: group.id, low_id: low, high_id: high})
                LakehouseMatrix.ClientStore.link_direct(low, high, Identity.room_id(group.id))
                member!(grant, group.id, person.id, "invite")
                audit!(grant, group.id, "invite", user_id(person.id))
                group.id

              {:error, e} ->
                Repo.rollback(e)
            end
          end

        if locked.room_mode == :selected do
          locked
          |> AppGrant.changeset(%{room_ids: Enum.uniq(locked.room_ids ++ [id])})
          |> Repo.update!()
        end

        describe(id, grant.principal_id)
      end)
    else
      {:error, e} -> {:error, e}
      _ -> {:error, :invalid_request}
    end
  end

  def channels(grant, id) do
    with :ok <- scope(grant, "chats.list"),
         :ok <- access(grant, id),
         true <- metadata(id)["kind"] == "space" do
      rooms =
        channel_ids(id)
        |> Enum.filter(&(allowed(grant, &1) == :ok))
        |> Enum.map(&describe(&1, grant.principal_id))

      {:ok, %{channels: rooms}}
    else
      {:error, e} -> {:error, e}
      _ -> {:error, :invalid_request}
    end
  end

  def create_channel(grant, id, params) do
    with :ok <- scope(grant, "groups.create"),
         :ok <- scope(grant, "groups.manage"),
         :ok <- access(grant, id),
         true <- metadata(id)["kind"] == "space",
         true <- text?(params["name"], 80) and txn?(params["txn_id"]),
         true <- params["kind"] in ["text", "drop_in"],
         true <- IAM.can?(grant.principal_id, "matrix.room.create", nil) do
      transact(fn ->
        locked =
          Repo.one(from g in AppGrant, where: g.id == ^grant.id, lock: "FOR UPDATE") ||
            Repo.rollback(:forbidden)

        lock!(id)
        LakehouseMatrix.AccountModeration.require!(grant.principal_id)
        owner!(grant, id)
        child = uuid("channel|#{grant.id}|#{id}|#{params["txn_id"]}")

        case Repo.get(RiverChannel, child) do
          nil ->
            if length(channel_ids(id)) >= 100, do: Repo.rollback(:too_many_channels)
            Repo.insert!(Room.changeset(%Room{id: child}, %{name: String.trim(params["name"])}))
            Repo.insert!(%RiverChannel{id: child, space_id: id, kind: params["kind"]})

            event!(
              grant,
              child,
              "m.room.create",
              %{"creator" => user_id(grant.principal_id), "room_version" => "11"},
              ""
            )

            event!(grant, child, "m.room.name", %{"name" => String.trim(params["name"])}, "")
            event!(grant, child, "m.room.join_rules", %{"join_rule" => "invite"}, "")

            event!(
              grant,
              child,
              "m.room.history_visibility",
              %{"history_visibility" => "shared"},
              ""
            )

            event!(
              grant,
              child,
              "m.room.power_levels",
              %{
                "users" => %{user_id(grant.principal_id) => 100},
                "state_default" => 100,
                "invite" => 100,
                "kick" => 100,
                "ban" => 100
              },
              ""
            )

            event!(
              grant,
              child,
              @group,
              %{
                "version" => 1,
                "kind" => "channel",
                "parent_id" => id,
                "channel_kind" => params["kind"]
              },
              ""
            )

            event!(
              grant,
              child,
              "m.space.parent",
              %{"via" => [Identity.homeserver_domain()], "canonical" => true},
              Identity.room_id(id)
            )

            event!(
              grant,
              id,
              "m.space.child",
              %{"via" => [Identity.homeserver_domain()], "suggested" => true},
              Identity.room_id(child)
            )

            for {principal, membership} <- Memberships.membership_map(id),
                membership in ["join", "invite"],
                do: member!(grant, child, principal, membership)

            if locked.room_mode == :selected do
              locked
              |> AppGrant.changeset(%{room_ids: Enum.uniq(locked.room_ids ++ [child])})
              |> Repo.update!()
            end

            audit!(grant, id, "channel.create", Identity.room_id(child))

          c ->
            unless c.space_id == id and c.kind == params["kind"] and
                     Rooms.get_room(child).name == String.trim(params["name"]),
                   do: Repo.rollback(:transaction_conflict)
        end

        describe(child, grant.principal_id)
      end)
    else
      {:error, e} -> {:error, e}
      _ -> {:error, :invalid_request}
    end
  end

  def mark_read(grant, id, params) do
    with :ok <- scope(grant, "chats.read"),
         :ok <- access(grant, id),
         true <- is_binary(params["event_id"]) do
      transact(fn ->
        lock!(id)
        unless access(grant, id) == :ok, do: Repo.rollback(:forbidden)
        event = Repo.get_by(RoomEvent, room_id: id, event_id: params["event_id"])
        unless event && is_nil(event.state_key), do: Repo.rollback(:invalid_event)
        current = Repo.get_by(RiverRoomRead, principal_id: grant.principal_id, room_id: id)
        previous = if current, do: Repo.get(RoomEvent, current.event_id)

        if is_nil(previous) or after_event?(event, previous) do
          changes = %{event_id: event.id}

          if current do
            Ecto.Changeset.change(current, changes) |> Repo.update!()
          else
            Repo.insert!(%RiverRoomRead{
              principal_id: grant.principal_id,
              room_id: id,
              event_id: event.id
            })
          end
        end

        %{ok: true}
      end)
    else
      {:error, e} -> {:error, e}
      _ -> {:error, :invalid_request}
    end
  end

  def update(grant, id, params) do
    with :ok <- scope(grant, "groups.manage"),
         :ok <- access(grant, id),
         true <- text?(params["name"], 80) do
      transact(fn ->
        lock!(id)
        owner!(grant, id)

        {:ok, _} =
          Rooms.get_room(id)
          |> Room.changeset(%{name: String.trim(params["name"])})
          |> Repo.update()

        event!(grant, id, "m.room.name", %{"name" => String.trim(params["name"])}, "")

        if is_binary(params["description"]) and byte_size(params["description"]) <= 2000 and
             String.length(params["description"]) <= 500,
           do: event!(grant, id, "m.room.topic", %{"topic" => params["description"]}, "")

        audit!(grant, id, "rename", user_id(grant.principal_id))
        describe(id, grant.principal_id)
      end)
    else
      {:error, e} -> {:error, e}
      _ -> {:error, :invalid_request}
    end
  end

  def membership(grant, id, params) do
    with :ok <-
           scope(
             grant,
             if(params["action"] == "public_join", do: "groups.join", else: "groups.manage")
           ),
         :ok <-
           if(
             params["action"] == "public_join" and
               LakehouseMatrix.RiverPublishing.public_join?(id),
             do: :ok,
             else: membership_allowed(grant, id)
           ),
         true <- params["action"] in ~w(invite accept leave remove public_join),
         :ok <- root_membership(id) do
      transact(fn ->
        locked_grant =
          if grant.id,
            do:
              Repo.one(from g in AppGrant, where: g.id == ^grant.id, lock: "FOR UPDATE") ||
                Repo.rollback(:forbidden)

        lock!(id)
        actor = grant.principal_id
        action = params["action"]

        target =
          if action in ~w(accept leave public_join), do: actor, else: target!(params["user_id"])

        current = Memberships.membership(id, target)
        direct = Repo.get(RiverDirect, id)
        if direct && target not in [direct.low_id, direct.high_id], do: Repo.rollback(:forbidden)

        membership =
          case action do
            "public_join" ->
              unless LakehouseMatrix.RiverPublishing.public_join?(id),
                do: Repo.rollback(:forbidden)

              "join"

            "invite" ->
              owner!(grant, id)

              if target == actor || current in ~w(join invite),
                do: Repo.rollback(:invalid_membership)

              "invite"

            "accept" ->
              unless current == "invite", do: Repo.rollback(:forbidden)
              "join"

            "leave" ->
              unless current in ~w(join invite), do: Repo.rollback(:forbidden)
              "leave"

            "remove" ->
              owner!(grant, id)

              if target == actor || current not in ~w(join invite),
                do: Repo.rollback(:invalid_membership)

              "leave"
          end

        # A leaving actor cannot send a timeline audit after leaving. An
        # invitation decline is already audited by its signed membership event.
        leaving = target == actor and membership == "leave"
        if leaving and current == "join", do: audit!(grant, id, action, user_id(target))
        event = member!(grant, id, target, membership)
        for child <- channel_ids(id), do: member!(grant, child, target, membership)

        if (action in ["accept", "public_join"] and locked_grant) &&
             locked_grant.room_mode == :selected do
          locked_grant
          |> AppGrant.changeset(%{room_ids: Enum.uniq(locked_grant.room_ids ++ [id])})
          |> Repo.update!()
        end

        unless leaving, do: audit!(grant, id, action, user_id(target))
        %{"event_id" => event["event_id"], "membership" => membership}
      end)
    else
      {:error, e} -> {:error, e}
      _ -> {:error, :invalid_request}
    end
  end

  def timeline(grant, id, params) do
    with :ok <- scope(grant, "chats.read"),
         :ok <- access(grant, id),
         :ok <- valid_cursor(params["before"]) do
      transact(fn ->
        lock!(id)
        unless access(grant, id) == :ok, do: Repo.rollback(:forbidden)
        value = params["limit"]

        limit =
          cond do
            is_integer(value) ->
              min(max(value, 1), 200)

            is_binary(value) ->
              case Integer.parse(value) do
                {n, ""} -> min(max(n, 1), 200)
                _ -> 100
              end

            true ->
              100
          end

        query =
          from e in RoomEvent,
            where: e.room_id == ^id and is_nil(e.state_key) and e.type != "m.rtc.member",
            order_by: [desc: e.inserted_at, desc: e.id],
            limit: ^(limit + 1)

        query =
          if params["before"] do
            cursor = Repo.get_by(RoomEvent, room_id: id, event_id: params["before"])
            unless cursor, do: Repo.rollback(:invalid_cursor)

            from e in query,
              where:
                e.inserted_at < ^cursor.inserted_at or
                  (e.inserted_at == ^cursor.inserted_at and e.id < ^cursor.id)
          else
            query
          end

        rows = Repo.all(query)
        candidates = Enum.take(rows, limit)

        events =
          candidates
          |> LakehouseMatrix.RiverContent.decorate(grant.principal_id)
          |> LakehouseMatrix.RiverContent.budget()

        page = Enum.take(candidates, length(events))

        %{
          events: Enum.reverse(events),
          next_cursor: if(length(rows) > length(page), do: List.last(page).event_id, else: nil)
        }
      end)
    end
  end

  def send(grant, id, type, txn, content) do
    with :ok <- scope(grant, "chats.write"),
         :ok <- access(grant, id),
         true <- type in @types && txn?(txn) && is_map(content),
         {:ok, content} <- LakehouseMatrix.RiverContent.bind_space(id, type, content),
         true <- byte_size(Jason.encode!(content)) <= 250_000,
         true <- IAM.can?(grant.principal_id, "matrix.room.send", Identity.resource_arn(id)),
         :ok <- validate(type, content),
         :ok <- LakehouseMatrix.RiverFiles.validate(content, id),
         true <-
           LakehouseMatrix.RiverPublishing.valid_send?(id, type, content, grant.principal_id) do
      transact(fn ->
        lock!(id)
        unless access(grant, id) == :ok, do: Repo.rollback(:forbidden)

        unless LakehouseMatrix.RiverPublishing.writer_allowed?(id, grant.principal_id) and
                 LakehouseMatrix.RiverPublishing.valid_send?(
                   id,
                   type,
                   content,
                   grant.principal_id
                 ),
               do: Repo.rollback(:forbidden)

        direct = Repo.get(RiverDirect, id)
        if direct && Social.blocked?(direct.low_id, direct.high_id), do: Repo.rollback(:forbidden)
        relation!(id, type, content)
        event_id = "$river_" <> digest("#{grant.principal_id}|#{grant.app_origin}|#{id}|#{txn}")

        decorated =
          Map.put(content, "cool.gravitas.delegation", %{
            "version" => 1,
            "app_origin" => grant.app_origin
          })

        result =
          case request_event(event_id) do
            nil ->
              event!(grant, id, type, decorated, nil, event_id)

            e ->
              unless e.type == type && e.content == decorated,
                do: Repo.rollback(:transaction_conflict)

              Events.to_client_event(e)
          end

        LakehouseMatrix.RiverFiles.register!(grant, id, result, content)
        result
      end)
    else
      {:error, e} -> {:error, e}
      _ -> {:error, :invalid_event}
    end
  end

  @doc false
  def with_room(grant, id, permission, callback)
      when permission in ["chats.read", "chats.write"] do
    with :ok <- scope(grant, permission), :ok <- access(grant, id) do
      transact(fn ->
        lock!(id)

        LakehouseMatrix.AccountModeration.require!(
          grant.principal_id,
          if(permission == "chats.write", do: :write, else: :read)
        )

        unless access(grant, id) == :ok, do: Repo.rollback(:forbidden)

        if permission == "chats.write" do
          if State.get(id, "m.room.encryption"), do: Repo.rollback(:encryption_required)

          unless LakehouseMatrix.RiverPublishing.writer_allowed?(id, grant.principal_id),
            do: Repo.rollback(:forbidden)

          unless IAM.can?(grant.principal_id, "matrix.room.send", Identity.resource_arn(id)),
            do: Repo.rollback(:forbidden)

          direct = Repo.get(RiverDirect, id)

          if direct && Social.blocked?(direct.low_id, direct.high_id),
            do: Repo.rollback(:forbidden)
        end

        callback.()
      end)
    end
  end

  @doc false
  def content_event!(g, id, type, content, txn) do
    event_id =
      "$river_content_" <> digest("#{g.principal_id}|#{g.app_origin}|#{id}|#{type}|#{txn}")

    decorated =
      Map.put(content, "cool.gravitas.delegation", %{"version" => 1, "app_origin" => g.app_origin})

    case request_event(event_id) do
      nil ->
        event!(g, id, type, decorated, nil, event_id)

      e ->
        unless e.room_id == id and e.type == type and e.content == decorated,
          do: Repo.rollback(:transaction_conflict)

        Events.to_client_event(e)
    end
  end

  @doc false
  def request_event(request) do
    event =
      Repo.one(
        from r in "matrix_river_requests", where: r.request_id == ^request, select: r.event_id
      ) || request

    Repo.get_by(RoomEvent, event_id: event)
  end

  defp validate("m.reaction", %{
         "m.relates_to" => %{"rel_type" => "m.annotation", "event_id" => id, "key" => key}
       })
       when is_binary(id) do
    if (is_binary(key) and byte_size(key) in 1..64) or LakehouseMatrix.RiverReactions.valid?(key),
      do: :ok,
      else: {:error, :invalid_event}
  end

  defp validate(type, %{"body" => body} = c) when type != "m.reaction" do
    valid =
      text?(body, if(type == "m.room.message", do: 16000, else: 40000)) &&
        String.length(body) <= 40000 &&
        (type == "m.room.message" ||
           (c["version"] == 1 && text?(c["title"], 160)))

    if valid, do: :ok, else: {:error, :invalid_event}
  end

  defp validate(_, _), do: {:error, :invalid_event}

  defp relation!(id, type, content) do
    relation = content["m.relates_to"]

    if relation do
      unless is_map(relation), do: Repo.rollback(:invalid_relation)
      reply = relation["m.in_reply_to"]

      if not is_nil(reply) and (not is_map(reply) or not is_binary(reply["event_id"])),
        do: Repo.rollback(:invalid_relation)

      targets =
        [relation["event_id"], if(is_map(reply), do: reply["event_id"])] |> Enum.reject(&is_nil/1)

      unless targets != [] and
               Enum.all?(targets, fn target ->
                 is_binary(target) and
                   Repo.exists?(
                     from e in RoomEvent,
                       where: e.room_id == ^id and e.event_id == ^target and is_nil(e.state_key)
                   )
               end),
             do: Repo.rollback(:invalid_relation)

      unless relation["rel_type"] in [nil, "m.thread", "m.annotation"],
        do: Repo.rollback(:invalid_relation)

      if type != "m.reaction" && relation["rel_type"] == "m.annotation",
        do: Repo.rollback(:invalid_relation)

      if relation["rel_type"] == "m.thread" do
        unless type == "m.room.message" and is_binary(relation["event_id"]),
          do: Repo.rollback(:invalid_relation)

        root = Repo.get_by(RoomEvent, room_id: id, event_id: relation["event_id"])

        if root && LakehouseMatrix.RiverContent.entry?(root.type),
          do: LakehouseMatrix.RiverContent.require_space!(id)

        unless root && LakehouseMatrix.RiverPublishing.replies_allowed?(root) &&
                 root.type in [
                   "m.room.message",
                   "cool.gravitas.river.post.v1",
                   "cool.gravitas.river.discussion.v1"
                 ] &&
                 get_in(root.content, ["m.relates_to", "rel_type"]) != "m.thread",
               do: Repo.rollback(:invalid_relation)

        if reply && reply["event_id"] != root.event_id do
          quoted = Repo.get_by!(RoomEvent, room_id: id, event_id: reply["event_id"])

          canonical =
            get_in(quoted.content, ["m.relates_to", "rel_type"]) == "m.thread" &&
              get_in(quoted.content, ["m.relates_to", "event_id"]) == root.event_id

          legacy =
            get_in(quoted.content, ["m.relates_to", "m.in_reply_to", "event_id"]) == root.event_id

          unless canonical or legacy, do: Repo.rollback(:invalid_relation)
        end
      end
    end
  end

  defp describe(id, principal) do
    r = Rooms.get_room(id)
    channel = Repo.get(RiverChannel, id)

    unread =
      if Memberships.joined?(id, principal),
        do: unread(id, principal),
        else: %{count: 0, preview: "", timestamp: 0}

    %{
      id: id,
      room_id: Identity.room_id(id),
      name: r.name,
      kind: metadata(id)["kind"] || "group",
      description: get_in(State.get(id, "m.room.topic") || %{}, ["content", "topic"]) || "",
      parent_id: channel && channel.space_id,
      context_id:
        get_in(State.get(id, "cool.gravitas.river.context.v1") || %{}, ["content", "context_id"]),
      channel_kind: channel && channel.kind,
      membership: Memberships.membership(id, principal),
      owner: Matrix.creator?(id, principal),
      unread_count: unread.count,
      unread_preview: unread.preview,
      last_activity_at: unread.timestamp,
      members: if(Memberships.joined?(id, principal), do: Memberships.list_members(id), else: [])
    }
    |> Map.merge(
      if Memberships.joined?(id, principal),
        do: LakehouseIam.ParticipantSets.current(id),
        else: %{subgroup_id: nil, subgroup_revision: nil}
    )
  end

  defp unread(id, principal) do
    read = Repo.get_by(RiverRoomRead, principal_id: principal, room_id: id)
    cursor = if read, do: Repo.get(RoomEvent, read.event_id)

    query =
      from e in RoomEvent,
        join: m in LakehouseMatrix.Schema.RoomMembership,
        on: m.room_id == e.room_id and m.principal_id == ^principal,
        where:
          e.room_id == ^id and is_nil(e.state_key) and e.inserted_at >= m.updated_at and
            e.principal_id != ^principal and
            e.type in ["m.room.message", "cool.gravitas.river.invitation.v1"] and
            fragment("COALESCE(? #>> '{m.relates_to,rel_type}', '') != 'm.thread'", e.content)

    query =
      if cursor do
        from e in query,
          where:
            e.inserted_at > ^cursor.inserted_at or
              (e.inserted_at == ^cursor.inserted_at and e.id > ^cursor.id)
      else
        query
      end

    latest =
      Repo.one(from e in query, order_by: [desc: e.inserted_at, desc: e.id], limit: 1, select: e)

    %{
      count: Repo.aggregate(query, :count, :id),
      preview: if(latest, do: String.slice(latest.content["body"] || "", 0, 220), else: ""),
      timestamp: if(latest, do: latest.origin_server_ts, else: 0)
    }
  end

  defp after_event?(a, b),
    do:
      DateTime.compare(a.inserted_at, b.inserted_at) == :gt or
        (a.inserted_at == b.inserted_at and a.id > b.id)

  defp metadata(id), do: get_in(State.get(id, @group) || %{}, ["content"]) || %{}

  defp channel_ids(id),
    do: Repo.all(from c in RiverChannel, where: c.space_id == ^id, order_by: c.id, select: c.id)

  defp lock!(id) do
    # Space mutations and all child writes take the same root lock first.
    root =
      case Repo.get(RiverChannel, id) do
        nil ->
          case LakehouseMatrix.RiverPublishing.thread_record(id) do
            nil ->
              case LakehouseMatrix.RiverRtc.chat_record(id) do
                nil -> id
                chat -> chat.parent_id
              end

            p ->
              p.space_id
          end

        c ->
          c.space_id
      end

    Repo.one(from r in Room, where: r.id == ^root, lock: "FOR UPDATE") ||
      Repo.rollback(:forbidden)
  end

  defp owner!(g, id) do
    unless Memberships.joined?(id, g.principal_id) && Matrix.creator?(id, g.principal_id),
      do: Repo.rollback(:forbidden)
  end

  defp target!(mxid) do
    with {:ok, username} <- Identity.parse_user_id(mxid),
         {:ok, p} <- Accounts.fetch_user(username),
         true <- Accounts.active?(p) do
      p.id
    else
      _ -> Repo.rollback(:invalid_member)
    end
  end

  defp member!(g, id, target, membership) do
    current = Memberships.membership(id, target)

    if Graph.room(id) && membership == "join" && current != "join" && target != g.principal_id &&
         current != "invite" do
      event!(g, id, "m.room.member", %{"membership" => "invite"}, user_id(target))
    end

    actor = if Graph.room(id) && membership == "join", do: %{g | principal_id: target}, else: g

    if Graph.room(id) && current == membership do
      event_id = get_in(State.get(id, "m.room.member", user_id(target)), ["event_id"])
      Events.to_client_event(Repo.get_by!(RoomEvent, event_id: event_id))
    else
      event!(
        actor,
        id,
        "m.room.member",
        %{"membership" => membership, "is_direct" => metadata(id)["kind"] == "dm"},
        user_id(target)
      )
    end
  end

  defp audit!(g, id, action, target),
    do:
      event!(
        g,
        id,
        "cool.gravitas.delegation.v1",
        %{"version" => 1, "action" => action, "target" => target, "app_origin" => g.app_origin},
        nil
      )

  defp event!(g, id, type, content, state_key, event_id \\ nil) do
    case LakehouseMatrix.AccountModeration.event(
           user_id(g.principal_id),
           id,
           type,
           content,
           state_key
         ) do
      :ok -> :ok
      {:error, reason} -> Repo.rollback(reason)
    end

    # River's delegated API carries plaintext content. A standard Matrix
    # client must encrypt timeline events itself once encryption is enabled.
    # Check under the stream/room transaction so enabling encryption cannot
    # race a pending message, edit, reaction or attachment manifest.
    if is_nil(state_key) and type not in ~w(m.room.encrypted m.room.redaction) and
         State.get(id, "m.room.encryption"),
       do: Repo.rollback(:encryption_required)

    cond do
      type == "m.room.create" && LakehouseMatrix.Protocol.Rooms.enabled?() ->
        creation = Map.drop(content, ["creator", "room_version"])
        {:ok, event} = Graph.create(id, user_id(g.principal_id), "12", creation)

        {:ok, _} =
          Graph.send(
            id,
            user_id(g.principal_id),
            "m.room.member",
            %{"membership" => "join"},
            user_id(g.principal_id)
          )

        Events.to_client_event(Repo.get_by!(RoomEvent, event_id: event["event_id"]))

      metadata = Graph.room(id) ->
        content = native_content(metadata, type, content)

        case Graph.send(id, user_id(g.principal_id), type, content, state_key) do
          {:ok, event} ->
            if event_id do
              Repo.insert_all("matrix_river_requests", [
                %{
                  request_id: event_id,
                  event_id: event["event_id"],
                  local_room_id: LakehouseMatrix.ClientStore.dump_id(id)
                }
              ])
            end

            Events.to_client_event(Repo.get_by!(RoomEvent, event_id: event["event_id"]))

          {:error, reason} ->
            Repo.rollback(reason)
        end

      true ->
        legacy_event!(g, id, type, content, state_key, event_id)
    end
  end

  defp native_content(metadata, "m.room.power_levels", content) do
    creators =
      LakehouseMatrix.Protocol.Authorization.creators(
        LakehouseMatrix.Federation.RoomAccess.state(metadata)
      )

    if metadata.version == "12",
      do: Map.put(content, "users", Map.drop(content["users"] || %{}, creators)),
      else: content
  end

  defp native_content(metadata, "m.room.join_rules", content) do
    case Repo.get(RiverChannel, metadata.local_room_id) do
      nil ->
        content

      channel ->
        %{
          "join_rule" => "restricted",
          "allow" => [
            %{"type" => "m.room_membership", "room_id" => Identity.room_id(channel.space_id)}
          ]
        }
    end
  end

  defp native_content(_, _, content), do: content

  defp legacy_event!(g, id, type, content, state_key, event_id) do
    ctx = %Context{
      room_id: id,
      principal_id: g.principal_id,
      sender: user_id(g.principal_id),
      event_id: event_id || Identity.new_event_id(),
      type: type,
      content: content,
      state_key: state_key,
      origin_server_ts: System.system_time(:millisecond),
      sticky_duration_ms: if(type == "m.rtc.member", do: 70_000)
    }

    if type == "m.room.member" do
      {:ok, target} = Identity.parse_user_id(state_key)
      p = Repo.get_by!(Principal, username: target)

      case Memberships.upsert_membership(id, p.id, content["membership"], ctx) do
        {:ok, _} -> :ok
        {:error, _} -> Repo.rollback(:invalid_membership)
      end
    end

    if is_binary(state_key),
      do: State.upsert(id, state_key, type, content, ctx.event_id, ctx.origin_server_ts)

    {:ok, e} = Events.persist(ctx, %{"content" => content})
    Events.to_client_event(e)
  end

  defp access(g, id) do
    with :ok <- allowed(g, id),
         true <- Memberships.joined?(id, g.principal_id),
         true <- parent_joined?(id, g.principal_id) do
      :ok
    else
      _ -> {:error, :forbidden}
    end
  end

  defp valid_cursor(nil), do: :ok
  defp valid_cursor(value) when is_binary(value) and byte_size(value) <= 512, do: :ok
  defp valid_cursor(_), do: {:error, :invalid_cursor}

  defp root_membership(id) do
    if is_nil(Repo.get(RiverChannel, id)) and is_nil(LakehouseMatrix.RiverRtc.chat_record(id)),
      do: :ok,
      else: {:error, :forbidden}
  end

  defp membership_allowed(g, id) do
    if allowed(g, id) == :ok or invitation_allowed?(g, id), do: :ok, else: {:error, :forbidden}
  end

  defp invitation_allowed?(g, id) do
    "groups.join" in g.scopes and match?({:ok, _}, Ecto.UUID.cast(id)) and
      is_nil(Repo.get(RiverChannel, id)) and Memberships.invited?(id, g.principal_id)
  end

  defp parent_joined?(id, principal) do
    case Repo.get(RiverChannel, id) do
      nil ->
        case LakehouseMatrix.RiverPublishing.thread_record(id) do
          nil -> true
          p -> p.visibility == "public" or Memberships.joined?(p.space_id, principal)
        end

      c ->
        Memberships.joined?(c.space_id, principal)
    end
  end

  defp allowed(g, id) do
    if match?({:ok, _}, Ecto.UUID.cast(id)) do
      direct = Grants.room_allowed?(g, id)

      inherited =
        case Repo.get(RiverChannel, id) do
          nil -> false
          c -> "spaces.channels" in g.scopes and Grants.room_allowed?(g, c.space_id)
        end

      call_chat = LakehouseMatrix.RiverRtc.chat_record(id)

      inherited_call =
        call_chat && "calls.join" in g.scopes && Grants.room_allowed?(g, call_chat.parent_id)

      if direct or inherited or inherited_call, do: :ok, else: {:error, :forbidden}
    else
      {:error, :forbidden}
    end
  end

  defp scope(g, s), do: if(s in g.scopes, do: :ok, else: {:error, :insufficient_scope})
  defp user_id(id), do: Repo.get!(Principal, id).username |> Identity.user_id()

  defp text?(s, max),
    do: is_binary(s) && String.trim(s) != "" && String.length(s) <= max && byte_size(s) <= max * 4

  defp txn?(s),
    do: is_binary(s) && byte_size(s) in 1..128 && String.match?(s, ~r/^[a-zA-Z0-9_-]+$/)

  defp digest(s), do: :crypto.hash(:sha256, s) |> Base.url_encode64(padding: false)

  defp uuid(s) do
    <<a::32, b::16, c::12, d::14, e::48, _::bitstring>> = :crypto.hash(:sha256, s)
    Ecto.UUID.load!(<<a::32, b::16, 5::4, c::12, 2::2, d::14, e::48>>)
  end

  defp transact(fun),
    do:
      LakehouseMatrix.Protocol.Policy.transaction(fn ->
        LakehouseMatrix.ClientStore.lock!()
        fun.()
      end)
end
