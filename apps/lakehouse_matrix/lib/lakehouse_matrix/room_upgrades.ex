defmodule LakehouseMatrix.RoomUpgrades do
  @moduledoc "Atomic replacement rooms, tombstones, local aliases and per-user upgrade settings."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientRooms, ClientStore, Identity}
  alias LakehouseMatrix.Protocol.{Authorization, Event, Graph, Policy, Rooms}
  alias LakehouseMatrix.Federation.RoomAccess

  @transfer ~w(m.room.server_acl m.room.encryption m.room.name m.room.avatar m.room.topic m.room.guest_access m.room.history_visibility m.room.join_rules m.space.child)

  def upgrade(principal, ref, params) do
    id = Ecto.UUID.generate()
    version = params["new_version"]

    with true <- version in Event.versions(),
         {:ok, room} <- ClientRooms.readable(principal, ref) do
      Policy.transaction(fn ->
        ClientStore.lock!()
        metadata = Graph.room(room.id) || Repo.rollback(:room_reset_required)
        state = RoomAccess.state(metadata)
        actor = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

        probe =
          Graph.template(metadata, Graph.load_graph(room.id), actor, "m.room.tombstone", %{}, "")

        require_ok!(Authorization.check(probe, state, metadata.version))

        case get_in(state, [{"m.room.tombstone", ""}, "content", "replacement_room"]) do
          target when is_binary(target) ->
            replacement = Graph.room_by_id(target)

            unless replacement && replacement.version == version,
              do: Repo.rollback(:already_upgraded)

            %{"replacement_room" => target}

          _ ->
            replace(principal, room, metadata, state, actor, id, version, params)
        end
      end)
    else
      false -> {:error, :unsupported_room_version}
      _ -> {:error, :forbidden}
    end
  end

  defp replace(principal, room, metadata, state, actor, id, version, params) do
    creation = get_in(state, [{"m.room.create", ""}, "content"]) || %{}
    creators = if version == "12", do: params["additional_creators"] || [], else: []

    unless is_list(creators) and length(creators) <= 1000 and
             Enum.all?(creators, &match?({:ok, _}, Event.user_domain(&1))),
           do: Repo.rollback(:invalid_param)

    predecessor = %{"room_id" => metadata.room_id}
    # A v11 ID is known before its create event. V12 permits predecessor without
    # event_id, avoiding a circular hash between create and tombstone events.
    {predecessor, tombstone} =
      if version == "11" do
        target = "!#{id}:#{Identity.homeserver_domain()}"

        event =
          require_ok!(
            Graph.send(
              room.id,
              actor,
              "m.room.tombstone",
              %{"body" => "This room has been upgraded", "replacement_room" => target},
              ""
            )
          )

        {Map.put(predecessor, "event_id", event["event_id"]), event}
      else
        {predecessor, nil}
      end

    creation = Map.take(creation, ~w(type m.federate)) |> Map.put("predecessor", predecessor)

    creation =
      if version == "12", do: Map.put(creation, "additional_creators", creators), else: creation

    levels = (state[{"m.room.power_levels", ""}] || %{})["content"] || %{}

    levels =
      if metadata.version == "11" and is_nil(state[{"m.room.power_levels", ""}]),
        do: Map.put(levels, "users", %{state[{"m.room.create", ""}]["sender"] => 100}),
        else: levels

    levels = converted_levels(levels, state, metadata.version, version, actor, creators)
    levels = Rooms.initial_levels(levels, version, [actor | creators])

    initial =
      for {{type, key}, event} <- state,
          type in @transfer and type != "m.space.child",
          do: %{"type" => type, "state_key" => key, "content" => event["content"]}

    bootstrap =
      if version == "11",
        do: Map.put(levels, "users", Map.put(levels["users"] || %{}, actor, maximum(levels))),
        else: %{}

    created =
      require_ok!(
        Rooms.create(
          principal,
          %{
            "room_version" => version,
            "visibility" => room.visibility,
            "creation_content" => creation,
            "initial_state" => initial,
            "power_level_content_override" => bootstrap
          },
          id: id
        )
      )

    target = created["room_id"]

    for {{"m.space.child", key}, event} <- state,
        do: require_ok!(Graph.send(id, actor, "m.space.child", event["content"], key))

    # Generate new invitations rather than impersonating any user's join.
    rule = get_in(state, [{"m.room.join_rules", ""}, "content", "join_rule"]) || "invite"

    if rule in ["invite", "knock"] do
      for {{"m.room.member", user}, event} <- state,
          event["content"]["membership"] == "join" and user != actor do
        case Identity.parse_user_id(user) do
          {:ok, name} ->
            case LakehouseIam.Accounts.fetch_user(name) do
              {:ok, %{active: true}} -> require_ok!(Rooms.invite(principal, id, user))
              _ -> :ok
            end

          _ ->
            require_ok!(Rooms.invite(principal, id, user))
        end
      end
    end

    # Set final power levels after transferring state and issuing invitations.
    require_ok!(Graph.send(id, actor, "m.room.power_levels", levels, ""))
    move_aliases!(room.id, id, actor, state)

    tombstone =
      tombstone ||
        require_ok!(
          Graph.send(
            room.id,
            actor,
            "m.room.tombstone",
            %{"body" => "This room has been upgraded", "replacement_room" => target},
            ""
          )
        )

    Repo.insert_all("matrix_room_upgrades", [
      %{
        old_room_id: ClientStore.dump_id(room.id),
        new_room_id: ClientStore.dump_id(id),
        tombstone_id: tombstone["event_id"]
      }
    ])

    copy_settings!(principal, id)
    freeze!(room.id, actor)
    %{"replacement_room" => target}
  end

  defp converted_levels(levels, _state, _from, "12", actor, additional) do
    Map.put(levels, "users", Map.drop(levels["users"] || %{}, [actor | additional]))
  end

  defp converted_levels(levels, state, "12", "11", _, _) do
    Map.put(
      levels,
      "users",
      Enum.reduce(Authorization.creators(state), levels["users"] || %{}, &Map.put(&2, &1, 100))
    )
  end

  defp converted_levels(levels, _, _, _, _, _), do: levels

  defp maximum(levels) do
    values =
      Map.values(
        Map.take(levels, ~w(users_default events_default state_default invite kick ban redact))
      ) ++ Enum.flat_map(~w(users events notifications), &Map.values(levels[&1] || %{}))

    Enum.max([100 | Enum.filter(values, &is_integer/1)])
  end

  defp move_aliases!(old, new, actor, state) do
    names =
      Repo.all(
        from a in "matrix_room_aliases",
          where: a.local_room_id == type(^old, :binary_id),
          select: a.name
      )

    Repo.update_all(
      from(a in "matrix_room_aliases", where: a.local_room_id == type(^old, :binary_id)),
      set: [local_room_id: ClientStore.dump_id(new)]
    )

    old_record = Repo.get!(LakehouseMatrix.Schema.Room, old)

    Repo.update_all(from(r in LakehouseMatrix.Schema.Room, where: r.id == ^old),
      set: [alias: nil]
    )

    if old_record.alias in names,
      do:
        Repo.update_all(from(r in LakehouseMatrix.Schema.Room, where: r.id == ^new),
          set: [alias: old_record.alias]
        )

    aliases = Enum.map(names, &Identity.room_alias/1)
    content = get_in(state, [{"m.room.canonical_alias", ""}, "content"]) || %{}
    canonical = if content["alias"] in aliases, do: content["alias"]

    alternate =
      Enum.filter(
        if(is_list(content["alt_aliases"]), do: content["alt_aliases"], else: []),
        &(&1 in aliases)
      )

    if canonical || alternate != [],
      do:
        require_ok!(
          Graph.send(
            new,
            actor,
            "m.room.canonical_alias",
            Map.reject(%{"alias" => canonical, "alt_aliases" => alternate}, fn {_, value} ->
              is_nil(value)
            end),
            ""
          )
        )

    if map_size(content) > 0, do: send_if_allowed!(old, actor, "m.room.canonical_alias", %{})
  end

  defp freeze!(room, actor) do
    metadata = Graph.room(room)
    levels = get_in(RoomAccess.state(metadata), [{"m.room.power_levels", ""}, "content"]) || %{}

    if (levels["users_default"] || 0) < 9_007_199_254_740_991 do
      threshold = max(50, (levels["users_default"] || 0) + 1)

      levels =
        Map.put(levels, "events_default", max(levels["events_default"] || 0, threshold))
        |> Map.put("invite", max(levels["invite"] || 0, threshold))

      send_if_allowed!(room, actor, "m.room.power_levels", levels)
    end
  end

  defp send_if_allowed!(room, actor, type, content) do
    metadata = Graph.room(room)
    event = Graph.template(metadata, Graph.load_graph(room), actor, type, content, "")

    if Authorization.check(event, RoomAccess.state(metadata), metadata.version) == :ok,
      do: require_ok!(Graph.send(room, actor, type, content, ""))
  end

  def copy_settings!(principal, room) do
    case Repo.one(
           from u in "matrix_room_upgrades",
             where: u.new_room_id == type(^room, :binary_id),
             select: type(u.old_room_id, :binary_id)
         ) do
      nil ->
        :ok

      old ->
        source = Identity.room_id(old)
        target = Identity.room_id(room)

        for type <- ~w(m.tag m.marked_unread),
            data = ClientStore.get_data(principal, source, type),
            not is_nil(data),
            is_nil(ClientStore.get_data(principal, target, type)),
            do: require_ok!(ClientStore.put_data(principal, target, type, data))

        direct = ClientStore.get_data(principal, "", "m.direct") || %{}

        updated =
          Map.new(direct, fn {user, rooms} ->
            {user,
             if(is_list(rooms) and source in rooms, do: Enum.uniq(rooms ++ [target]), else: rooms)}
          end)

        if updated != direct,
          do: require_ok!(ClientStore.put_data(principal, "", "m.direct", updated))

        with {:ok, rule} <- LakehouseMatrix.PushRules.fetch(principal, "room", source),
             {:error, :not_found} <- LakehouseMatrix.PushRules.fetch(principal, "room", target) do
          require_ok!(LakehouseMatrix.PushRules.mutate(principal, "room", target, "PUT", rule))

          if rule["enabled"] == false,
            do:
              require_ok!(
                LakehouseMatrix.PushRules.mutate(
                  principal,
                  "room",
                  target,
                  "PUT",
                  %{"enabled" => false},
                  "enabled"
                )
              )
        end

        :ok
    end
  end

  defp require_ok!({:ok, value}), do: value
  defp require_ok!({:error, reason}), do: Repo.rollback(reason)
  defp require_ok!(:ok), do: :ok
end
