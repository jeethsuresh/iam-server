defmodule LakehouseMatrix.ClientSpaces do
  @moduledoc "Permission-filtered room previews and depth-first local/federated space discovery."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, ClientSync, Directory, Identity, Memberships}
  alias LakehouseMatrix.Protocol.{Authorization, Event, Graph}
  alias LakehouseMatrix.Federation.{RoomAccess, Transport}

  def summary(principal, ref, via \\ [], request \\ &Transport.request/4) do
    with {:ok, ref, via} <- reference(ref, via),
         {:ok, result} <- view(ref, via, false, {:user, principal}, request) do
      {:ok, Map.delete(result, "children_state")}
    end
  end

  def hierarchy(principal, device, ref, params, via \\ [], request \\ &Transport.request/4) do
    with true <- valid_id?(ref),
         {:ok, limit} <- ClientSync.integer(params["limit"], 20, 1, 100),
         {:ok, state} <- page_state(principal, device, ref, params, via),
         {:ok, _} <- view(ref, state["root_via"], state["suggested"], {:user, principal}, request) do
      {rooms, state} =
        walk(
          state,
          {:user, principal},
          request,
          limit,
          [],
          2000,
          System.monotonic_time(:millisecond) + 15_000
        )

      cond do
        state["overflow"] == true ->
          {:error, :limit_exceeded}

        true ->
          response = %{"rooms" => Enum.reverse(rooms)}

          if state["queue"] == [] do
            {:ok, response}
          else
            token = ClientStore.random()

            Repo.delete_all(
              from c in "matrix_hierarchy_cursors", where: c.expires_at <= ^ClientStore.now()
            )

            Repo.insert_all("matrix_hierarchy_cursors", [
              %{
                token: token,
                principal_id: ClientStore.dump_id(principal),
                device_id: device,
                root: ref,
                state: state,
                expires_at: DateTime.add(ClientStore.now(), 1800, :second)
              }
            ])

            {:ok, Map.put(response, "next_batch", token)}
          end
      end
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_param}
    end
  end

  def federation(origin, ref, params) do
    with true <- params["suggested_only"] in [nil, true, false, "true", "false"],
         metadata when not is_nil(metadata) <- Graph.room_by_id(ref),
         {:ok, room} <-
           local(metadata, params["suggested_only"] in [true, "true"], {:server, origin}) do
      {children, inaccessible} =
        Enum.reduce(room["children_state"], {[], []}, fn event, {children, inaccessible} ->
          case Graph.room_by_id(event["state_key"]) do
            nil ->
              {children, inaccessible}

            metadata ->
              case local(metadata, params["suggested_only"] in [true, "true"], {:server, origin}) do
                {:ok, child} -> {[Map.delete(child, "children_state") | children], inaccessible}
                _ -> {children, [event["state_key"] | inaccessible]}
              end
          end
        end)

      {:ok,
       %{
         "room" => room,
         "children" => Enum.reverse(children),
         "inaccessible_children" => Enum.reverse(inaccessible)
       }}
    else
      {:error, _} = error -> error
      nil -> {:error, :not_found}
      _ -> {:error, :invalid_param}
    end
  end

  defp page_state(principal, device, ref, %{"from" => token} = params, _) when is_binary(token) do
    row =
      Repo.one(
        from c in "matrix_hierarchy_cursors",
          where:
            c.token == ^token and c.principal_id == type(^principal, :binary_id) and
              c.device_id == ^device and c.root == ^ref and c.expires_at > ^ClientStore.now(),
          select: c.state
      )

    with state when is_map(state) <- row,
         {:ok, depth} <- ClientSync.integer(params["max_depth"], state["max_depth"], 0, 64),
         true <- depth == state["max_depth"],
         true <-
           params["suggested_only"] in [nil, state["suggested"], to_string(state["suggested"])] do
      {:ok, state}
    else
      _ -> {:error, :invalid_cursor}
    end
  end

  defp page_state(_, _, _, %{"from" => token}, _) when not is_nil(token),
    do: {:error, :invalid_cursor}

  defp page_state(_, _, ref, params, via) do
    with {:ok, depth} <- ClientSync.integer(params["max_depth"], 5, 0, 64),
         true <- params["suggested_only"] in [nil, true, false, "true", "false"] do
      {:ok,
       %{
         "queue" => [%{"room" => ref, "via" => peers(via, ref), "depth" => 0}],
         "root_via" => peers(via, ref),
         "visited" => [],
         "max_depth" => depth,
         "suggested" => params["suggested_only"] in [true, "true"]
       }}
    else
      _ -> {:error, :invalid_param}
    end
  end

  defp walk(%{"queue" => []} = state, _, _, _, rooms, _, _), do: {rooms, state}
  defp walk(state, _, _, 0, rooms, _, _), do: {rooms, state}
  defp walk(state, _, _, _, rooms, 0, _), do: {rooms, state}

  defp walk(state, subject, request, remaining, rooms, budget, deadline) do
    if System.monotonic_time(:millisecond) >= deadline do
      {rooms, state}
    else
      [next | rest] = state["queue"]
      ref = next["room"]

      cond do
        ref in state["visited"] ->
          walk(
            Map.put(state, "queue", rest),
            subject,
            request,
            remaining,
            rooms,
            budget - 1,
            deadline
          )

        length(state["visited"]) >= 10_000 ->
          {rooms, Map.put(state, "overflow", true)}

        true ->
          case view(ref, next["via"], state["suggested"], subject, request) do
            {:ok, room} ->
              children =
                if next["depth"] < state["max_depth"],
                  do:
                    Enum.map(
                      room["children_state"],
                      &%{
                        "room" => &1["state_key"],
                        "via" => &1["content"]["via"],
                        "depth" => next["depth"] + 1
                      }
                    ),
                  else: []

              state = %{
                state
                | "queue" => children ++ rest,
                  "visited" => [ref | state["visited"]]
              }

              walk(state, subject, request, remaining - 1, [room | rooms], budget - 1, deadline)

            _ ->
              # Do not expose the children of an inaccessible space. Unknown
              # rooms may be skipped, without treating peer summaries as state.
              state = %{state | "queue" => rest, "visited" => [ref | state["visited"]]}
              walk(state, subject, request, remaining, rooms, budget - 1, deadline)
          end
      end
    end
  end

  defp view(ref, via, suggested, subject, request) do
    case Graph.room_by_id(ref) do
      nil ->
        with {:ok, response} <- remote(ref, via, suggested, request),
             true <- accessible?(response["room"], subject) do
          room =
            Map.update!(response["room"], "children_state", fn children ->
              Enum.reject(children, &(&1["state_key"] in response["inaccessible_children"]))
            end)

          {:ok, with_membership(room, subject)}
        else
          _ -> {:error, :not_found}
        end

      metadata ->
        local(metadata, suggested, subject)
    end
  end

  defp local(metadata, suggested, subject) do
    state = RoomAccess.state(metadata)

    user =
      case subject do
        {:user, principal} -> user(principal)
        _ -> nil
      end

    # A signed invite/knock only authorizes a partial preview for its recipient.
    state =
      if (metadata.extremities == [] and user) &&
           Memberships.membership(metadata.local_room_id, elem(subject, 1)) in ["invite", "knock"],
         do:
           Map.new(
             ClientSync.stripped(
               metadata.local_room_id,
               ClientStore.position(),
               elem(subject, 1)
             ),
             &{{&1["type"], &1["state_key"]}, &1}
           ),
         else: state

    content = fn type -> get_in(state, [{type, ""}, "content"]) || %{} end
    rule = content.("m.room.join_rules")

    summary =
      %{
        "room_id" => metadata.room_id,
        "room_version" => metadata.version,
        "name" => text(content.("m.room.name")["name"]),
        "topic" => text(content.("m.room.topic")["topic"]),
        "avatar_url" => text(content.("m.room.avatar")["url"]),
        "canonical_alias" => text(content.("m.room.canonical_alias")["alias"]),
        "room_type" => text(content.("m.room.create")["type"]),
        "encryption" => text(content.("m.room.encryption")["algorithm"]),
        "join_rule" => text(rule["join_rule"]) || "invite",
        "allowed_room_ids" => allowed_rooms(rule),
        "num_joined_members" =>
          Enum.count(state, fn {{type, _}, event} ->
            type == "m.room.member" and event["content"]["membership"] == "join"
          end),
        "world_readable" =>
          content.("m.room.history_visibility")["history_visibility"] == "world_readable",
        "guest_can_join" => content.("m.room.guest_access")["guest_access"] == "can_join"
      }
      |> Map.reject(fn {_, value} -> is_nil(value) end)

    permitted =
      case subject do
        {:user, principal} ->
          LakehouseMatrix.RiverRtc.chat_allowed?(metadata.local_room_id, principal) and
            LakehouseMatrix.RiverPublishing.reader_allowed?(metadata.local_room_id, principal) and
            (Authorization.membership(state, user) in ["join", "invite", "knock"] or
               accessible?(summary, subject))

        {:server, server} ->
          RoomAccess.allowed?(metadata, server) and
            (RoomAccess.joined?(state, server) or
               Enum.any?(state, fn {{type, key}, event} ->
                 type == "m.room.member" and event["content"]["membership"] in ["invite", "knock"] and
                   Event.user_domain(key) == {:ok, server}
               end) or accessible?(summary, subject))
      end

    if permitted do
      children =
        if summary["room_type"] == "m.space",
          do:
            state
            |> Map.values()
            |> Enum.filter(&valid_child?(&1, suggested))
            |> Enum.sort_by(&child_order/1)
            |> Enum.map(&Map.take(&1, ~w(type state_key sender content origin_server_ts))),
          else: []

      {:ok, summary |> Map.put("children_state", children) |> with_membership(subject)}
    else
      {:error, :forbidden}
    end
  end

  defp accessible?(summary, subject) do
    summary["world_readable"] == true or
      summary["join_rule"] in ["public", "knock", "knock_restricted"] or
      (summary["join_rule"] == "restricted" and
         Enum.any?(summary["allowed_room_ids"] || [], fn ref ->
           case {subject, Graph.room_by_id(ref)} do
             {{:user, principal}, %{local_room_id: id}} ->
               Memberships.joined?(id, principal)

             {{:server, server}, metadata} when not is_nil(metadata) ->
               RoomAccess.joined?(RoomAccess.state(metadata), server)

             _ ->
               false
           end
         end))
  end

  defp with_membership(summary, {:server, _}), do: summary

  defp with_membership(summary, {:user, principal}) do
    case Graph.room_by_id(summary["room_id"]) do
      nil ->
        summary

      metadata ->
        case Memberships.membership(metadata.local_room_id, principal) do
          value when value in ~w(join invite knock leave ban) ->
            Map.put(summary, "membership", value)

          _ ->
            summary
        end
    end
  end

  defp remote(ref, via, suggested, request) do
    Enum.reduce_while(peers(via, ref), {:error, :not_found}, fn server, _ ->
      cached =
        Repo.one(
          from c in "matrix_hierarchy_cache",
            where:
              c.server == ^server and c.room_id == ^ref and c.suggested == ^suggested and
                c.expires_at > ^ClientStore.now(),
            select: c.response
        )

      result =
        if cached,
          do: {:ok, cached},
          else:
            request.(
              :get,
              server,
              "/_matrix/federation/v1/hierarchy/" <>
                escape(ref) <> "?suggested_only=" <> to_string(suggested),
              nil
            )

      case result do
        {:ok, %{"room" => room} = body} when is_map(room) ->
          if room["room_id"] == ref and valid_summary?(room) and is_list(room["children_state"]) do
            body = sanitize(body, suggested)

            Repo.delete_all(
              from c in "matrix_hierarchy_cache", where: c.expires_at <= ^ClientStore.now()
            )

            unless cached,
              do:
                Repo.insert_all(
                  "matrix_hierarchy_cache",
                  [
                    %{
                      server: server,
                      room_id: ref,
                      suggested: suggested,
                      response: body,
                      expires_at: DateTime.add(ClientStore.now(), 300, :second)
                    }
                  ],
                  on_conflict: [
                    set: [
                      response: body,
                      expires_at: DateTime.add(ClientStore.now(), 300, :second)
                    ]
                  ],
                  conflict_target: [:server, :room_id, :suggested]
                )

            {:halt, {:ok, body}}
          else
            {:cont, {:error, :not_found}}
          end

        _ ->
          {:cont, {:error, :not_found}}
      end
    end)
  end

  defp sanitize(body, suggested) do
    room = clean_summary(body["room"])

    children =
      body["room"]["children_state"]
      |> Enum.filter(&valid_child?(&1, suggested))
      |> Enum.sort_by(&child_order/1)
      |> Enum.map(&Map.take(&1, ~w(type state_key sender content origin_server_ts)))

    inaccessible =
      if is_list(body["inaccessible_children"]),
        do: Enum.filter(body["inaccessible_children"], &valid_id?/1),
        else: []

    %{
      "room" =>
        Map.put(
          room,
          "children_state",
          if(room["room_type"] == "m.space", do: children, else: [])
        ),
      "inaccessible_children" => inaccessible
    }
  end

  defp clean_summary(room) do
    result =
      Map.take(
        room,
        ~w(room_id name topic avatar_url canonical_alias room_type encryption room_version join_rule world_readable guest_can_join num_joined_members allowed_room_ids)
      )

    result
    |> Map.put("allowed_room_ids", Enum.filter(room["allowed_room_ids"] || [], &valid_id?/1))
    |> Map.put("world_readable", room["world_readable"] == true)
    |> Map.put("guest_can_join", room["guest_can_join"] == true)
    |> Map.put(
      "num_joined_members",
      if(
        is_integer(room["num_joined_members"]) and
          room["num_joined_members"] in 0..9_007_199_254_740_991,
        do: room["num_joined_members"],
        else: 0
      )
    )
  end

  defp valid_summary?(room),
    do:
      valid_id?(room["room_id"]) and
        Enum.all?(
          ~w(name topic avatar_url canonical_alias room_type encryption room_version join_rule),
          &(is_nil(room[&1]) or is_binary(room[&1]))
        ) and (is_nil(room["allowed_room_ids"]) or is_list(room["allowed_room_ids"]))

  defp valid_child?(event, suggested) when is_map(event) do
    content = event["content"]

    event["type"] == "m.space.child" and valid_id?(event["state_key"]) and is_map(content) and
      is_list(content["via"]) and length(content["via"]) in 1..1000 and
      Enum.all?(content["via"], &match?({:ok, _}, Transport.server_name(&1))) and
      (not suggested or content["suggested"] == true) and is_integer(event["origin_server_ts"]) and
      is_binary(event["sender"])
  end

  defp valid_child?(_, _), do: false

  defp child_order(event) do
    order = event["content"]["order"]
    valid = is_binary(order) and Regex.match?(~r/\A[ -~]{0,50}\z/, order)

    {if(valid, do: 0, else: 1), if(valid, do: order, else: ""), event["origin_server_ts"],
     event["state_key"]}
  end

  defp allowed_rooms(rule),
    do:
      for(
        %{"type" => "m.room_membership", "room_id" => ref} <-
          if(is_list(rule["allow"]), do: rule["allow"], else: []),
        valid_id?(ref),
        do: ref
      )

  defp reference("#" <> _ = ref, via) do
    with {:ok, resolution} <- Directory.resolve(ref),
         do:
           {:ok, resolution["room_id"],
            peers(via ++ resolution["servers"], resolution["room_id"])}
  end

  defp reference(ref, via),
    do: if(valid_id?(ref), do: {:ok, ref, peers(via, ref)}, else: {:error, :invalid_param})

  defp peers(via, ref) do
    inferred =
      case String.split(ref, ":", parts: 2) do
        [_id, server] -> [server]
        _ -> []
      end

    (if(is_list(via), do: via, else: []) ++ inferred)
    |> Enum.filter(
      &(&1 != Identity.homeserver_domain() and match?({:ok, _}, Transport.server_name(&1)))
    )
    |> Enum.uniq()
    |> Enum.take(3)
  end

  defp valid_id?(ref),
    do:
      is_binary(ref) and byte_size(ref) in 2..255 and String.valid?(ref) and
        String.starts_with?(ref, "!") and not String.contains?(ref, "\x00")

  defp text(value), do: if(is_binary(value), do: value)

  defp user(principal),
    do: Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

  defp escape(value), do: URI.encode(value, &URI.char_unreserved?/1)
end
