defmodule LakehouseMatrix.Federation.RoomAccess do
  @moduledoc "Federation room ACLs and membership checks at the network boundary."
  import Ecto.Query
  alias LakehouseMatrix.Federation.Transport
  alias LakehouseMatrix.Protocol.{Authorization, Graph, Event}

  def state(metadata) do
    ids = Map.values(metadata.current_state)

    graph =
      LakehouseIam.Repo.all(from p in LakehouseMatrix.Schema.Pdu, where: p.event_id in ^ids)
      |> Map.new(fn p -> {p.event_id, Map.put(p.pdu, "event_id", p.event_id)} end)

    Map.new(Graph.decode_state(metadata.current_state), fn {key, id} -> {key, graph[id]} end)
  end

  def allowed?(metadata, server),
    do: acl_allowed?(state(metadata)[{"m.room.server_acl", ""}], server)

  def acl_allowed?(nil, _), do: true

  def acl_allowed?(event, server) do
    with {:ok, target} <- Transport.server_name(server) do
      acl = event["content"]
      ip = match?({:ok, _}, :inet.parse_address(String.to_charlist(target.host)))

      not (ip and acl["allow_ip_literals"] == false) and
        not matches_any?(acl["deny"], target.host) and matches_any?(acl["allow"], target.host)
    else
      _ -> false
    end
  end

  def joined?(state, server) do
    Enum.any?(state, fn
      {{"m.room.member", user}, event} ->
        event["content"]["membership"] == "join" and Event.user_domain(user) == {:ok, server}

      _ ->
        false
    end)
  end

  def readable?(metadata, server) do
    state = state(metadata)

    allowed?(metadata, server) and
      (joined?(state, server) or historical_join?(metadata, server) or
         get_in(state, [{"m.room.history_visibility", ""}, "content", "history_visibility"]) ==
           "world_readable")
  end

  def visible_event?(metadata, server, id) do
    record = Graph.event(id)

    with true <-
           not is_nil(record) and record.local_room_id == metadata.local_room_id and
             not record.auth_rejected and not record.state_rejected and not record.soft_failed and
             not record.outlier,
         true <- allowed?(metadata, server) do
      event = record.pdu
      graph = Graph.load_graph(metadata.local_room_id, [id])

      before =
        Map.new(Graph.decode_state(record.state_before), fn {key, id} -> {key, graph[id]} end)

      visibility =
        get_in(before, [{"m.room.history_visibility", ""}, "content", "history_visibility"]) ||
          "shared"

      visibility =
        if event["type"] == "m.room.history_visibility" and event["state_key"] == "" do
          after_visibility = event["content"]["history_visibility"] || "shared"
          Enum.min_by([visibility, after_visibility], &visibility_rank/1)
        else
          visibility
        end

      own_member =
        event["type"] == "m.room.member" and
          Event.user_domain(event["state_key"]) == {:ok, server}

      own_member or
        case visibility do
          "world_readable" ->
            true

          "joined" ->
            joined?(before, server)

          "invited" ->
            Enum.any?(before, fn
              {{"m.room.member", user}, e} ->
                e["content"]["membership"] in ~w(join invite) and
                  Event.user_domain(user) == {:ok, server}

              _ ->
                false
            end)

          _ ->
            joined?(state(metadata), server) or joined?(before, server) or
              historical_join?(metadata, server, id)
        end
    else
      _ -> false
    end
  end

  # A shared-history event remains readable after departure only when it was
  # before a valid join in the DAG. Arrival order and depth do not prove this.
  def historical_join?(metadata, server, ancestor \\ nil) do
    joins =
      LakehouseIam.Repo.all(
        from p in LakehouseMatrix.Schema.Pdu,
          where:
            p.local_room_id == ^metadata.local_room_id and not p.auth_rejected and
              not p.state_rejected and not p.soft_failed and not p.outlier and
              fragment(
                "?->>'type' = 'm.room.member' AND ?->'content'->>'membership' = 'join'",
                p.pdu,
                p.pdu
              ),
          select: {p.event_id, p.pdu}
      )
      |> Enum.flat_map(fn {id, event} ->
        if Event.user_domain(event["state_key"]) == {:ok, server}, do: [id], else: []
      end)

    if is_nil(ancestor),
      do: joins != [],
      else: Graph.ancestor?(metadata.local_room_id, ancestor, joins)
  end

  defp visibility_rank("world_readable"), do: 0
  defp visibility_rank("shared"), do: 1
  defp visibility_rank("invited"), do: 2
  defp visibility_rank(_), do: 3

  def restricted_join(metadata, user, template) do
    state = state(metadata)
    rule = state[{"m.room.join_rules", ""}]

    if get_in(rule || %{}, ["content", "join_rule"]) in ~w(restricted knock_restricted) and
         Authorization.membership(state, user) not in ~w(join invite) do
      eligible =
        Enum.any?(get_in(rule, ["content", "allow"]) || [], fn
          %{"type" => "m.room_membership", "room_id" => room} ->
            case Graph.room_by_id(room) do
              nil -> false
              other -> Authorization.membership(state(other), user) == "join"
            end

          _ ->
            false
        end)

      valid_authorizer = fn member ->
        Authorization.membership(state, member) == "join" and
          Event.user_domain(member) == {:ok, LakehouseMatrix.Identity.homeserver_domain()} and
          Authorization.gte?(
            Authorization.power(state, member, metadata.version),
            Authorization.level(state, "invite", 0)
          )
      end

      requested = get_in(template, ["content", "join_authorised_via_users_server"])

      authorizer =
        if is_binary(requested) and valid_authorizer.(requested),
          do: requested,
          else:
            Enum.find_value(state, fn
              {{"m.room.member", member}, event} ->
                if event["content"]["membership"] == "join" and
                     Event.user_domain(member) ==
                       {:ok, LakehouseMatrix.Identity.homeserver_domain()} and
                     Authorization.gte?(
                       Authorization.power(state, member, metadata.version),
                       Authorization.level(state, "invite", 0)
                     ),
                   do: member

              _ ->
                nil
            end)

      if eligible and authorizer do
        {:ok, put_in(template, ["content", "join_authorised_via_users_server"], authorizer)}
      else
        {:error, :unable_to_authorise_join}
      end
    else
      {:ok, template}
    end
  end

  defp matches_any?(patterns, host) when is_list(patterns) do
    Enum.any?(patterns, fn pattern ->
      if is_binary(pattern) do
        regex =
          pattern |> Regex.escape() |> String.replace("\\*", ".*") |> String.replace("\\?", ".")

        Regex.match?(Regex.compile!("\\A" <> regex <> "\\z", "iu"), host)
      else
        false
      end
    end)
  end

  defp matches_any?(_, _), do: false
end
