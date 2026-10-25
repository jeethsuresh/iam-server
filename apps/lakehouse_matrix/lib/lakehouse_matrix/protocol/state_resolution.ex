defmodule LakehouseMatrix.Protocol.StateResolution do
  @moduledoc "Deterministic state resolution v2 (room 11) and v2.1 (room 12)."
  alias LakehouseMatrix.Protocol.Authorization, as: Auth

  @doc "Resolve state maps of {type, state_key} => event_id against an authenticated event graph."
  def resolve(states, graph, version)
      when version in ["11", "12"] and is_list(states) and is_map(graph) do
    try do
      roots = states |> Enum.flat_map(&Map.values/1) |> Enum.uniq()

      cache =
        Enum.reduce(roots, %{}, fn id, cache ->
          elem(ancestors(id, graph, cache, MapSet.new()), 1)
        end)

      Enum.each(states, fn state ->
        Enum.each(state, fn {key, id} ->
          event = fetch!(graph, id)

          unless Auth.key(event) == key and event[:auth_rejected] != true,
            do: throw({:resolution_error, :invalid_state})
        end)
      end)

      {unconflicted, conflicted} = partition(states)

      if MapSet.size(conflicted) == 0 do
        {:ok, unconflicted}
      else
        chains =
          Enum.map(states, fn state ->
            Enum.reduce(Map.values(state), MapSet.new(), &MapSet.union(cache[&1], &2))
          end)

        difference = MapSet.difference(union(chains), intersection(chains))
        full = MapSet.union(conflicted, difference)

        full =
          if version == "12",
            do: MapSet.union(full, conflicted_subgraph(conflicted, cache)),
            else: full

        powers = Enum.filter(full, &power_event?(fetch!(graph, &1)))

        selected =
          Enum.reduce(powers, MapSet.new(powers), fn id, set ->
            MapSet.union(set, MapSet.intersection(cache[id], full))
          end)

        create = get_create(states, graph)
        ordered = power_sort(selected, graph, version, create)
        base = if version == "12", do: %{}, else: unconflicted
        partial = iterative(ordered, base, graph, version, create)
        remaining = MapSet.difference(full, selected)
        mainline = mainline(partial[{"m.room.power_levels", ""}], graph)

        ordered =
          Enum.sort_by(remaining, fn id ->
            event = fetch!(graph, id)
            {-mainline_position(id, mainline, graph), event["origin_server_ts"], id}
          end)

        resolved = iterative(ordered, partial, graph, version, create)
        {:ok, Map.merge(resolved, unconflicted)}
      end
    catch
      {:resolution_error, error} -> {:error, error}
    end
  end

  def resolve(_, _, _), do: {:error, :unsupported_room_version}

  defp partition(states) do
    keys = states |> Enum.flat_map(&Map.keys/1) |> Enum.uniq()

    Enum.reduce(keys, {%{}, MapSet.new()}, fn key, {unconflicted, conflicted} ->
      values = states |> Enum.map(& &1[key]) |> Enum.uniq()

      case values do
        [id] when is_binary(id) -> {Map.put(unconflicted, key, id), conflicted}
        _ -> {unconflicted, MapSet.union(conflicted, MapSet.new(Enum.reject(values, &is_nil/1)))}
      end
    end)
  end

  defp ancestors(id, graph, cache, visiting) do
    cond do
      MapSet.member?(visiting, id) ->
        throw({:resolution_error, :cyclic_auth_graph})

      Map.has_key?(cache, id) ->
        {cache[id], cache}

      true ->
        event = fetch!(graph, id)
        visiting = MapSet.put(visiting, id)

        {set, cache} =
          Enum.reduce(event["auth_events"] || [], {MapSet.new(), cache}, fn parent,
                                                                            {set, cache} ->
            {chain, cache} = ancestors(parent, graph, cache, visiting)
            {set |> MapSet.union(chain) |> MapSet.put(parent), cache}
          end)

        {set, Map.put(cache, id, set)}
    end
  end

  defp conflicted_subgraph(conflicted, cache) do
    # A vertex lies on a path between conflicted events precisely when it is
    # below one endpoint and above another. Include both endpoints of each path.
    Enum.reduce(conflicted, MapSet.new(), fn start, result ->
      Enum.reduce(cache[start], result, fn vertex, result ->
        if MapSet.member?(conflicted, vertex) or not MapSet.disjoint?(cache[vertex], conflicted),
          do: result |> MapSet.put(start) |> MapSet.put(vertex),
          else: result
      end)
    end)
  end

  defp power_event?(event) do
    Map.has_key?(event, "state_key") and
      (event["type"] in ~w(m.room.power_levels m.room.join_rules) or
         (event["type"] == "m.room.member" and event["sender"] != event["state_key"] and
            event["content"]["membership"] in ~w(leave ban)))
  end

  defp power_sort(ids, graph, version, create),
    do: power_sort(ids, MapSet.new(), [], graph, version, create)

  defp power_sort(pending, emitted, ordered, graph, version, create) do
    if MapSet.size(pending) == 0 do
      Enum.reverse(ordered)
    else
      ready =
        Enum.filter(pending, fn id ->
          Enum.all?(fetch!(graph, id)["auth_events"] || [], fn parent ->
            not MapSet.member?(pending, parent) or MapSet.member?(emitted, parent)
          end)
        end)

      if ready == [], do: throw({:resolution_error, :cyclic_auth_graph})

      next =
        Enum.min_by(ready, fn id ->
          event = fetch!(graph, id)
          state = auth_state(event, graph, create)
          power = Auth.power(state, event["sender"], version)
          # A tuple avoids a numeric sentinel for room creators' infinite power.
          power_key = if power == :infinity, do: {0, 0}, else: {1, -power}
          {power_key, event["origin_server_ts"], id}
        end)

      power_sort(
        MapSet.delete(pending, next),
        MapSet.put(emitted, next),
        [next | ordered],
        graph,
        version,
        create
      )
    end
  end

  defp iterative(ids, state, graph, version, create) do
    Enum.reduce(ids, state, fn id, state ->
      event = fetch!(graph, id)
      fallback = auth_state(event, graph, create)
      resolved = Map.new(state, fn {key, value} -> {key, fetch!(graph, value)} end)
      auth = Map.merge(fallback, resolved)

      if event[:auth_rejected] != true and Map.has_key?(event, "state_key") and
           Auth.check(event, auth, version) == :ok,
         do: Map.put(state, Auth.key(event), id),
         else: state
    end)
  end

  defp auth_state(event, graph, create) do
    state =
      for id <- event["auth_events"] || [],
          auth = fetch!(graph, id),
          auth[:auth_rejected] != true,
          into: %{},
          do: {Auth.key(auth), auth}

    if create, do: Map.put(state, {"m.room.create", ""}, create), else: state
  end

  defp get_create(states, graph) do
    creates =
      states |> Enum.map(& &1[{"m.room.create", ""}]) |> Enum.reject(&is_nil/1) |> Enum.uniq()

    case creates do
      [id] -> fetch!(graph, id)
      _ -> throw({:resolution_error, :conflicting_create_events})
    end
  end

  defp mainline(nil, _), do: %{}
  defp mainline(id, graph), do: mainline(id, graph, %{}, 0)
  defp mainline(nil, _, result, _), do: result

  defp mainline(id, graph, result, position) do
    if Map.has_key?(result, id), do: throw({:resolution_error, :cyclic_auth_graph})
    mainline(previous_power(id, graph), graph, Map.put(result, id, position), position + 1)
  end

  defp mainline_position(id, mainline, graph) do
    # The starting event itself is deliberately excluded from its auth mainline.
    case previous_power(id, graph) do
      nil ->
        map_size(graph) + 1

      parent ->
        case mainline[parent] do
          nil -> mainline_position(parent, mainline, graph)
          position -> position
        end
    end
  end

  defp previous_power(id, graph) do
    Enum.find(fetch!(graph, id)["auth_events"] || [], fn parent ->
      event = fetch!(graph, parent)
      event["type"] == "m.room.power_levels" and event["state_key"] == ""
    end)
  end

  defp fetch!(graph, id) do
    case graph[id] do
      nil -> throw({:resolution_error, {:missing_event, id}})
      event -> event
    end
  end

  defp union(sets), do: Enum.reduce(sets, MapSet.new(), &MapSet.union/2)
  defp intersection([]), do: MapSet.new()
  defp intersection([first | rest]), do: Enum.reduce(rest, first, &MapSet.intersection/2)
end
