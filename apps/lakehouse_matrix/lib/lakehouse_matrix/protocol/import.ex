defmodule LakehouseMatrix.Protocol.Import do
  @moduledoc "Validate a federated state/auth snapshot before installing it or using it to fill a DAG gap."
  alias LakehouseMatrix.Protocol.{Authorization, Event}
  alias LakehouseMatrix.Federation.Keyring

  def snapshot(ref, version, wire, state, auth, lookup \\ &Keyring.key/3) do
    with true <-
           version in Event.versions() and is_list(state) and is_list(auth) and
             length(state) + length(auth) <= 50_000,
         {:ok, event} <- Event.verify(wire, version, lookup),
         true <- wire["room_id"] == ref,
         {:ok, graph} <- verify_all([wire | state ++ auth], version, ref, lookup),
         {:ok, state_ids} <- state_ids(state, version),
         create when not is_nil(create) <- graph[state_ids[{"m.room.create", ""}]],
         true <- Event.room_id(create, version) == ref,
         {:ok, _} <-
           verify_auth(Map.keys(graph), graph, create, version, MapSet.new(), MapSet.new()),
         :ok <- Authorization.check(event, materialize(state_ids, graph), version) do
      {:ok, %{event: event, graph: graph, state: state_ids, create: create}}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_room_snapshot}
    end
  end

  defp verify_all(events, version, ref, lookup) do
    Enum.reduce_while(events, {:ok, %{}}, fn wire, {:ok, graph} ->
      case Event.verify(wire, version, lookup) do
        {:ok, event} ->
          if (event["type"] == "m.room.create" and Event.room_id(event, version) == ref) or
               event["room_id"] == ref do
            {:cont, {:ok, Map.put(graph, event["event_id"], event)}}
          else
            {:halt, {:error, :wrong_room}}
          end

        error ->
          {:halt, error}
      end
    end)
  end

  defp state_ids(state, version) do
    Enum.reduce_while(state, {:ok, %{}}, fn event, {:ok, ids} ->
      key = Authorization.key(event)

      if is_binary(event["state_key"]) and not Map.has_key?(ids, key),
        do: {:cont, {:ok, Map.put(ids, key, Event.id(event, version))}},
        else: {:halt, {:error, :invalid_state}}
    end)
  end

  defp verify_auth([], _, _, _, checked, _), do: {:ok, checked}

  defp verify_auth([id | rest], graph, create, version, checked, visiting) do
    cond do
      MapSet.member?(checked, id) ->
        verify_auth(rest, graph, create, version, checked, visiting)

      MapSet.member?(visiting, id) ->
        {:error, :cyclic_auth_graph}

      is_nil(graph[id]) ->
        {:error, :missing_auth_event}

      true ->
        event = graph[id]

        with {:ok, checked} <-
               verify_auth(
                 event["auth_events"],
                 graph,
                 create,
                 version,
                 checked,
                 MapSet.put(visiting, id)
               ),
             :ok <- Authorization.check_auth_events(event, graph, version, create) do
          verify_auth(rest, graph, create, version, MapSet.put(checked, id), visiting)
        end
    end
  end

  defp materialize(state, graph), do: Map.new(state, fn {key, id} -> {key, graph[id]} end)
end
