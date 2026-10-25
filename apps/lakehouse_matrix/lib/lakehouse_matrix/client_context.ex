defmodule LakehouseMatrix.ClientContext do
  @moduledoc "State and event context at authenticated native pagination positions."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientHistory, ClientRooms, ClientSync, Cursor}
  alias LakehouseMatrix.Protocol.Graph
  alias LakehouseMatrix.Schema.Pdu

  def members(principal, device, ref, params) do
    with {:ok, room, boundary} <- ClientRooms.history_access(principal, ref),
         true <-
           params["membership"] in [nil, "join", "invite", "leave", "ban", "knock"] and
             params["not_membership"] in [nil, "join", "invite", "leave", "ban", "knock"],
         {:ok, state} <- state_at(principal, device, room.id, boundary, params["at"]) do
      chunk =
        Enum.filter(state, fn event ->
          membership = event["content"]["membership"]
          include = params["membership"]
          exclude = params["not_membership"]

          event["type"] == "m.room.member" and
            cond do
              include && exclude -> membership == include or membership != exclude
              include -> membership == include
              exclude -> membership != exclude
              true -> true
            end
        end)

      {:ok, %{"chunk" => chunk}}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_param}
    end
  end

  def context(principal, device, ref, id, params) do
    with {:ok, room, _} <- ClientRooms.history_access(principal, ref),
         true <- not is_nil(Graph.room(room.id)),
         {:ok, target} <- ClientHistory.event(principal, room.id, id),
         {:ok, limit} <- ClientSync.integer(params["limit"], 10, 0, 100),
         token <- ClientHistory.before(principal, device, room.id, id),
         {:ok, before} <-
           ClientHistory.page(principal, device, room.id, %{
             "from" => token,
             "dir" => "b",
             "limit" => div(limit, 2),
             "filter" => params["filter"]
           }),
         {:ok, after_events} <-
           ClientHistory.page(principal, device, room.id, %{
             "from" => token,
             "dir" => "f",
             "limit" => limit - div(limit, 2),
             "filter" => params["filter"]
           }) do
      last = List.last(after_events["chunk"]) || target
      state = state_events(Graph.event(last["event_id"]).state_after)
      filter = if params["filter"], do: Jason.decode!(params["filter"]), else: %{}
      earliest = List.last(before["chunk"]) || target
      latest = List.last(after_events["chunk"]) || target

      {:ok,
       %{
         "event" => target,
         "events_before" => before["chunk"],
         "events_after" => after_events["chunk"],
         "state" => ClientSync.filter_events(state, filter),
         "start" => ClientHistory.before(principal, device, room.id, earliest["event_id"]),
         "end" => ClientHistory.before(principal, device, room.id, latest["event_id"])
       }}
    else
      {:error, _} = error -> error
      _ -> {:error, :not_found}
    end
  end

  defp state_at(_, _, room, boundary, nil), do: {:ok, ClientSync.state_at(room, boundary)}

  defp state_at(principal, device, room, boundary, token) do
    case Cursor.decode(token, "topology", principal, device, room) do
      {:ok, [_, id]} ->
        after_event = String.ends_with?(id, "~")
        id = if after_event, do: String.trim_trailing(id, "~"), else: id

        with {:ok, _} <- ClientHistory.event(principal, room, id),
             %Pdu{local_room_id: ^room} = event <- Graph.event(id) do
          {:ok, state_events(if(after_event, do: event.state_after, else: event.state_before))}
        else
          _ -> {:error, :invalid_cursor}
        end

      _ ->
        with {:ok, stream} <- ClientSync.history_cursor(token, principal, device, room),
             do: {:ok, ClientSync.state_at(room, min(stream, boundary))}
    end
  end

  defp state_events(state) do
    ids = Map.values(state)

    Repo.all(from p in Pdu, where: p.event_id in ^ids, order_by: p.event_id)
    |> Enum.map(&ClientHistory.client_event/1)
  end
end
