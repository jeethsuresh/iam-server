defmodule LakehouseMatrix.ClientEventMetadata do
  @moduledoc "Locally computed state-replacement metadata, with prior content subject to event visibility and erasure."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientHistory, Erasure, Identity}
  alias LakehouseMatrix.Protocol.Graph
  alias LakehouseMatrix.Schema.{Pdu, RoomEvent}

  def replaces(event, %Pdu{} = record) do
    if is_binary(event["state_key"]) do
      key = Jason.encode!([event["type"], event["state_key"]])
      put_previous(event, record.state_before[key])
    else
      event
    end
  end

  def replaces(event, %RoomEvent{state_key: nil}), do: event

  def replaces(event, %RoomEvent{} = record) do
    case Graph.event(record.event_id) do
      %Pdu{} = pdu ->
        replaces(event, pdu)

      nil ->
        previous =
          if is_binary(record.state_key),
            do:
              Repo.one(
                from e in RoomEvent,
                  where:
                    e.room_id == ^record.room_id and e.type == ^record.type and
                      e.state_key == ^record.state_key and e.stream_id < ^record.stream_id,
                  order_by: [desc: e.stream_id],
                  limit: 1,
                  select: e.event_id
              )

        put_previous(event, previous)
    end
  end

  def previous_content(event, principal) do
    previous = get_in(event, ["unsigned", "replaces_state"])

    with true <- is_binary(previous) and is_binary(principal),
         %Pdu{} = record <- Graph.event(previous),
         metadata when not is_nil(metadata) <- Graph.room(record.local_room_id),
         [_] <- ClientHistory.visible([record], metadata, principal) do
      prior = record |> ClientHistory.client_event() |> Erasure.client(principal)
      Map.update!(event, "unsigned", &Map.put(&1, "prev_content", prior["content"]))
    else
      _ -> legacy_content(event, principal, previous)
    end
  end

  defp legacy_content(event, principal, previous)
       when is_binary(principal) and is_binary(previous) do
    with %RoomEvent{} = record <- Repo.get_by(RoomEvent, event_id: previous),
         nil <- Graph.room(record.room_id),
         {:ok, _, high} <-
           LakehouseMatrix.ClientRooms.history_access(principal, Identity.room_id(record.room_id)),
         true <- record.stream_id <= high,
         query <- from(e in RoomEvent, where: e.id == ^record.id),
         true <- Repo.exists?(LakehouseMatrix.ClientSync.visible_query(query, principal)) do
      prior = record |> LakehouseMatrix.Events.to_client_event() |> Erasure.client(principal)
      Map.update!(event, "unsigned", &Map.put(&1, "prev_content", prior["content"]))
    else
      _ -> event
    end
  end

  defp legacy_content(event, _, _), do: event

  defp put_previous(event, id) when is_binary(id),
    do:
      Map.update(event, "unsigned", %{"replaces_state" => id}, &Map.put(&1, "replaces_state", id))

  defp put_previous(event, _), do: event
end
