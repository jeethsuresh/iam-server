defmodule LakehouseMatrix.Federation.Transactions do
  @moduledoc "Replay-safe federation ingestion with independent PDU results and durable dependency retries."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, Identity}
  alias LakehouseMatrix.Federation.{Edus, Keyring, RoomAccess, Signing}
  alias LakehouseMatrix.Protocol.{Event, Graph}

  def receive(origin, transaction_id, body) do
    pdus = body["pdus"] || []
    edus = body["edus"] || []

    if is_binary(transaction_id) and byte_size(transaction_id) in 1..255 and
         body["origin"] == origin and
         is_integer(body["origin_server_ts"]) and is_list(pdus) and length(pdus) <= 50 and
         is_list(edus) and length(edus) <= 100 do
      case cached(origin, transaction_id) do
        nil -> ingest(origin, transaction_id, pdus, edus, body)
        response -> {:ok, response}
      end
    else
      {:error, :invalid_param}
    end
  end

  defp ingest(origin, transaction_id, pdus, edus, body) do
    candidates = Enum.flat_map(pdus, &candidate(origin, &1))
    {results, pending} = process(candidates, %{}, length(candidates) + 1)

    for {id, metadata, wire} <- pending do
      Repo.insert_all(
        "matrix_federation_inbox",
        [
          %{
            event_id: id,
            origin: origin,
            local_room_id: ClientStore.dump_id(metadata.local_room_id),
            pdu: wire,
            available_at: ClientStore.now(),
            attempts: 0
          }
        ],
        on_conflict: :nothing,
        conflict_target: [:event_id]
      )
    end

    Enum.each(edus, &Edus.receive(origin, &1))
    response = %{"pdus" => results}

    Repo.insert_all(
      "matrix_federation_transactions",
      [
        %{
          origin: origin,
          transaction_id: transaction_id,
          request_hash: :crypto.hash(:sha256, Signing.canonical(body)),
          response: response,
          received_at: ClientStore.now()
        }
      ],
      on_conflict: :nothing,
      conflict_target: [:origin, :transaction_id]
    )

    {:ok, cached(origin, transaction_id)}
  end

  defp candidate(origin, wire) when is_map(wire) do
    ref = wire["room_id"]
    metadata = if is_binary(ref), do: Graph.room_by_id(ref)

    version =
      if metadata, do: metadata.version, else: get_in(wire, ["content", "room_version"]) || "12"

    if version in Event.versions() do
      id = Event.id(wire, version)

      cond do
        is_nil(metadata) ->
          [{id, {:error, :unknown_room}}]

        not RoomAccess.allowed?(metadata, origin) ->
          [{id, {:error, :server_denied}}]

        not RoomAccess.joined?(RoomAccess.state(metadata), Identity.homeserver_domain()) ->
          [{id, {:error, :not_in_room}}]

        true ->
          case Event.verify(wire, version, &Keyring.key/3) do
            {:ok, _} -> [{id, metadata, wire}]
            error -> [{id, error}]
          end
      end
    else
      []
    end
  rescue
    _ -> []
  end

  defp candidate(_, _), do: []

  defp process(candidates, results, remaining) when remaining > 0 do
    {pending, results, progress} =
      Enum.reduce(candidates, {[], results, false}, fn
        {id, {:error, reason}}, {pending, results, progress} ->
          {pending, Map.put(results, id, failure(reason)), progress}

        {id, metadata, wire} = candidate, {pending, results, progress} ->
          case Graph.receive_pdu(metadata.local_room_id, wire) do
            {:ok, _} ->
              {pending, Map.put(results, id, %{}), true}

            {:error, reason}
            when reason in [:missing_prev_event, :missing_auth_event, :missing_prev_state] ->
              {[candidate | pending], Map.put(results, id, failure(reason)), progress}

            {:error, reason} ->
              {pending, Map.put(results, id, failure(reason)), progress}
          end
      end)

    if progress and pending != [],
      do: process(Enum.reverse(pending), results, remaining - 1),
      else: {results, pending}
  end

  defp process(pending, results, _), do: {results, pending}
  defp failure(reason), do: %{"error" => reason |> inspect() |> String.slice(0, 255)}

  defp cached(origin, id),
    do:
      Repo.one(
        from t in "matrix_federation_transactions",
          where: t.origin == ^origin and t.transaction_id == ^id,
          select: t.response
      )
end
