defmodule LakehouseMatrix.Federation.Outbox do
  @moduledoc "Durable, ordered per-destination delivery with stable transaction IDs and crash-recoverable leases."
  use GenServer
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.ClientStore
  alias LakehouseMatrix.Federation.{Keyring, Signing, Transport}
  alias LakehouseMatrix.Protocol.{Event, Graph}

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  @impl true
  def init(_),
    do:
      (
        send(self(), :deliver)
        {:ok, %{}}
      )

  @impl true
  def handle_info(:deliver, state) do
    result = deliver_once()
    Process.send_after(self(), :deliver, if(result == :idle, do: 1000, else: 10))
    {:noreply, state}
  end

  def deliver_once(request \\ &Transport.request/4, lookup \\ &Keyring.key/3) do
    case claim() do
      nil ->
        :idle

      item ->
        path =
          if item.kind == "leave" do
            record = Graph.event(item.event_id)
            room = Graph.room(record.local_room_id)

            "/_matrix/federation/v2/send_leave/" <>
              escape(room.room_id) <> "/" <> escape(item.event_id)
          else
            if item.kind == "invite" do
              record = Graph.event(item.event_id)
              room = Graph.room(record.local_room_id)

              "/_matrix/federation/v2/invite/" <>
                escape(room.room_id) <> "/" <> escape(item.event_id)
            else
              "/_matrix/federation/v1/send/" <> escape(item.transaction_id)
            end
          end

        result = request.(:put, item.destination, path, LakehouseMatrix.Erasure.outbox(item))

        case result do
          {:ok, body} ->
            case accept_response(item, body, lookup) do
              :ok -> complete(item.id, :delivered_at, nil)
              {:rejected, reason} -> complete(item.id, :failed_at, reason)
              {:error, reason} -> retry(item, reason)
            end

          {:error, {:http, status, _}} when status in [400, 403, 404, 405, 410, 413, 415, 422] ->
            complete(item.id, :failed_at, "HTTP #{status}")

          {:error, reason} ->
            retry(item, reason)
        end

        :delivered
    end
  end

  defp claim do
    {:ok, item} =
      Repo.transaction(fn ->
        now = ClientStore.now()

        result =
          Repo.query!(
            """
            SELECT o.id, o.destination, o.event_id, o.kind, o.payload, o.transaction_id, o.attempts
            FROM matrix_federation_outbox o
            WHERE o.delivered_at IS NULL AND o.failed_at IS NULL AND o.available_at <= $1
              AND (o.lease_until IS NULL OR o.lease_until < $1)
              AND NOT EXISTS (SELECT 1 FROM matrix_federation_outbox p
                WHERE p.destination = o.destination AND p.id < o.id AND p.delivered_at IS NULL AND p.failed_at IS NULL)
            ORDER BY o.id LIMIT 1 FOR UPDATE OF o SKIP LOCKED
            """,
            [now]
          )

        case result.rows do
          [] ->
            nil

          [[id, destination, event_id, kind, payload, transaction_id, attempts]] ->
            Repo.update_all(from(o in "matrix_federation_outbox", where: o.id == ^id),
              set: [lease_until: DateTime.add(now, 60, :second), attempts: attempts + 1]
            )

            %{
              id: id,
              destination: destination,
              event_id: event_id,
              kind: kind,
              payload: payload,
              transaction_id: transaction_id,
              attempts: attempts + 1
            }
        end
      end)

    item
  end

  defp accept_response(_, body, _) when not is_map(body), do: {:error, :invalid_peer_response}

  defp accept_response(%{kind: "invite"} = item, body, lookup) when is_map(body) do
    record = Graph.event(item.event_id)
    room = Graph.room(record.local_room_id)

    with event when is_map(event) <- body["event"],
         true <- Event.id(event, room.version) == item.event_id,
         {:ok, _} <- Event.verify(event, room.version, lookup),
         true <- recipient_signed?(event, room.version, item.destination, lookup) do
      # Keep the original content, adding only the recipient's verified signature.
      signatures =
        Map.put(record.pdu["signatures"], item.destination, event["signatures"][item.destination])

      record
      |> Ecto.Changeset.change(pdu: Map.put(record.pdu, "signatures", signatures))
      |> Repo.update!()

      :ok
    else
      _ -> {:error, :invalid_invite_response}
    end
  end

  defp accept_response(%{kind: "leave"}, body, _) when is_map(body), do: :ok

  defp accept_response(%{kind: "edu"}, body, _) when is_map(body),
    do: if(is_map(body["pdus"]), do: :ok, else: {:error, :invalid_transaction_response})

  defp accept_response(item, %{"pdus" => results}, _) when is_map(results) do
    case Map.fetch(results, item.event_id) do
      {:ok, %{"error" => reason}} -> {:rejected, inspect(reason) |> String.slice(0, 512)}
      {:ok, value} when is_map(value) -> :ok
      # A peer may ignore an already-known event and omit its result. A 200
      # transaction response still completes transport delivery; replaying that
      # stable transaction forever cannot produce a different acknowledgement.
      :error -> :ok
      _ -> {:error, :invalid_transaction_response}
    end
  end

  defp accept_response(_, _, _), do: {:error, :invalid_transaction_response}

  defp recipient_signed?(event, version, server, lookup) do
    Enum.any?(event["signatures"][server] || %{}, fn {id, _} ->
      with true <- String.starts_with?(id, "ed25519:"),
           {:ok, public} <- lookup.(server, id, event["origin_server_ts"]),
           do:
             Signing.verify(
               Event.redact(Map.delete(event, "event_id"), version),
               public,
               id,
               server
             ),
           else: (_ -> false)
    end)
  end

  defp complete(id, field, error),
    do:
      Repo.update_all(from(o in "matrix_federation_outbox", where: o.id == ^id),
        set: [{field, ClientStore.now()}, {:lease_until, nil}, {:last_error, error}]
      )

  defp retry(item, reason) do
    seconds = min(3600, 5 * Integer.pow(2, min(item.attempts - 1, 10))) + :rand.uniform(5)

    summary =
      case reason do
        {:http, status, _} -> "HTTP #{status}"
        _ -> inspect(reason) |> String.slice(0, 255)
      end

    Repo.update_all(from(o in "matrix_federation_outbox", where: o.id == ^item.id),
      set: [
        lease_until: nil,
        available_at: DateTime.add(ClientStore.now(), seconds, :second),
        last_error: summary
      ]
    )
  end

  defp escape(value), do: URI.encode(value, &URI.char_unreserved?/1)
end
