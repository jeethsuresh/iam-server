defmodule LakehouseMatrix.Federation.Inbox do
  @moduledoc "Recover missing event/state dependencies without holding database locks across peer requests."
  use GenServer
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, Identity}
  alias LakehouseMatrix.Federation.{Keyring, RoomAccess, Transport}
  alias LakehouseMatrix.Protocol.{Event, Graph, Import}

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  @impl true
  def init(_),
    do:
      (
        send(self(), :recover)
        {:ok, %{}}
      )

  @impl true
  def handle_info(:recover, state) do
    result = recover_once()
    Process.send_after(self(), :recover, if(result == :idle, do: 1000, else: 10))
    {:noreply, state}
  end

  def recover_once(request \\ &Transport.request/4, lookup \\ &Keyring.key/3) do
    case claim() do
      nil ->
        :idle

      item ->
        result = recover(item, request, lookup)

        case result do
          {:ok, _} ->
            Repo.delete_all(
              from i in "matrix_federation_inbox", where: i.event_id == ^item.event_id
            )

          {:error, reason}
          when reason in [:forbidden, :wrong_room, :rejected_event, :invalid_room_snapshot] ->
            fail(item, reason)

          {:error, reason} ->
            retry(item, reason)
        end

        :recovered
    end
  end

  defp recover(item, request, lookup) do
    metadata = Graph.room(item.local_room_id)

    with true <-
           not is_nil(metadata) and RoomAccess.allowed?(metadata, item.origin) and
             RoomAccess.joined?(RoomAccess.state(metadata), Identity.homeserver_domain()),
         {:ok, _} <- Event.verify(item.pdu, metadata.version, lookup) do
      case Graph.receive_pdu(item.local_room_id, item.pdu, lookup) do
        {:error, reason}
        when reason in [:missing_prev_event, :missing_prev_state, :missing_auth_event] ->
          with :ok <- recover_parents(item, metadata, request, lookup) do
            case Graph.receive_pdu(item.local_room_id, item.pdu, lookup) do
              {:error, :missing_auth_event} ->
                with {:ok, snapshot} <-
                       snapshot(item.origin, metadata, item.pdu, request, lookup),
                     {:ok, _} <- Graph.store_auth(item.local_room_id, snapshot),
                     do: Graph.receive_pdu(item.local_room_id, item.pdu, lookup)

              result ->
                result
            end
          end

        result ->
          result
      end
    else
      false -> {:error, :forbidden}
      error -> error
    end
  rescue
    _ -> {:error, :invalid_peer_response}
  end

  defp recover_parents(item, metadata, request, lookup) do
    Enum.reduce_while(item.pdu["prev_events"], :ok, fn id, :ok ->
      record = Graph.event(id)

      if record && not record.outlier do
        if record.local_room_id == metadata.local_room_id,
          do: {:cont, :ok},
          else: {:halt, {:error, :wrong_room}}
      else
        result =
          with {:ok, response} <-
                 request.(:get, item.origin, "/_matrix/federation/v1/event/" <> escape(id), nil),
               [wire] <- response["pdus"],
               true <- Event.id(wire, metadata.version) == id,
               {:ok, snapshot} <- snapshot(item.origin, metadata, wire, request, lookup),
               {:ok, _} <-
                 Graph.install_snapshot(
                   item.local_room_id,
                   metadata.room_id,
                   metadata.version,
                   snapshot,
                   :backfill
                 ),
               do: :ok

        case result do
          :ok -> {:cont, :ok}
          {:error, _} = error -> {:halt, error}
          _ -> {:halt, {:error, :invalid_peer_response}}
        end
      end
    end)
  end

  defp snapshot(origin, metadata, wire, request, lookup) do
    id = Event.id(wire, metadata.version)

    path =
      "/_matrix/federation/v1/state/" <>
        escape(metadata.room_id) <> "?event_id=" <> URI.encode_www_form(id)

    with {:ok, response} <- request.(:get, origin, path, nil),
         do:
           Import.snapshot(
             metadata.room_id,
             metadata.version,
             wire,
             response["pdus"],
             response["auth_chain"],
             lookup
           )
  end

  defp claim do
    {:ok, item} =
      Repo.transaction(fn ->
        now = ClientStore.now()

        result =
          Repo.query!(
            """
            SELECT event_id, origin, local_room_id, pdu, attempts FROM matrix_federation_inbox
            WHERE failed_at IS NULL AND available_at <= $1 AND (lease_until IS NULL OR lease_until < $1)
            ORDER BY available_at LIMIT 1 FOR UPDATE SKIP LOCKED
            """,
            [now]
          )

        case result.rows do
          [] ->
            nil

          [[id, origin, local_id, pdu, attempts]] ->
            Repo.update_all(from(i in "matrix_federation_inbox", where: i.event_id == ^id),
              set: [lease_until: DateTime.add(now, 900, :second), attempts: attempts + 1]
            )

            %{
              event_id: id,
              origin: origin,
              local_room_id: Ecto.UUID.load!(local_id),
              pdu: pdu,
              attempts: attempts + 1
            }
        end
      end)

    item
  end

  defp fail(item, reason),
    do:
      Repo.update_all(from(i in "matrix_federation_inbox", where: i.event_id == ^item.event_id),
        set: [
          failed_at: ClientStore.now(),
          lease_until: nil,
          last_error: inspect(reason) |> String.slice(0, 255)
        ]
      )

  defp retry(item, reason) do
    seconds = min(3600, 5 * Integer.pow(2, min(item.attempts - 1, 10)))

    Repo.update_all(from(i in "matrix_federation_inbox", where: i.event_id == ^item.event_id),
      set: [
        lease_until: nil,
        available_at: DateTime.add(ClientStore.now(), seconds, :second),
        last_error: inspect(reason) |> String.slice(0, 255)
      ]
    )
  end

  defp escape(value), do: URI.encode(value, &URI.char_unreserved?/1)
end
