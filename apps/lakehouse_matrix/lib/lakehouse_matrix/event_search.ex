defmodule LakehouseMatrix.EventSearch do
  @moduledoc "Timestamp lookup over visible native events, with authenticated historical discovery."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientHistory, ClientRooms, ClientSync, Identity}
  alias LakehouseMatrix.Protocol.{Event, Graph}
  alias LakehouseMatrix.Federation.{Keyring, RoomAccess, Transport}

  def timestamp(principal, ref, params, request \\ &Transport.request/4, lookup \\ &Keyring.key/3) do
    with {:ok, room, _} <- ClientRooms.history_access(principal, ref),
         metadata when not is_nil(metadata) <- Graph.room(room.id),
         {:ok, ts, direction} <- parameters(params),
         {:ok, closest} <- closest(metadata, {:user, principal}, ts, direction) do
      closest = discover(metadata, principal, ts, direction, closest, request, lookup)
      result(closest)
    else
      {:error, _} = error -> error
      _ -> {:error, :not_found}
    end
  end

  def federation(origin, ref, params) do
    with metadata when not is_nil(metadata) <- Graph.room_by_id(ref),
         true <- RoomAccess.readable?(metadata, origin),
         {:ok, ts, direction} <- parameters(params),
         {:ok, closest} <- closest(metadata, {:server, origin}, ts, direction),
         do: result(closest),
         else: (
           {:error, _} = error -> error
           _ -> {:error, :not_found}
         )
  end

  defp parameters(params) do
    with true <- not is_nil(params["ts"]) and params["dir"] in ["b", "f"],
         {:ok, ts} <-
           ClientSync.integer(params["ts"], 0, -9_007_199_254_740_991, 9_007_199_254_740_991),
         do: {:ok, ts, params["dir"]},
         else: (_ -> {:error, :invalid_param})
  end

  defp closest(metadata, subject, ts, direction) do
    query = ClientHistory.query(metadata.local_room_id)

    query =
      if direction == "f",
        do:
          from(p in query,
            where: fragment("(?->>'origin_server_ts')::bigint >= ?", p.pdu, ^ts),
            order_by: [asc: fragment("(?->>'origin_server_ts')::bigint", p.pdu), asc: p.event_id]
          ),
        else:
          from(p in query,
            where: fragment("(?->>'origin_server_ts')::bigint <= ?", p.pdu, ^ts),
            order_by: [
              desc: fragment("(?->>'origin_server_ts')::bigint", p.pdu),
              desc: p.event_id
            ]
          )

    scan(query, metadata, subject, direction, nil, System.monotonic_time(:millisecond) + 10_000)
  end

  defp scan(query, metadata, subject, direction, cursor, deadline) do
    if System.monotonic_time(:millisecond) >= deadline do
      {:error, :unavailable}
    else
      page =
        if cursor do
          [ts, id] = cursor

          if direction == "f",
            do:
              from(p in query,
                where:
                  fragment(
                    "((?->>'origin_server_ts')::bigint, ?) > (?, ?)",
                    p.pdu,
                    p.event_id,
                    ^ts,
                    ^id
                  )
              ),
            else:
              from(p in query,
                where:
                  fragment(
                    "((?->>'origin_server_ts')::bigint, ?) < (?, ?)",
                    p.pdu,
                    p.event_id,
                    ^ts,
                    ^id
                  )
              )
        else
          query
        end

      rows = Repo.all(from p in page, limit: 500)

      visible =
        case subject do
          {:user, principal} ->
            ignored = ClientSync.ignored_users(principal)

            ClientHistory.visible(rows, metadata, principal)
            |> Enum.reject(
              &(not Map.has_key?(&1.pdu, "state_key") and &1.pdu["sender"] in ignored)
            )

          {:server, server} ->
            Enum.filter(rows, &RoomAccess.visible_event?(metadata, server, &1.event_id))
        end

      case visible do
        [event | _] ->
          {:ok, event}

        [] when length(rows) < 500 ->
          {:ok, nil}

        [] ->
          last = List.last(rows)

          scan(
            query,
            metadata,
            subject,
            direction,
            [last.pdu["origin_server_ts"], last.event_id],
            deadline
          )
      end
    end
  end

  defp discover(metadata, principal, ts, direction, closest, request, lookup) do
    if closest && abs(closest.pdu["origin_server_ts"] - ts) <= 60_000 do
      closest
    else
      # No network work is performed while holding the room/stream lock.
      state = RoomAccess.state(metadata)

      peers =
        for {{"m.room.member", user}, event} <- state,
            event["content"]["membership"] == "join",
            {:ok, server} <- [Event.user_domain(user)],
            server != Identity.homeserver_domain() and RoomAccess.allowed?(metadata, server),
            do: server

      peers = peers |> Enum.uniq() |> Enum.take(3)

      Enum.reduce(peers, closest, fn peer, best ->
        path =
          "/_matrix/federation/v1/timestamp_to_event/" <>
            escape(metadata.room_id) <> "?" <> URI.encode_query(%{"ts" => ts, "dir" => direction})

        with {:ok, %{"event_id" => id, "origin_server_ts" => remote_ts}} <-
               request.(:get, peer, path, nil),
             true <-
               is_binary(id) and byte_size(id) <= 255 and is_integer(remote_ts) and
                 remote_ts in -9_007_199_254_740_991..9_007_199_254_740_991 and
                 ((direction == "f" and remote_ts >= ts) or (direction == "b" and remote_ts <= ts)),
             true <- is_nil(best) or abs(remote_ts - ts) < abs(best.pdu["origin_server_ts"] - ts),
             {:ok, %{"pdus" => pdus}} <-
               request.(:get, peer, "/_matrix/federation/v1/event/" <> escape(id), nil),
             true <- is_list(pdus) and length(pdus) <= 100,
             wire when is_map(wire) <- Enum.find(pdus, &same_event?(&1, id, metadata.version)),
             true <- wire["origin_server_ts"] == remote_ts,
             {:ok, snapshot} <- ClientHistory.snapshot(metadata, peer, wire, request, lookup),
             {:ok, _} <-
               Graph.install_snapshot(
                 metadata.local_room_id,
                 metadata.room_id,
                 metadata.version,
                 snapshot,
                 :backfill
               ),
             {:ok, _} <- ClientHistory.event(principal, metadata.local_room_id, id) do
          Graph.event(id)
        else
          _ -> best
        end
      end)
    end
  end

  defp result(nil), do: {:error, :not_found}

  defp result(event),
    do:
      {:ok, %{"event_id" => event.event_id, "origin_server_ts" => event.pdu["origin_server_ts"]}}

  defp escape(value), do: URI.encode(value, &URI.char_unreserved?/1)

  defp same_event?(wire, id, version) do
    is_map(wire) and Event.id(wire, version) == id
  rescue
    _ -> false
  end
end
