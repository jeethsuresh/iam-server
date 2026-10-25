defmodule LakehouseMatrix.LegacySync do
  @moduledoc "Legacy sync and room peeking over the current, permission-filtered Matrix stream."
  import Ecto.Query
  alias LakehouseIam.Repo

  alias LakehouseMatrix.{
    AccountModeration,
    ClientRooms,
    ClientStore,
    ClientSync,
    Cursor,
    Events,
    Identity
  }

  alias LakehouseMatrix.Schema.RoomEvent

  def initial(principal, device, params) do
    with {:ok, limit} <- ClientSync.integer(params["limit"], 10, 0, 100),
         true <- params["archived"] in [nil, true, false, "true", "false"] do
      Repo.transaction(fn ->
        high = ClientStore.lock!()
        AccountModeration.require!(principal, :read)
        memberships = ClientSync.memberships_at(principal, high)
        rooms = Enum.map(memberships.join, &room_info(principal, device, &1, high, limit))

        invited =
          for room <- memberships.invite,
              do: %{
                "room_id" => Identity.room_id(room),
                "membership" => "invite",
                "state" => ClientSync.stripped(room, high, principal)
              }

        archived =
          if params["archived"] in [true, "true"] do
            for room <- memberships.leave,
                ClientSync.ever_joined?(principal, room, high),
                {:ok, _, boundary} <- [
                  ClientRooms.history_access(principal, Identity.room_id(room))
                ] do
              member = ClientSync.last_membership(principal, room, high)
              room_info(principal, device, room, min(member.stream_id, boundary), limit)
            end
          else
            []
          end

        %{
          "end" => Cursor.encode("sync", principal, device, high),
          "rooms" => rooms ++ invited ++ archived,
          "presence" => LakehouseMatrix.Ephemeral.presence_events(principal, 0, high),
          "account_data" => ClientStore.account_data(principal, "", 0, high)
        }
      end)
    else
      false -> {:error, :invalid_param}
      error -> error
    end
  end

  def room(principal, device, ref, params) do
    with {:ok, limit} <- ClientSync.integer(params["limit"], 10, 0, 100) do
      Repo.transaction(fn ->
        ClientStore.lock!()
        AccountModeration.require!(principal, :read)

        case ClientRooms.history_access(principal, ref) do
          {:ok, room, high} -> room_info(principal, device, room.id, high, limit)
          {:error, _} -> Repo.rollback(:forbidden)
        end
      end)
    end
  end

  def event(principal, id) when is_binary(id) and byte_size(id) <= 255 do
    case Repo.get_by(RoomEvent, event_id: id) do
      nil -> {:error, :not_found}
      record -> ClientRooms.event(principal, Identity.room_id(record.room_id), id)
    end
  end

  def event(_, _), do: {:error, :not_found}

  def stream(principal, device, params) do
    with {:ok, from} <- from(params["from"], principal, device),
         {:ok, timeout} <- ClientSync.integer(params["timeout"], 30_000, 0, 30_000),
         true <- is_nil(params["room_id"]) or is_binary(params["room_id"]) do
      poll(
        principal,
        device,
        params["room_id"],
        from,
        System.monotonic_time(:millisecond) + timeout
      )
    else
      false -> {:error, :invalid_param}
      error -> error
    end
  end

  defp from(nil, _, _), do: {:ok, ClientStore.position()}
  defp from(token, principal, device), do: Cursor.decode(token, "sync", principal, device)

  defp poll(principal, device, ref, from, deadline) do
    with {:ok, {payload, more}} <- snapshot(principal, device, ref, from) do
      remaining = deadline - System.monotonic_time(:millisecond)

      if payload["chunk"] == [] and not more and remaining > 0 do
        Process.sleep(min(remaining, 200))
        poll(principal, device, ref, from, deadline)
      else
        {:ok, payload}
      end
    end
  end

  defp snapshot(principal, device, ref, from) do
    Repo.transaction(fn ->
      high = ClientStore.lock!()
      AccountModeration.require!(principal, :read)
      memberships = ClientSync.memberships_at(principal, high)

      {rooms, bounds} =
        if ref do
          case ClientRooms.history_access(principal, ref) do
            {:ok, room, boundary} -> {[room.id], %{room.id => boundary}}
            {:error, _} -> Repo.rollback(:forbidden)
          end
        else
          rooms = Enum.uniq(memberships.join ++ memberships.invite ++ memberships.leave)

          bounds =
            Map.new(rooms, fn room ->
              boundary =
                case ClientRooms.history_access(principal, Identity.room_id(room)) do
                  {:ok, _, boundary} -> boundary
                  _ -> nil
                end

              {room, boundary}
            end)

          {rooms, bounds}
        end

      # Resolved state can change to a PDU whose timeline position is older.
      # Merge its state-change position into the same paginated stream.
      timeline =
        from e in RoomEvent,
          where:
            e.room_id in ^rooms and e.timeline_visible and e.stream_id > ^from and
              e.stream_id <= ^high,
          select: %{position: e.stream_id, event_id: e.event_id, room_id: e.room_id}

      state =
        from c in "matrix_state_changes",
          join: e in RoomEvent,
          on: e.event_id == c.event_id,
          where: e.room_id in ^rooms and c.stream_id > ^from and c.stream_id <= ^high,
          select: %{position: c.stream_id, event_id: e.event_id, room_id: e.room_id}

      query = union_all(timeline, ^state)

      candidates =
        Repo.all(from c in subquery(query), order_by: [c.position, c.event_id], limit: 1001)

      more = length(candidates) > 1000
      selected = Enum.take(candidates, 1000)
      finish = if more, do: List.last(selected).position, else: high
      ids = Enum.map(selected, & &1.event_id)

      allowed =
        Repo.all(
          ClientSync.visible_query(from(e in RoomEvent, where: e.event_id in ^ids), principal)
        )
        |> Map.new(&{&1.event_id, &1})

      user = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

      chunk =
        selected
        |> Enum.uniq_by(& &1.event_id)
        |> Enum.flat_map(fn item ->
          case allowed[item.event_id] do
            nil ->
              []

            event ->
              own_membership = event.type == "m.room.member" and event.state_key == user
              boundary = bounds[event.room_id]
              # Private invitations expose only the recipient's membership event.
              if own_membership or (is_integer(boundary) and item.position <= boundary) do
                [
                  Events.to_client_event(event, principal)
                  |> Map.put("room_id", Identity.room_id(event.room_id))
                ]
              else
                []
              end
          end
        end)

      presence =
        if ref, do: [], else: LakehouseMatrix.Ephemeral.presence_events(principal, from, finish)

      {%{
         "start" => Cursor.encode("sync", principal, device, from),
         "end" => Cursor.encode("sync", principal, device, finish),
         "chunk" => chunk ++ presence
       }, more}
    end)
  end

  defp room_info(principal, device, room, high, limit) do
    payload =
      ClientSync.room_payload(principal, device, room, 0, high, true, %{
        "_use_state_after" => true,
        "room" => %{"timeline" => %{"limit" => limit}}
      })

    ref = Identity.room_id(room)
    membership = ClientSync.last_membership(principal, room, high)

    result = %{
      "room_id" => ref,
      "messages" => %{
        "start" => payload["timeline"]["prev_batch"],
        "end" => Cursor.encode("sync", principal, device, high),
        "chunk" => Enum.map(payload["timeline"]["events"], &Map.put(&1, "room_id", ref))
      },
      "state" => Enum.map(payload["state_after"]["events"], &Map.put(&1, "room_id", ref)),
      "account_data" => payload["account_data"]["events"],
      "visibility" => Repo.get!(LakehouseMatrix.Schema.Room, room).visibility
    }

    if membership,
      do: Map.put(result, "membership", membership.content["membership"]),
      else: result
  end
end
