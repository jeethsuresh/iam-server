defmodule LakehouseMatrix.Federation.Edus do
  @moduledoc "Authenticated federation device messages, device invalidations, typing, presence and public receipts."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseMatrix.{ClientStore, Identity}
  alias LakehouseMatrix.Federation.RoomAccess
  alias LakehouseMatrix.Protocol.{Authorization, Event, Graph}
  alias LakehouseMatrix.Schema.ProtocolRoom

  def receive(origin, %{"edu_type" => type, "content" => content}) when is_map(content) do
    Repo.transaction(fn ->
      ClientStore.lock!()

      case type do
        "m.direct_to_device" -> to_device!(origin, content)
        "m.device_list_update" -> device_update!(origin, content)
        "m.signing_key_update" -> signing_update!(origin, content)
        "m.typing" -> typing!(origin, content)
        "m.presence" -> presence!(origin, content)
        "m.receipt" -> receipts!(origin, content)
        _ -> :ok
      end
    end)
  end

  def receive(_, _), do: {:error, :invalid_param}

  def shared_rooms(user) do
    key = Jason.encode!(["m.room.member", user])

    Repo.all(
      from r in ProtocolRoom,
        join: p in LakehouseMatrix.Schema.Pdu,
        on: p.event_id == fragment("?->>?", r.current_state, ^key),
        where: fragment("?->'content'->>'membership' = 'join'", p.pdu),
        select: r
    )
  end

  def outgoing!(destination, type, content) do
    Repo.insert_all("matrix_federation_outbox", [
      %{
        destination: destination,
        kind: "edu",
        payload: %{
          "origin" => Identity.homeserver_domain(),
          "origin_server_ts" => System.system_time(:millisecond),
          "pdus" => [],
          "edus" => [%{"edu_type" => type, "content" => content}]
        },
        attempts: 0,
        available_at: ClientStore.now(),
        transaction_id: ClientStore.random()
      }
    ])
  end

  def broadcast!(metadata, type, content) do
    servers =
      for {{"m.room.member", user}, event} <- RoomAccess.state(metadata),
          event["content"]["membership"] == "join",
          {:ok, server} <- [Event.user_domain(user)],
          server != Identity.homeserver_domain() and RoomAccess.allowed?(metadata, server),
          do: server

    for server <- Enum.uniq(servers), do: outgoing!(server, type, content)
    :ok
  end

  defp to_device!(origin, content) do
    sender = content["sender"]
    type = content["type"]
    id = content["message_id"]
    messages = content["messages"]

    unless Event.user_domain(sender) == {:ok, origin} and is_binary(type) and
             byte_size(type) in 1..255 and
             is_binary(id) and byte_size(id) in 1..255 and is_map(messages) and
             map_size(messages) <= 100,
           do: Repo.rollback(:invalid_param)

    {inserted, _} =
      Repo.insert_all(
        "matrix_federation_edus",
        [%{origin: origin, message_id: id, received_at: ClientStore.now()}],
        on_conflict: :nothing,
        conflict_target: [:origin, :message_id]
      )

    if inserted > 0 do
      for {user, devices} <- messages do
        unless is_map(devices) and map_size(devices) <= 100, do: Repo.rollback(:invalid_param)

        with {:ok, name} <- Identity.parse_user_id(user),
             {:ok, principal} <- Accounts.fetch_user(name) do
          for {device, message} <- devices do
            unless is_map(message) and byte_size(Jason.encode!(message)) <= 65_536,
              do: Repo.rollback(:invalid_param)

            query =
              from d in "matrix_devices", where: d.principal_id == type(^principal.id, :binary_id)

            query =
              if device == "*", do: query, else: from(d in query, where: d.device_id == ^device)

            for device <- Repo.all(from d in query, select: d.device_id) do
              Repo.insert_all("matrix_to_device", [
                %{
                  principal_id: ClientStore.dump_id(principal.id),
                  device_id: device,
                  sender: sender,
                  type: type,
                  content: message
                }
              ])
            end
          end
        end
      end
    end

    :ok
  end

  defp device_update!(origin, content) do
    user = content["user_id"]
    stream = content["stream_id"]
    device = content["device_id"]
    previous = content["prev_id"] || []

    unless Event.user_domain(user) == {:ok, origin} and is_integer(stream) and is_binary(device) and
             byte_size(device) in 1..255 and
             is_list(previous) and length(previous) <= 100 and Enum.all?(previous, &is_integer/1),
           do: Repo.rollback(:invalid_param)

    if shared_rooms(user) != [] do
      current =
        Repo.one(
          from u in "matrix_remote_users",
            where: u.user_id == ^user,
            select: %{stream: u.device_stream_id, valid: u.valid}
        )

      if is_nil(current) or stream != current.stream do
        contiguous = current && current.valid && current.stream in previous
        valid = contiguous == true

        Repo.insert_all(
          "matrix_remote_users",
          [%{user_id: user, device_stream_id: stream, valid: valid}],
          on_conflict: [set: [device_stream_id: stream, valid: valid]],
          conflict_target: [:user_id]
        )

        if valid do
          if content["deleted"] == true do
            Repo.delete_all(
              from d in "matrix_remote_devices",
                where: d.user_id == ^user and d.device_id == ^device
            )
          else
            keys = content["keys"] || %{}

            unless is_map(keys) and keys["user_id"] == user and keys["device_id"] == device,
              do: Repo.rollback(:invalid_param)

            display = content["device_display_name"]

            Repo.insert_all(
              "matrix_remote_devices",
              [%{user_id: user, device_id: device, keys: keys, display_name: display}],
              on_conflict: [set: [keys: keys, display_name: display]],
              conflict_target: [:user_id, :device_id]
            )
          end
        end

        changed!(user)
      end
    end

    :ok
  end

  defp signing_update!(origin, content) do
    user = content["user_id"]
    unless Event.user_domain(user) == {:ok, origin}, do: Repo.rollback(:forbidden)

    if shared_rooms(user) != [] do
      for field <- ~w(master_key self_signing_key),
          value = content[field],
          not is_nil(value),
          do: if(not is_map(value) or value["user_id"] != user, do: Repo.rollback(:invalid_param))

      Repo.insert_all(
        "matrix_remote_users",
        [
          %{
            user_id: user,
            valid: false,
            master_key: content["master_key"],
            self_signing_key: content["self_signing_key"]
          }
        ],
        on_conflict: [
          set: [
            valid: false,
            master_key: content["master_key"],
            self_signing_key: content["self_signing_key"]
          ]
        ],
        conflict_target: [:user_id]
      )

      changed!(user)
    end
  end

  defp typing!(origin, content) do
    user = content["user_id"]

    with {:ok, ^origin} <- Event.user_domain(user),
         true <- is_boolean(content["typing"]) and is_binary(content["room_id"]),
         metadata when not is_nil(metadata) <- Graph.room_by_id(content["room_id"]),
         true <- RoomAccess.allowed?(metadata, origin),
         "join" <- Authorization.membership(RoomAccess.state(metadata), user) do
      ephemeral!(metadata.local_room_id, user, "m.typing", %{"typing" => content["typing"]}, 30)
    else
      _ -> :ok
    end
  end

  defp presence!(origin, content) do
    push = content["push"] || []
    unless is_list(push) and length(push) <= 1000, do: Repo.rollback(:invalid_param)

    for value <- push,
        is_map(value),
        Event.user_domain(value["user_id"]) == {:ok, origin},
        value["presence"] in ~w(online offline unavailable),
        metadata <- shared_rooms(value["user_id"]),
        RoomAccess.allowed?(metadata, origin) do
      data =
        Map.take(
          value,
          ~w(presence status_msg currently_active last_active_ago displayname avatar_url)
        )
        |> Map.reject(fn {_, value} -> is_nil(value) end)

      unless Enum.all?(~w(status_msg displayname avatar_url), fn key ->
               is_nil(data[key]) or (is_binary(data[key]) and byte_size(data[key]) <= 4096)
             end) and
               (is_nil(data["currently_active"]) or is_boolean(data["currently_active"])) and
               (is_nil(data["last_active_ago"]) or
                  (is_integer(data["last_active_ago"]) and
                     data["last_active_ago"] in 0..9_007_199_254_740_991)),
             do: Repo.rollback(:invalid_param)

      ephemeral!(metadata.local_room_id, value["user_id"], "m.presence", data, 180)
    end
  end

  defp receipts!(origin, content) do
    unless map_size(content) <= 100, do: Repo.rollback(:invalid_param)

    for {ref, receipts} <- content, is_map(receipts) do
      with metadata when not is_nil(metadata) <- Graph.room_by_id(ref),
           true <- RoomAccess.allowed?(metadata, origin) do
        state = RoomAccess.state(metadata)
        reads = receipts["m.read"]
        reads = if is_map(reads), do: reads, else: %{}

        for {user, receipt} <- reads,
            Event.user_domain(user) == {:ok, origin},
            Authorization.membership(state, user) == "join",
            is_map(receipt),
            is_list(receipt["event_ids"]),
            length(receipt["event_ids"]) <= 100 do
          events =
            for id <- receipt["event_ids"],
                is_binary(id),
                pdu = Graph.event(id),
                not is_nil(pdu),
                pdu.local_room_id == metadata.local_room_id,
                do: pdu

          if events != [] do
            event = Enum.max_by(events, &{&1.pdu["depth"], &1.event_id})

            data =
              if is_map(receipt["data"]),
                do: Map.take(receipt["data"], ~w(ts thread_id)),
                else: %{}

            thread = data["thread_id"] || ""

            if is_binary(thread) do
              Repo.insert_all(
                "matrix_remote_receipts",
                [
                  %{
                    local_room_id: ClientStore.dump_id(metadata.local_room_id),
                    user_id: user,
                    type: "m.read",
                    thread_id: thread,
                    event_id: event.event_id,
                    data: data
                  }
                ],
                on_conflict: [set: [event_id: event.event_id, data: data]],
                conflict_target: [:local_room_id, :user_id, :type, :thread_id]
              )
            end
          end
        end
      end
    end
  end

  defp changed!(user), do: Repo.insert_all("matrix_device_changes", [%{user_id: user}])

  defp ephemeral!(room, user, type, content, seconds) do
    received = ClientStore.now()
    expiry = DateTime.add(received, seconds, :second)

    Repo.insert_all(
      "matrix_ephemeral_events",
      [
        %{
          local_room_id: ClientStore.dump_id(room),
          user_id: user,
          type: type,
          content: content,
          expires_at: expiry,
          received_at: received
        }
      ],
      on_conflict: [set: [content: content, expires_at: expiry, received_at: received]],
      conflict_target: [:local_room_id, :type, :user_id]
    )
  end
end
