defmodule LakehouseWeb.Matrix.ProtocolController do
  use LakehouseWeb, :controller
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientKeys, ClientRooms, ClientStore, ClientSync, Identity, Memberships}

  def create_room(conn, params), do: respond(conn, ClientRooms.create(principal(conn), params))
  def login_flows(conn, _), do: json(conn, %{"flows" => [%{"type" => "m.login.password"}]})

  def login(conn, params) do
    identifier = if is_map(params["identifier"]), do: params["identifier"], else: %{}
    user = identifier["user"] || params["user"]

    if params["type"] in [nil, "m.login.password"] and is_binary(user) and
         is_binary(params["password"]) do
      respond(conn, ClientStore.login(user, params["password"], params))
    else
      error(
        conn,
        400,
        "M_INVALID_PARAM",
        "A supported login type, user and password are required"
      )
    end
  end

  def sync(conn, params),
    do: respond(conn, ClientSync.sync(principal(conn), device(conn), params))

  def sliding_sync(conn, params),
    do:
      respond(
        conn,
        LakehouseMatrix.SlidingSync.sync(
          principal(conn),
          device(conn),
          params,
          if(String.contains?(conn.request_path, "/v4/"), do: :v4, else: :msc4186)
        )
      )

  def whoami(conn, _),
    do:
      json(conn, %{
        "user_id" => Identity.user_id(conn.assigns.username),
        "device_id" => device(conn),
        "is_guest" => false
      })

  def logout(conn, _), do: json(conn, ClientStore.logout(principal(conn), device(conn)))
  def logout_all(conn, _), do: json(conn, ClientStore.logout(principal(conn), device(conn), true))
  def devices(conn, _), do: json(conn, %{"devices" => ClientStore.devices(principal(conn))})

  def get_device(conn, %{"device" => device}) do
    case Enum.find(ClientStore.devices(principal(conn)), &(&1.device_id == device)) do
      nil -> respond(conn, {:error, :not_found})
      found -> json(conn, found)
    end
  end

  def update_device(conn, %{"device" => device} = params),
    do: respond(conn, ClientStore.update_device(principal(conn), device, params["display_name"]))

  def capabilities(conn, _),
    do:
      json(conn, %{
        "capabilities" => %{
          "m.change_password" => %{"enabled" => false},
          "m.set_displayname" => %{"enabled" => false},
          "m.set_avatar_url" => %{"enabled" => false},
          "m.3pid_changes" => %{"enabled" => false}
        }
      })

  def joined_rooms(conn, _),
    do:
      json(conn, %{
        "joined_rooms" =>
          Enum.map(Memberships.joined_room_ids(principal(conn)), &Identity.room_id/1)
      })

  def get_state(conn, %{"roomId" => ref} = params) do
    with {:ok, room} <- ClientRooms.readable(principal(conn), ref) do
      events = ClientSync.state_at(room.id, ClientStore.position())

      if type = params["eventType"] do
        case Enum.find(
               events,
               &(&1["type"] == type and &1["state_key"] == (params["stateKey"] || ""))
             ) do
          nil -> respond(conn, {:error, :not_found})
          event -> json(conn, event["content"])
        end
      else
        json(conn, events)
      end
    else
      _ -> respond(conn, {:error, :forbidden})
    end
  end

  def put_state(conn, %{"roomId" => ref, "eventType" => type} = p),
    do:
      respond(
        conn,
        ClientRooms.put_state(principal(conn), ref, type, p["stateKey"] || "", body(conn))
      )

  def send_event(conn, %{"roomId" => ref, "eventType" => type, "txnId" => txn}),
    do: respond(conn, ClientRooms.send(principal(conn), device(conn), ref, type, txn, body(conn)))

  def redact(conn, %{"roomId" => ref, "eventId" => event, "txnId" => txn}),
    do:
      respond(
        conn,
        ClientRooms.redact(principal(conn), device(conn), ref, event, txn, body(conn))
      )

  def event(conn, %{"roomId" => ref, "eventId" => event}),
    do: respond(conn, ClientRooms.event(principal(conn), ref, event))

  def messages(conn, %{"roomId" => ref} = params) do
    with {:ok, room} <- ClientRooms.readable(principal(conn), ref) do
      respond(conn, ClientSync.history(principal(conn), device(conn), room.id, params))
    else
      _ -> respond(conn, {:error, :forbidden})
    end
  end

  def members(conn, %{"roomId" => ref} = params) do
    with {:ok, room} <- ClientRooms.readable(principal(conn), ref) do
      events =
        ClientSync.state_at(room.id, ClientStore.position())
        |> Enum.filter(&(&1["type"] == "m.room.member"))

      events =
        Enum.filter(events, fn e ->
          (is_nil(params["membership"]) or e["content"]["membership"] == params["membership"]) and
            (is_nil(params["not_membership"]) or
               e["content"]["membership"] != params["not_membership"])
        end)

      json(conn, %{"chunk" => events})
    else
      _ -> respond(conn, {:error, :forbidden})
    end
  end

  def joined_members(conn, %{"roomId" => ref}) do
    with {:ok, room} <- ClientRooms.readable(principal(conn), ref) do
      joined =
        for p <- Memberships.list_members(room.id),
            into: %{},
            do:
              {Identity.user_id(p.username), %{"display_name" => p.username, "avatar_url" => nil}}

      json(conn, %{"joined" => joined})
    else
      _ -> respond(conn, {:error, :forbidden})
    end
  end

  def get_data(conn, %{"userId" => user, "type" => type} = params) do
    if user == Identity.user_id(conn.assigns.username) do
      case ClientStore.get_data(principal(conn), params["roomId"] || "", type) do
        nil -> respond(conn, {:error, :not_found})
        content -> json(conn, content)
      end
    else
      respond(conn, {:error, :forbidden})
    end
  end

  def put_data(conn, %{"userId" => user, "type" => type} = params) do
    room = params["roomId"] || ""

    if user == Identity.user_id(conn.assigns.username) and
         (room == "" or match?({:ok, _}, ClientRooms.readable(principal(conn), room))) and
         byte_size(Jason.encode!(body(conn))) <= 65_536 do
      respond(conn, ClientStore.put_data(principal(conn), room, type, body(conn)))
    else
      respond(conn, {:error, :forbidden})
    end
  end

  def create_filter(conn, %{"userId" => user}) do
    if user == Identity.user_id(conn.assigns.username) and
         byte_size(Jason.encode!(body(conn))) <= 65_536 do
      {1, [row]} =
        Repo.insert_all(
          "matrix_filters",
          [%{principal_id: ClientStore.dump_id(principal(conn)), content: body(conn)}],
          returning: [:id]
        )

      json(conn, %{"filter_id" => to_string(row.id)})
    else
      respond(conn, {:error, :forbidden})
    end
  end

  def get_filter(conn, %{"userId" => user, "filterId" => id}) do
    if user == Identity.user_id(conn.assigns.username),
      do: respond(conn, ClientSync.filter(principal(conn), id)),
      else: respond(conn, {:error, :forbidden})
  end

  def send_to_device(conn, %{"eventType" => type, "txnId" => txn} = params),
    do:
      respond(
        conn,
        ClientStore.send_to_device(
          principal(conn),
          device(conn),
          conn.assigns.username,
          type,
          txn,
          params["messages"]
        )
      )

  def keys_upload(conn, params),
    do:
      respond(
        conn,
        ClientKeys.upload(principal(conn), device(conn), conn.assigns.username, params)
      )

  def keys_query(conn, params),
    do: respond(conn, ClientKeys.query(principal(conn), params["device_keys"]))

  def keys_claim(conn, params),
    do: respond(conn, ClientKeys.claim(principal(conn), params["one_time_keys"]))

  def receipt(conn, %{"roomId" => ref, "receiptType" => type, "eventId" => event}),
    do: respond(conn, ClientRooms.receipt(principal(conn), ref, type, event, body(conn)))

  def read_markers(conn, %{"roomId" => ref} = p) do
    with {:ok, _} <- ClientRooms.readable(principal(conn), ref) do
      for key <- ~w(m.read m.read.private),
          is_binary(p[key]),
          do: ClientRooms.receipt(principal(conn), ref, key, p[key], %{})

      if is_binary(p["m.fully_read"]) do
        case ClientRooms.event(principal(conn), ref, p["m.fully_read"]) do
          {:ok, _} ->
            ClientStore.put_data(principal(conn), ref, "m.fully_read", %{
              "event_id" => p["m.fully_read"]
            })

          _ ->
            :ok
        end
      end

      json(conn, %{})
    else
      _ -> respond(conn, {:error, :forbidden})
    end
  end

  def profile(conn, %{"userId" => user} = p) do
    with {:ok, name} <- Identity.parse_user_id(user),
         {:ok, _} <- LakehouseIam.Accounts.fetch_user(name) do
      fields = %{"displayname" => name, "avatar_url" => nil}
      json(conn, if(p["field"], do: Map.take(fields, [p["field"]]), else: fields))
    else
      _ -> respond(conn, {:error, :not_found})
    end
  end

  def media_config(conn, _), do: json(conn, %{"m.upload.size" => 10 * 1024 * 1024})

  def pushrules(conn, _),
    do: json(conn, %{"global" => Map.new(~w(override content room sender underride), &{&1, []})})

  def unrecognized(conn, _),
    do: error(conn, 404, "M_UNRECOGNIZED", "Unrecognized Matrix endpoint")

  def respond(conn, {:ok, body}), do: json(conn, body)

  def respond(conn, {:error, reason}) do
    {status, code, message} =
      case reason do
        :unsupported_room_version ->
          {400, "M_UNSUPPORTED_ROOM_VERSION", "This room version is not supported"}

        :invalid_credentials ->
          {403, "M_FORBIDDEN", "Invalid username or password"}

        :invalid_cursor ->
          {400, "M_INVALID_PARAM", "Invalid sync or pagination token"}

        :invalid_param ->
          {400, "M_INVALID_PARAM", "Invalid request parameter"}

        :not_found ->
          {404, "M_NOT_FOUND", "Not found"}

        :unknown_pos ->
          {400, "M_UNKNOWN_POS", "Unknown sliding sync position; start a new connection"}

        _ ->
          {403, "M_FORBIDDEN", "This operation is not permitted"}
      end

    error(conn, status, code, message)
  end

  def error(conn, status, code, message),
    do: conn |> put_status(status) |> json(%{"errcode" => code, "error" => message})

  defp principal(conn), do: conn.assigns.principal_id
  defp device(conn), do: conn.assigns.matrix_device_id
  defp body(conn), do: if(is_map(conn.body_params), do: conn.body_params, else: %{})
end
