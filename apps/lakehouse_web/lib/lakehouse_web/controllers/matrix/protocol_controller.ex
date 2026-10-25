defmodule LakehouseWeb.Matrix.ProtocolController do
  use LakehouseWeb, :controller
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientKeys, ClientRooms, ClientStore, ClientSync, Identity, Memberships}

  def resolve_alias(conn, %{"roomAlias" => ref}),
    do: respond(conn, LakehouseMatrix.Directory.resolve(ref))

  def set_alias(conn, %{"roomAlias" => ref} = params),
    do: respond(conn, LakehouseMatrix.Directory.put(principal(conn), ref, params["room_id"]))

  def delete_alias(conn, %{"roomAlias" => ref}),
    do: respond(conn, LakehouseMatrix.Directory.delete(principal(conn), ref))

  def local_aliases(conn, %{"roomId" => ref}),
    do: respond(conn, LakehouseMatrix.Directory.aliases(principal(conn), ref))

  def directory_visibility(conn, %{"roomId" => ref}),
    do: respond(conn, LakehouseMatrix.Directory.visibility(ref))

  def set_directory_visibility(conn, %{"roomId" => ref} = params),
    do:
      respond(
        conn,
        LakehouseMatrix.Directory.visibility(
          principal(conn),
          ref,
          params["visibility"] || "public"
        )
      )

  def public_rooms(conn, params),
    do: respond(conn, LakehouseMatrix.Directory.client_public_rooms(params))

  def room_summary(conn, %{"roomIdOrAlias" => ref}),
    do: respond(conn, LakehouseMatrix.ClientSpaces.summary(principal(conn), ref, via(conn)))

  def space_hierarchy(conn, %{"roomId" => ref} = params),
    do:
      respond(
        conn,
        LakehouseMatrix.ClientSpaces.hierarchy(
          principal(conn),
          device(conn),
          ref,
          params,
          via(conn)
        )
      )

  def moderate(conn, %{"roomId" => ref} = params) do
    action = conn.request_path |> String.split("/") |> List.last()

    respond(
      conn,
      ClientRooms.moderate(principal(conn), ref, action, params["user_id"], params["reason"])
    )
  end

  def create_room(conn, params), do: respond(conn, ClientRooms.create(principal(conn), params))

  def upgrade_room(conn, %{"roomId" => ref} = params),
    do: respond(conn, LakehouseMatrix.RoomUpgrades.upgrade(principal(conn), ref, params))

  def login_flows(conn, _),
    do:
      json(conn, %{
        "flows" => [
          %{"type" => "m.login.password"},
          %{"type" => "m.login.token", "get_login_token" => true},
          %{
            "type" => "m.login.sso",
            "identity_providers" => [%{"id" => "gravitas", "name" => "Gravitas"}]
          }
        ]
      })

  def login(conn, params) do
    conn = put_resp_header(conn, "cache-control", "no-store")
    identifier = if is_map(params["identifier"]), do: params["identifier"], else: %{}
    user = identifier["user"] || params["user"]

    cond do
      params["type"] == "m.login.token" ->
        respond(conn, LakehouseMatrix.ClientLogin.redeem(params["token"], params))

      params["type"] in [nil, "m.login.password"] and identifier["type"] in [nil, "m.id.user"] and
        is_binary(user) and is_binary(params["password"]) ->
        respond(conn, ClientStore.login(user, params["password"], params))

      true ->
        error(
          conn,
          400,
          "M_INVALID_PARAM",
          "A supported login type, user and password are required"
        )
    end
  end

  def refresh(conn, params),
    do:
      conn
      |> put_resp_header("cache-control", "no-store")
      |> respond(LakehouseMatrix.ClientLogin.refresh(params["refresh_token"]))

  def login_token(conn, _) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> respond(
      LakehouseMatrix.ClientUia.perform(
        principal(conn),
        device(conn),
        "login_token",
        body(conn),
        fn -> LakehouseMatrix.ClientLogin.generate(principal(conn), true, device(conn)) end
      )
    )
  end

  def typing(conn, %{"roomId" => room, "userId" => user} = params),
    do: respond(conn, LakehouseMatrix.Ephemeral.typing(principal(conn), room, user, params))

  def presence(conn, %{"userId" => user} = params) do
    result =
      cond do
        conn.method == "GET" ->
          LakehouseMatrix.Ephemeral.get_presence(principal(conn), user)

        user == Identity.user_id(conn.assigns.username) ->
          LakehouseMatrix.Ephemeral.set_presence(principal(conn), params)

        true ->
          {:error, :forbidden}
      end

    respond(conn, result)
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

  def delete_device(conn, %{"device" => target}), do: delete_devices(conn, [target])

  def delete_devices(conn, %{"devices" => devices}) when is_list(devices),
    do: delete_devices(conn, devices)

  def delete_devices(conn, devices) when is_list(devices) do
    respond(
      conn,
      LakehouseMatrix.ClientUia.perform(
        principal(conn),
        device(conn),
        "delete_devices:" <> Jason.encode!(devices),
        body(conn),
        fn -> ClientStore.delete_devices(principal(conn), devices) end
      )
    )
  end

  def delete_devices(conn, _), do: respond(conn, {:error, :invalid_param})

  def cross_signing_upload(conn, _) do
    result = LakehouseMatrix.CrossSigning.upload(principal(conn), body(conn))

    result =
      if result == {:error, :reauth_required} do
        LakehouseMatrix.ClientUia.perform(
          principal(conn),
          device(conn),
          "cross_signing",
          body(conn),
          fn -> LakehouseMatrix.CrossSigning.upload(principal(conn), body(conn), true) end
        )
      else
        result
      end

    respond(conn, result)
  end

  def signatures_upload(conn, _),
    do: respond(conn, LakehouseMatrix.CrossSigning.signatures(principal(conn), body(conn)))

  def key_changes(conn, %{"from" => lower, "to" => upper}) do
    with {:ok, low} <-
           LakehouseMatrix.Cursor.decode(lower, "sync", principal(conn), device(conn)),
         {:ok, high} <-
           LakehouseMatrix.Cursor.decode(upper, "sync", principal(conn), device(conn)),
         true <- low <= high and high <= ClientStore.position(),
         do: respond(conn, {:ok, ClientSync.device_lists(principal(conn), low, high)}),
         else: (_ -> respond(conn, {:error, :invalid_param}))
  end

  def key_changes(conn, _), do: respond(conn, {:error, :invalid_param})

  def backup_version(conn, params) do
    alias LakehouseMatrix.KeyBackups

    result =
      case conn.method do
        "GET" -> KeyBackups.version(principal(conn), params["version"])
        "POST" -> KeyBackups.create(principal(conn), body(conn))
        "PUT" -> KeyBackups.update(principal(conn), params["version"], body(conn))
        "DELETE" -> KeyBackups.delete_version(principal(conn), params["version"])
      end

    respond(conn, result)
  end

  def backup_keys(conn, %{"version" => version} = params) when is_binary(version) do
    alias LakehouseMatrix.KeyBackups
    room = params["roomId"]
    session = params["sessionId"]

    result =
      case conn.method do
        "GET" -> KeyBackups.get(principal(conn), version, room, session)
        "PUT" -> KeyBackups.put(principal(conn), version, body(conn), room, session)
        "DELETE" -> KeyBackups.delete(principal(conn), version, room, session)
      end

    respond(conn, result)
  end

  def backup_keys(conn, _), do: respond(conn, {:error, :invalid_param})

  def capabilities(conn, _),
    do:
      json(conn, %{
        "capabilities" => %{
          "m.room_versions" => %{
            "default" => if(LakehouseMatrix.Protocol.Rooms.enabled?(), do: "12", else: "11"),
            "available" =>
              if(LakehouseMatrix.Protocol.Rooms.enabled?(),
                do: %{"11" => "stable", "12" => "stable"},
                else: %{"11" => "stable"}
              )
          },
          "m.change_password" => %{"enabled" => false},
          "m.get_login_token" => %{"enabled" => true},
          "m.set_displayname" => %{"enabled" => true},
          "m.set_avatar_url" => %{"enabled" => true},
          "m.3pid_changes" => %{"enabled" => false}
        }
      })

  def knock(conn, %{"roomIdOrAlias" => ref} = params) do
    peers =
      URI.query_decoder(conn.query_string)
      |> Enum.filter(fn {key, _} -> key in ["via", "via[]", "server_name", "server_name[]"] end)
      |> Enum.map(&elem(&1, 1))

    respond(conn, ClientRooms.knock(principal(conn), ref, peers, params))
  end

  def forget(conn, %{"roomId" => ref}),
    do: respond(conn, ClientRooms.forget(principal(conn), ref))

  def joined_rooms(conn, _),
    do:
      json(conn, %{
        "joined_rooms" =>
          Enum.map(Memberships.joined_room_ids(principal(conn)), &Identity.room_id/1)
      })

  def get_state(conn, %{"roomId" => ref} = params) do
    with {:ok, room, boundary} <- ClientRooms.history_access(principal(conn), ref) do
      events = ClientSync.state_at(room.id, boundary)

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

  def relations(conn, %{"roomId" => ref, "eventId" => event} = params),
    do:
      respond(
        conn,
        LakehouseMatrix.ClientRelations.page(principal(conn), device(conn), ref, event, params)
      )

  def threads(conn, %{"roomId" => ref} = params),
    do:
      respond(
        conn,
        LakehouseMatrix.ClientRelations.threads(principal(conn), device(conn), ref, params)
      )

  def timestamp_to_event(conn, %{"roomId" => ref} = params),
    do: respond(conn, LakehouseMatrix.EventSearch.timestamp(principal(conn), ref, params))

  def messages(conn, %{"roomId" => ref} = params) do
    with {:ok, room, _} <- ClientRooms.history_access(principal(conn), ref) do
      respond(conn, ClientSync.history(principal(conn), device(conn), room.id, params))
    else
      _ -> respond(conn, {:error, :forbidden})
    end
  end

  def members(conn, %{"roomId" => ref} = params),
    do:
      respond(
        conn,
        LakehouseMatrix.ClientContext.members(principal(conn), device(conn), ref, params)
      )

  def context(conn, %{"roomId" => ref, "eventId" => id} = params),
    do:
      respond(
        conn,
        LakehouseMatrix.ClientContext.context(principal(conn), device(conn), ref, id, params)
      )

  def joined_members(conn, %{"roomId" => ref}) do
    with {:ok, room} <- ClientRooms.readable(principal(conn), ref) do
      joined =
        for p <- Memberships.list_members(room.id),
            into: %{},
            do:
              {Map.get(p, :user_id) || Identity.user_id(p.username),
               %{
                 "display_name" => Map.get(p, :display_name, p.username),
                 "avatar_url" => Map.get(p, :avatar_url)
               }}

      json(conn, %{"joined" => joined})
    else
      _ -> respond(conn, {:error, :forbidden})
    end
  end

  def get_data(conn, %{"userId" => user, "type" => type} = params) do
    if user == Identity.user_id(conn.assigns.username) do
      data =
        if type == "m.push_rules" and is_nil(params["roomId"]),
          do: LakehouseMatrix.PushRules.get(principal(conn)),
          else: ClientStore.get_data(principal(conn), params["roomId"] || "", type)

      case data do
        nil -> respond(conn, {:error, :not_found})
        content -> json(conn, content)
      end
    else
      respond(conn, {:error, :forbidden})
    end
  end

  def put_data(conn, %{"userId" => user, "type" => type} = params) do
    room = params["roomId"] || ""

    if type != "m.push_rules" and user == Identity.user_id(conn.assigns.username) and
         (room == "" or match?({:ok, _}, ClientRooms.readable(principal(conn), room))) and
         byte_size(Jason.encode!(body(conn))) <= 65_536 do
      respond(conn, ClientStore.put_data(principal(conn), room, type, body(conn)))
    else
      respond(conn, {:error, :forbidden})
    end
  end

  def create_filter(conn, %{"userId" => user}) do
    cond do
      user != Identity.user_id(conn.assigns.username) ->
        respond(conn, {:error, :forbidden})

      byte_size(Jason.encode!(body(conn))) > 65_536 ->
        respond(conn, {:error, :invalid_param})

      not match?({:ok, _}, ClientSync.validate_filter(body(conn))) ->
        respond(conn, {:error, :invalid_param})

      true ->
        {1, [row]} =
          Repo.insert_all(
            "matrix_filters",
            [%{principal_id: ClientStore.dump_id(principal(conn)), content: body(conn)}],
            returning: [:id]
          )

        json(conn, %{"filter_id" => to_string(row.id)})
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

  def profile(conn, %{"userId" => user} = params) do
    case LakehouseMatrix.ClientProfiles.get(user) do
      {:ok, profile} ->
        json(conn, if(params["field"], do: Map.take(profile, [params["field"]]), else: profile))

      error ->
        respond(conn, error)
    end
  end

  def set_profile(conn, %{"userId" => user, "field" => field} = params),
    do:
      respond(
        conn,
        LakehouseMatrix.ClientProfiles.put(principal(conn), user, field, params[field])
      )

  def user_directory(conn, params),
    do: respond(conn, LakehouseMatrix.ClientProfiles.search(principal(conn), params))

  def media_config(conn, _), do: json(conn, %{"m.upload.size" => 10 * 1024 * 1024})

  def pushrules(conn, params) do
    result =
      cond do
        params["scope"] not in [nil, "global"] ->
          {:error, :not_found}

        is_nil(params["kind"]) ->
          {:ok, LakehouseMatrix.PushRules.get(principal(conn))}

        conn.method == "GET" ->
          LakehouseMatrix.PushRules.fetch(
            principal(conn),
            params["kind"],
            params["ruleId"],
            params["field"]
          )

        true ->
          LakehouseMatrix.PushRules.mutate(
            principal(conn),
            params["kind"],
            params["ruleId"],
            conn.method,
            Map.merge(body(conn), Map.take(conn.query_params, ~w(before after))),
            params["field"]
          )
      end

    respond(conn, result)
  end

  def notifications(conn, params),
    do: respond(conn, LakehouseMatrix.Notifications.page(principal(conn), device(conn), params))

  def pushers(conn, params),
    do:
      respond(
        conn,
        if(conn.method == "GET",
          do: {:ok, LakehouseMatrix.Pushers.list(principal(conn))},
          else: LakehouseMatrix.Pushers.set(principal(conn), device(conn), params)
        )
      )

  def unrecognized(conn, _),
    do: error(conn, 404, "M_UNRECOGNIZED", "Unrecognized Matrix endpoint")

  def respond(conn, {:ok, body}), do: json(conn, body)

  def respond(conn, {:error, {:policy_error, status, body}}),
    do: conn |> put_status(status) |> json(body)

  def respond(conn, {:error, {:uia, body}}), do: conn |> put_status(401) |> json(body)

  def respond(conn, {:error, :unknown_token}),
    do:
      conn
      |> put_status(401)
      |> json(%{
        "errcode" => "M_UNKNOWN_TOKEN",
        "error" => "Unknown refresh token",
        "soft_logout" => true
      })

  def respond(conn, {:error, :rate_limited}),
    do:
      conn
      |> put_status(429)
      |> put_resp_header("retry-after", "60")
      |> json(%{
        "errcode" => "M_LIMIT_EXCEEDED",
        "error" => "Please wait before requesting another login token",
        "retry_after_ms" => 60_000
      })

  def respond(conn, {:error, {:wrong_backup_version, version}}),
    do:
      conn
      |> put_status(403)
      |> json(%{
        "errcode" => "M_WRONG_ROOM_KEYS_VERSION",
        "error" => "Wrong backup version",
        "current_version" => version
      })

  def respond(conn, {:error, {:incompatible_room_version, version}}),
    do:
      conn
      |> put_status(400)
      |> json(%{
        "errcode" => "M_INCOMPATIBLE_ROOM_VERSION",
        "error" => "No compatible room version",
        "room_version" => version
      })

  def respond(conn, {:error, reason}) do
    {status, code, message} =
      case reason do
        :policy_unavailable ->
          {503, "M_UNAVAILABLE", "The room policy server did not provide a valid signature"}

        :unsupported_room_version ->
          {400, "M_UNSUPPORTED_ROOM_VERSION", "This room version is not supported"}

        :already_upgraded ->
          {400, "M_BAD_STATE", "This room already has a replacement in a different version"}

        :unable_to_authorise_join ->
          {403, "M_UNABLE_TO_AUTHORISE_JOIN", "This server cannot authorize the restricted join"}

        :invalid_credentials ->
          {403, "M_FORBIDDEN", "Invalid username or password"}

        :invalid_cursor ->
          {400, "M_INVALID_PARAM", "Invalid sync or pagination token"}

        :invalid_param ->
          {400, "M_INVALID_PARAM", "Invalid request parameter"}

        :duplicate_annotation ->
          {400, "M_DUPLICATE_ANNOTATION", "An identical annotation already exists"}

        :limit_exceeded ->
          {413, "M_TOO_LARGE", "Request exceeds the server limit"}

        :alias_in_use ->
          {409, "M_UNKNOWN", "This room alias already exists"}

        :unavailable ->
          {502, "M_UNAVAILABLE", "The remote server is unavailable"}

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

  defp via(conn),
    do:
      URI.query_decoder(conn.query_string)
      |> Enum.filter(fn {key, _} -> key in ["via", "via[]"] end)
      |> Enum.map(&elem(&1, 1))
      |> Enum.take(10)

  defp device(conn), do: conn.assigns.matrix_device_id
  defp body(conn), do: if(is_map(conn.body_params), do: conn.body_params, else: %{})
end
