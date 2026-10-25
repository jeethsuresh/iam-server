defmodule LakehouseWeb.Matrix.FederationController do
  use LakehouseWeb, :controller
  alias LakehouseMatrix.{Federation.Signing, Identity}
  alias LakehouseWeb.Matrix.ProtocolController

  def version(conn, _),
    do: json(conn, %{"server" => %{"name" => "Gravitas", "version" => "0.1.0"}})

  def server_keys(conn, _) do
    case Signing.server_keys() do
      {:ok, keys} ->
        conn |> put_resp_header("cache-control", "public, max-age=3600") |> json(keys)

      _ ->
        ProtocolController.error(
          conn,
          503,
          "M_UNAVAILABLE",
          "Matrix signing key is not configured"
        )
    end
  end

  def query_keys(conn, params) do
    servers = params["server_keys"] || %{}

    wanted =
      params["serverName"] == Identity.homeserver_domain() or
        Map.has_key?(servers, Identity.homeserver_domain())

    case Signing.server_keys() do
      {:ok, keys} ->
        json(conn, %{"server_keys" => if(wanted, do: [keys], else: [])})

      _ ->
        ProtocolController.error(
          conn,
          503,
          "M_UNAVAILABLE",
          "Matrix signing key is not configured"
        )
    end
  end

  def profile(conn, %{"user_id" => user} = params) do
    with {:ok, local} <- Identity.parse_user_id(user),
         {:ok, p} <- LakehouseIam.Accounts.fetch_user(local),
         true <- p.active do
      fields = LakehouseMatrix.ClientProfiles.local(p)
      json(conn, if(params["field"], do: Map.take(fields, [params["field"]]), else: fields))
    else
      _ -> ProtocolController.respond(conn, {:error, :not_found})
    end
  end

  def profile(conn, _), do: ProtocolController.respond(conn, {:error, :invalid_param})

  def openid_userinfo(conn, params),
    do:
      conn
      |> put_resp_header("cache-control", "no-store")
      |> ProtocolController.respond(LakehouseMatrix.OpenId.userinfo(params["access_token"]))

  def directory(conn, %{"room_alias" => ref}),
    do:
      ProtocolController.respond(
        conn,
        LakehouseMatrix.Federation.RoomProtocol.directory(conn.assigns.matrix_origin, ref)
      )

  def directory(conn, _), do: ProtocolController.respond(conn, {:error, :invalid_param})

  def public_rooms(conn, params),
    do:
      ProtocolController.respond(
        conn,
        LakehouseMatrix.Directory.public_rooms(params, conn.assigns.matrix_origin)
      )

  def user_devices(conn, %{"userId" => user}),
    do: ProtocolController.respond(conn, LakehouseMatrix.Federation.DeviceKeys.user_devices(user))

  def keys_query(conn, _),
    do:
      ProtocolController.respond(
        conn,
        LakehouseMatrix.Federation.DeviceKeys.query(conn.body_params["device_keys"])
      )

  def keys_claim(conn, _),
    do:
      ProtocolController.respond(
        conn,
        LakehouseMatrix.Federation.DeviceKeys.claim(conn.body_params["one_time_keys"])
      )

  def make_membership(conn, %{"roomId" => room, "userId" => user} = params) do
    membership = membership_action(conn.request_path)
    versions = repeated_query(conn, "ver", params["ver"] || ["1"])

    ProtocolController.respond(
      conn,
      LakehouseMatrix.Federation.RoomProtocol.make_membership(
        conn.assigns.matrix_origin,
        room,
        user,
        membership,
        versions
      )
    )
  end

  def send_membership(conn, %{"roomId" => room, "eventId" => event}) do
    response =
      LakehouseMatrix.Federation.RoomProtocol.send_membership(
        conn.assigns.matrix_origin,
        room,
        event,
        membership_action(conn.request_path),
        conn.body_params
      )

    case response do
      {:ok, body} ->
        json(
          conn,
          if(
            String.contains?(conn.request_path, "/v1/send_join/") or
              String.contains?(conn.request_path, "/v1/send_leave/"),
            do: [200, body],
            else: body
          )
        )

      error ->
        ProtocolController.respond(conn, error)
    end
  end

  def event(conn, %{"eventId" => id}),
    do:
      ProtocolController.respond(
        conn,
        LakehouseMatrix.Federation.RoomProtocol.event(conn.assigns.matrix_origin, id)
      )

  def space_hierarchy(conn, %{"roomId" => ref} = params),
    do:
      ProtocolController.respond(
        conn,
        LakehouseMatrix.ClientSpaces.federation(conn.assigns.matrix_origin, ref, params)
      )

  def timestamp_to_event(conn, %{"roomId" => ref} = params),
    do:
      ProtocolController.respond(
        conn,
        LakehouseMatrix.EventSearch.federation(conn.assigns.matrix_origin, ref, params)
      )

  def invite(conn, %{"roomId" => room, "eventId" => event}),
    do:
      ProtocolController.respond(
        conn,
        LakehouseMatrix.Federation.Invites.receive(
          conn.assigns.matrix_origin,
          room,
          event,
          conn.body_params
        )
      )

  def room_state(conn, %{"roomId" => room, "event_id" => event}),
    do:
      ProtocolController.respond(
        conn,
        LakehouseMatrix.Federation.RoomProtocol.state(
          conn.assigns.matrix_origin,
          room,
          event,
          String.contains?(conn.request_path, "/state_ids/")
        )
      )

  def room_state(conn, _), do: ProtocolController.respond(conn, {:error, :invalid_param})

  def event_auth(conn, %{"roomId" => room, "eventId" => event}),
    do:
      ProtocolController.respond(
        conn,
        LakehouseMatrix.Federation.RoomProtocol.event_auth(
          conn.assigns.matrix_origin,
          room,
          event
        )
      )

  def backfill(conn, %{"roomId" => room} = params) do
    roots = repeated_query(conn, "v", params["v"] || [])

    result =
      with {:ok, limit} <- LakehouseMatrix.ClientSync.integer(params["limit"], 10, 1, 1000),
           do:
             LakehouseMatrix.Federation.RoomProtocol.backfill(
               conn.assigns.matrix_origin,
               room,
               roots,
               limit
             )

    ProtocolController.respond(conn, result)
  end

  def missing(conn, %{"roomId" => room}),
    do:
      ProtocolController.respond(
        conn,
        LakehouseMatrix.Federation.RoomProtocol.missing(
          conn.assigns.matrix_origin,
          room,
          conn.body_params
        )
      )

  defp membership_action(path) do
    cond do
      String.contains?(path, "_join/") -> "join"
      String.contains?(path, "_leave/") -> "leave"
      String.contains?(path, "_knock/") -> "knock"
    end
  end

  defp repeated_query(conn, name, fallback) do
    values =
      URI.query_decoder(conn.query_string)
      |> Enum.filter(fn {key, _} -> key in [name, name <> "[]"] end)
      |> Enum.map(&elem(&1, 1))

    if values == [], do: List.wrap(fallback), else: values
  end

  def transaction(conn, params) do
    ProtocolController.respond(
      conn,
      LakehouseMatrix.Federation.Transactions.receive(
        conn.assigns.matrix_origin,
        params["txnId"],
        conn.body_params
      )
    )
  end
end
