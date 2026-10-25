defmodule LakehouseWeb.Matrix.ClientController do
  use LakehouseWeb, :controller

  alias LakehouseMatrix.{Identity, Matrix}

  # API path versions (v3) are distinct from specification versions. The older
  # local-only backend retains its baseline; the signed graph uses the audited API.
  @native_versions Enum.map(1..19, &"v1.#{&1}")

  def versions(conn, _params) do
    versions = if LakehouseMatrix.Protocol.Rooms.enabled?(), do: @native_versions, else: ["v1.1"]

    json(conn, %{
      "versions" => versions,
      "unstable_features" => %{
        "org.matrix.msc4186" => true,
        "org.matrix.simplified_msc3575" => true
      }
    })
  end

  def login(conn, params) do
    type = Map.get(params, "type", "m.login.password")

    if type != "m.login.password" do
      matrix_error(conn, 400, "M_INVALID_PARAM", "Only m.login.password is supported")
    else
      {username, password} = extract_credentials(params)

      case Matrix.login(username, password) do
        {:ok, session} ->
          json(conn, session)

        {:error, :inactive} ->
          matrix_error(conn, 403, "M_USER_DEACTIVATED", "Account is not active")

        {:error, :invalid_credentials} ->
          matrix_error(conn, 403, "M_FORBIDDEN", "Invalid username or password")
      end
    end
  end

  def sync(conn, params) do
    since = Map.get(params, "since")
    full_state = Map.get(params, "full_state", "false") in ["true", true]
    timeout = params |> Map.get("timeout", "0") |> parse_int(0)

    body =
      Matrix.sync(
        conn.assigns.principal_id,
        since,
        full_state: full_state,
        timeout: timeout
      )

    json(conn, body)
  end

  def invite(conn, %{"id_server" => _, "medium" => _, "address" => _}),
    do:
      matrix_error(conn, 403, "M_FORBIDDEN", "Invitations through identity services are disabled")

  def invite(conn, %{"roomId" => room_ref} = params) do
    user =
      Map.get(params, "user_id") ||
        get_in(params, ["user"]) ||
        ""

    username =
      case Identity.parse_user_id(user) do
        {:ok, name} -> name
        :error -> to_string(user)
      end

    case Matrix.invite(conn.assigns.principal_id, room_ref, username) do
      {:ok, body} ->
        json(conn, body)

      {:error, :room_not_found} ->
        matrix_error(conn, 404, "M_NOT_FOUND", "Room not found")

      {:error, :user_not_found} ->
        matrix_error(conn, 404, "M_NOT_FOUND", "User not found")

      {:error, :already_member} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "User is already in the room")

      {:error, :already_invited} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "User is already invited")

      {:error, :forbidden} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "You cannot invite to this room")

      {:error, :invite_blocked} ->
        LakehouseWeb.Matrix.ProtocolController.respond(conn, {:error, :invite_blocked})

      {:error, _} ->
        matrix_error(conn, 400, "M_UNKNOWN", "Could not invite user")
    end
  end

  def create_room(conn, params) do
    case Matrix.create_room(conn.assigns.principal_id, params) do
      {:ok, body} ->
        json(conn, body)

      {:error, :invite_blocked} ->
        LakehouseWeb.Matrix.ProtocolController.respond(conn, {:error, :invite_blocked})

      {:error, :forbidden} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "You are not allowed to create rooms")

      {:error, _} ->
        matrix_error(conn, 400, "M_UNKNOWN", "Could not create room")
    end
  end

  def join_room_id(conn, %{"roomId" => id}), do: join_room(conn, %{"roomIdOrAlias" => id})

  def join_room(conn, %{"roomIdOrAlias" => room_ref}) do
    servers =
      URI.query_decoder(conn.query_string)
      |> Enum.filter(fn {key, _} -> key in ["via", "via[]", "server_name", "server_name[]"] end)
      |> Enum.map(&elem(&1, 1))

    case Matrix.join_room(conn.assigns.principal_id, room_ref, servers, conn.body_params) do
      {:ok, body} ->
        json(conn, body)

      {:error, :room_not_found} ->
        matrix_error(conn, 404, "M_NOT_FOUND", "Room not found")

      {:error, :forbidden} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "You are not allowed to join this room")

      {:error, {:policy_error, _, _}} = error ->
        LakehouseWeb.Matrix.ProtocolController.respond(conn, error)

      {:error, :policy_unavailable} = error ->
        LakehouseWeb.Matrix.ProtocolController.respond(conn, error)

      {:error, _} ->
        matrix_error(conn, 400, "M_UNKNOWN", "Could not join room")
    end
  end

  def leave_room(conn, %{"roomId" => room_ref}) do
    case Matrix.leave_room(conn.assigns.principal_id, room_ref, conn.body_params) do
      {:ok, body} ->
        json(conn, body)

      {:error, :room_not_found} ->
        matrix_error(conn, 404, "M_NOT_FOUND", "Room not found")

      {:error, :unavailable} ->
        matrix_error(conn, 503, "M_UNAVAILABLE", "The resident server is unavailable; try again")

      {:error, _} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "You are not in this room")
    end
  end

  def send_event(
        conn,
        %{
          "roomId" => room_ref,
          "eventType" => "m.room.message",
          "txnId" => txn_id
        } = params
      ) do
    with {:ok, room_uuid} <- Identity.parse_room_id(room_ref) do
      content =
        params
        |> Map.get("content", %{})
        |> event_content(params)

      case Matrix.send_message(conn.assigns.principal_id, room_uuid, txn_id, content) do
        {:ok, event} ->
          json(conn, %{"event_id" => event["event_id"]})

        {:error, :empty_message} ->
          matrix_error(conn, 400, "M_INVALID_PARAM", "Message body is required")

        {:error, _} ->
          matrix_error(conn, 403, "M_FORBIDDEN", "Cannot send to this room")
      end
    else
      :error ->
        matrix_error(conn, 404, "M_NOT_FOUND", "Room not found")
    end
  end

  def send_event(conn, %{"eventType" => event_type}) do
    matrix_error(conn, 400, "M_UNKNOWN", "Unsupported event type: #{event_type}")
  end

  def put_state(conn, %{"roomId" => room_ref, "eventType" => "m.room.name"} = params) do
    name =
      params
      |> Map.get("content", params)
      |> Map.get("name", "")
      |> to_string()

    case Matrix.set_name(conn.assigns.principal_id, room_ref, name) do
      {:ok, event} ->
        json(conn, %{"event_id" => event["event_id"]})

      {:error, :not_member} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "Not a room member")

      {:error, :invalid_name} ->
        matrix_error(conn, 400, "M_INVALID_PARAM", "Name is required")

      {:error, _} ->
        matrix_error(conn, 400, "M_UNKNOWN", "Could not set room name")
    end
  end

  def put_state(conn, %{"roomId" => room_ref, "eventType" => "m.room.avatar"} = params) do
    content = Map.get(params, "content", params)
    url = Map.get(content, "url", "") |> to_string()
    info = Map.get(content, "info", %{})

    case Matrix.set_avatar(conn.assigns.principal_id, room_ref, url, info) do
      {:ok, event} ->
        json(conn, %{"event_id" => event["event_id"]})

      {:error, :not_member} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "Not a room member")

      {:error, _} ->
        matrix_error(conn, 400, "M_UNKNOWN", "Could not set room avatar")
    end
  end

  def put_state(conn, %{"eventType" => event_type}) do
    matrix_error(conn, 400, "M_UNKNOWN", "Unsupported state event: #{event_type}")
  end

  def kick(conn, %{"roomId" => room_ref} = params) do
    user = Map.get(params, "user_id") || ""

    username =
      case Identity.parse_user_id(user) do
        {:ok, name} -> name
        :error -> to_string(user)
      end

    case Matrix.remove_member(conn.assigns.principal_id, room_ref, username) do
      {:ok, event} ->
        json(conn, %{"event_id" => event["event_id"]})

      {:error, :forbidden} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "Only the room creator can remove members")

      {:error, :cannot_remove_self} ->
        matrix_error(conn, 400, "M_BAD_STATE", "Use leave to leave the room")

      {:error, :not_member} ->
        matrix_error(conn, 404, "M_NOT_FOUND", "User is not in the room")

      {:error, :user_not_found} ->
        matrix_error(conn, 404, "M_NOT_FOUND", "User not found")

      {:error, _} ->
        matrix_error(conn, 400, "M_UNKNOWN", "Could not remove member")
    end
  end

  def messages(conn, %{"roomId" => room_ref} = params) do
    limit = params |> Map.get("limit", "50") |> parse_int(50)

    with {:ok, room_uuid} <- Identity.parse_room_id(room_ref) do
      case Matrix.room_messages(conn.assigns.principal_id, room_uuid, limit: limit) do
        %{"errcode" => _} = err ->
          status = if err["errcode"] == "M_FORBIDDEN", do: 403, else: 400
          conn |> put_status(status) |> json(err)

        body ->
          json(conn, body)
      end
    else
      :error ->
        matrix_error(conn, 404, "M_NOT_FOUND", "Room not found")
    end
  end

  defp extract_credentials(params) do
    identifier = Map.get(params, "identifier", %{})
    user = Map.get(identifier, "user") || Map.get(params, "user") || ""
    password = Map.get(params, "password", "")
    {user, password}
  end

  defp event_content(content, params) when is_map(content) do
    cond do
      map_size(content) > 0 ->
        content

      Map.has_key?(params, "body") ->
        Map.take(params, ["body", "msgtype", "url", "info", "filename"])

      true ->
        content
    end
  end

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> n
      :error -> default
    end
  end

  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(_, default), do: default

  defp matrix_error(conn, status, errcode, error) do
    conn
    |> put_status(status)
    |> json(%{"errcode" => errcode, "error" => error})
  end
end
