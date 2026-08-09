defmodule LakehouseWeb.Matrix.ClientController do
  use LakehouseWeb, :controller

  alias LakehouseMatrix.{Identity, Matrix}

  @versions ["v3"]

  def versions(conn, _params) do
    json(conn, %{"versions" => @versions, "unstable_features" => %{}})
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

    body =
      Matrix.sync(
        conn.assigns.principal_id,
        since,
        full_state: full_state
      )

    json(conn, body)
  end

  def create_room(conn, params) do
    case Matrix.create_room(conn.assigns.principal_id, params) do
      {:ok, body} ->
        json(conn, body)

      {:error, :forbidden} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "You are not allowed to create rooms")

      {:error, _} ->
        matrix_error(conn, 400, "M_UNKNOWN", "Could not create room")
    end
  end

  def join_room(conn, %{"roomIdOrAlias" => room_ref}) do
    case Matrix.join_room(conn.assigns.principal_id, room_ref) do
      {:ok, body} ->
        json(conn, body)

      {:error, :room_not_found} ->
        matrix_error(conn, 404, "M_NOT_FOUND", "Room not found")

      {:error, :forbidden} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "You are not allowed to join this room")

      {:error, _} ->
        matrix_error(conn, 400, "M_UNKNOWN", "Could not join room")
    end
  end

  def leave_room(conn, %{"roomId" => room_ref}) do
    case Matrix.leave_room(conn.assigns.principal_id, room_ref) do
      {:ok, body} ->
        json(conn, body)

      {:error, :room_not_found} ->
        matrix_error(conn, 404, "M_NOT_FOUND", "Room not found")

      {:error, _} ->
        matrix_error(conn, 403, "M_FORBIDDEN", "You are not in this room")
    end
  end

  def send_event(conn, %{
        "roomId" => room_ref,
        "eventType" => "m.room.message",
        "txnId" => txn_id
      } = params) do
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
    if Map.has_key?(params, "body") and not Map.has_key?(content, "body") do
      Map.take(params, ["body", "msgtype"])
    else
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
