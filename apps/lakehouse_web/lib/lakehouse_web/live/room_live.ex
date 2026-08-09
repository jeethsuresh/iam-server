defmodule LakehouseWeb.RoomLive do
  use LakehouseWeb, :live_view

  require Logger

  alias LakehouseMatrix.{Events, Identity, Matrix, Memberships, Rooms}

  @impl true
  def mount(_params, _session, socket) do
    principal_id = socket.assigns.principal_id

    {:ok,
     socket
     |> assign(:rooms, Rooms.list_rooms_for(principal_id))
     |> assign(:room, nil)
     |> assign(:members, [])
     |> assign(:messages, [])
     |> assign(:composer, "")}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    {:noreply, apply_room_param(socket, params["id"])}
  end

  @impl true
  def handle_event("create_room", params, socket) do
    name = params |> Map.get("name", "") |> String.trim() |> blank_to_default("Room")

    case Matrix.create_room(socket.assigns.principal_id, %{"name" => name}) do
      {:ok, %{"room_id" => matrix_room_id}} ->
        {:ok, room_uuid} = Identity.parse_room_id(matrix_room_id)

        {:noreply,
         socket
         |> assign(:rooms, Rooms.list_rooms_for(socket.assigns.principal_id))
         |> push_patch(to: ~p"/rooms/#{room_uuid}")}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Could not create room.")}
    end
  end

  def handle_event("update_composer", %{"body" => body}, socket) do
    {:noreply, assign(socket, :composer, body)}
  end

  def handle_event("send_message", params, socket) do
    body =
      params
      |> Map.get("body", socket.assigns.composer)
      |> to_string()
      |> String.trim()

    socket =
      if body != "" and socket.assigns.room do
        txn = "lv-#{System.unique_integer([:positive])}"

        Logger.info(
          "room_live.send_message user=#{socket.assigns.username} room=#{socket.assigns.room.id} txn=#{txn}"
        )

        case Matrix.send_message(
               socket.assigns.principal_id,
               socket.assigns.room.id,
               txn,
               %{"body" => body, "msgtype" => "m.text"}
             ) do
          {:ok, event} ->
            socket
            |> append_message(event)
            |> assign(:composer, "")

          {:error, :not_member} ->
            put_flash(socket, :error, "You are not a member of this room.")

          {:error, :no_send_permission} ->
            put_flash(socket, :error, "Your account cannot send messages yet. Contact an admin.")

          {:error, reason} ->
            Logger.warning(
              "room_live.send_message failed user=#{socket.assigns.username} reason=#{inspect(reason)}"
            )

            put_flash(socket, :error, "Could not send message.")
        end
      else
        if body == "" do
          Logger.debug(
            "room_live.send_message skipped empty body user=#{socket.assigns.username}"
          )
        end

        socket
      end

    {:noreply, socket}
  end

  def handle_event("add_member", %{"username" => username}, socket) do
    username = String.trim(username)

    socket =
      if socket.assigns.room && username != "" do
        case Matrix.add_member(socket.assigns.room.id, socket.assigns.principal_id, username) do
          {:ok, _} ->
            socket
            |> assign(:members, Memberships.list_members(socket.assigns.room.id))
            |> put_flash(:info, "Added #{username} to the room.")

          {:error, :user_not_found} ->
            put_flash(socket, :error, "No active user named #{username}.")

          {:error, :already_member} ->
            put_flash(socket, :error, "#{username} is already in this room.")

          {:error, :inactive} ->
            put_flash(socket, :error, "#{username} is not an active user yet.")

          {:error, _} ->
            put_flash(socket, :error, "Could not add #{username} to the room.")
        end
      else
        socket
      end

    {:noreply, socket}
  end

  def handle_event("leave_room", _params, socket) do
    if socket.assigns.room do
      _ =
        Matrix.leave_room(
          socket.assigns.principal_id,
          Identity.room_id(socket.assigns.room.id)
        )

      {:noreply,
       socket
       |> assign(:rooms, Rooms.list_rooms_for(socket.assigns.principal_id))
       |> assign(room: nil, members: [], messages: [])
       |> push_patch(to: ~p"/rooms")}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:room_event, room_id, msg}, socket) do
    socket =
      if socket.assigns.room && socket.assigns.room.id == room_id do
        case msg["type"] do
          "m.room.message" ->
            append_message(socket, msg)

          "m.room.member" ->
            if Map.get(msg["content"], "membership") == "join" do
              assign(socket, :members, Memberships.list_members(room_id))
            else
              assign(socket, :members, Memberships.list_members(room_id))
            end

          _ ->
            socket
        end
      else
        socket
      end

    {:noreply, socket}
  end

  defp apply_room_param(socket, nil) do
    unsubscribe_room(socket)
    assign(socket, room: nil, members: [], messages: [])
  end

  defp apply_room_param(socket, room_id) do
    principal_id = socket.assigns.principal_id

    case Rooms.get_room(room_id) do
      nil ->
        socket
        |> unsubscribe_room()
        |> assign(room: nil, members: [], messages: [])
        |> put_flash(:error, "Room not found.")
        |> push_patch(to: ~p"/rooms")

      room ->
        if Memberships.joined?(room.id, principal_id) do
          unsubscribe_room(socket)

          if connected?(socket) do
            Phoenix.PubSub.subscribe(LakehouseWeb.PubSub, topic(room.id))
          end

          _ = Rooms.ensure_started(room.id)

          socket
          |> assign(:rooms, Rooms.list_rooms_for(principal_id))
          |> assign(:room, room)
          |> assign(:members, Memberships.list_members(room.id))
          |> assign(:messages, Events.list_timeline(room.id, limit: 100))
        else
          socket
          |> unsubscribe_room()
          |> assign(room: nil, members: [], messages: [])
          |> put_flash(:error, "You are not a member of this room.")
          |> push_patch(to: ~p"/rooms")
        end
    end
  end

  defp append_message(socket, msg) do
    if message_seen?(socket.assigns.messages, msg) do
      socket
    else
      update(socket, :messages, &(&1 ++ [msg]))
    end
  end

  defp message_seen?(messages, %{"event_id" => id}) do
    Enum.any?(messages, &(&1["event_id"] == id))
  end

  defp message_seen?(_, _), do: false

  defp unsubscribe_room(socket) do
    if connected?(socket) and socket.assigns[:room] do
      Phoenix.PubSub.unsubscribe(LakehouseWeb.PubSub, topic(socket.assigns.room.id))
    end

    socket
  end

  defp topic(room_id), do: "room:#{room_id}"

  defp blank_to_default("", default), do: default
  defp blank_to_default(value, _default), do: value

  def format_ts(ts) when is_integer(ts) do
    ts
    |> DateTime.from_unix!(:millisecond)
    |> Calendar.strftime("%H:%M")
  end

  def format_ts(_), do: ""

  def sender_label(%{"sender" => "@" <> rest}) do
    rest |> String.split(":", parts: 2) |> List.first() || rest
  end

  def sender_label(%{"sender" => sender}), do: sender
  def sender_label(_), do: ""

  def message_body(%{"content" => %{"body" => body}}), do: body
  def message_body(_), do: ""
end
