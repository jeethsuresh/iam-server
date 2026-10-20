defmodule LakehouseWeb.RoomLive do
  use LakehouseWeb, :live_view

  require Logger

  alias LakehouseMatrix.{Events, Identity, Matrix, Media, Memberships, RoomServer, Rooms}
  alias LakehouseWeb.TypingLabel

  @typing_refresh_ms 1_500
  @typing_idle_ms 2_000

  @doc false
  def typing_idle_ms, do: @typing_idle_ms

  @impl true
  def mount(_params, _session, socket) do
    principal_id = socket.assigns.principal_id

    socket =
      socket
      |> assign(:rooms, Rooms.list_rooms_for(principal_id))
      |> assign(:room, nil)
      |> assign(:members, [])
      |> assign(:messages, [])
      |> assign(:composer, "")
      |> assign(:info_open?, false)
      |> assign(:is_creator?, false)
      |> assign(:room_files, [])
      |> assign(:name_draft, "")
      |> assign(:typing_users, [])
      |> assign(:typing_label, nil)
      |> assign(:typing_sent_at, 0)
      |> assign(:i_am_typing?, false)
      |> assign(:typing_idle_token, 0)
      |> allow_upload(:chat_file,
        accept: :any,
        max_entries: 1,
        max_file_size: 10_000_000,
        auto_upload: true,
        progress: &handle_chat_progress/3
      )
      |> allow_upload(:room_avatar,
        accept: ~w(.jpg .jpeg .png .gif .webp),
        max_entries: 1,
        max_file_size: 10_000_000,
        auto_upload: true,
        progress: &handle_avatar_progress/3
      )

    {:ok, socket}
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
         |> push_patch(to: ~p"/groups/#{room_uuid}")}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Could not create room.")}
    end
  end

  def handle_event("toggle_info", _params, socket) do
    {:noreply, assign(socket, :info_open?, !socket.assigns.info_open?)}
  end

  def handle_event("close_info", _params, socket) do
    {:noreply, assign(socket, :info_open?, false)}
  end

  def handle_event("update_name_draft", %{"name" => name}, socket) do
    {:noreply, assign(socket, :name_draft, name)}
  end

  def handle_event("save_room_name", %{"name" => name}, socket) do
    name = String.trim(name)

    socket =
      if socket.assigns.room && name != "" do
        case Matrix.set_name(socket.assigns.principal_id, socket.assigns.room.id, name) do
          {:ok, _} ->
            room = Rooms.get_room(socket.assigns.room.id)

            socket
            |> assign(:room, room)
            |> assign(:name_draft, room.name)
            |> assign(:rooms, Rooms.list_rooms_for(socket.assigns.principal_id))
            |> put_flash(:info, "Room name updated.")

          {:error, _} ->
            put_flash(socket, :error, "Could not update room name.")
        end
      else
        socket
      end

    {:noreply, socket}
  end

  def handle_event("update_composer", %{"body" => body}, socket) do
    {:noreply, socket |> assign(:composer, body) |> sync_typing_state(body)}
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

        case Matrix.send_message(
               socket.assigns.principal_id,
               socket.assigns.room.id,
               txn,
               %{"body" => body, "msgtype" => "m.text"}
             ) do
          {:ok, event} ->
            socket
            |> clear_local_typing()
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

          {:error, :forbidden} ->
            put_flash(socket, :error, "Only the room creator can add members.")

          {:error, _} ->
            put_flash(socket, :error, "Could not add #{username} to the room.")
        end
      else
        socket
      end

    {:noreply, socket}
  end

  def handle_event("remove_member", %{"username" => username}, socket) do
    socket =
      if socket.assigns.room do
        case Matrix.remove_member(socket.assigns.principal_id, socket.assigns.room.id, username) do
          {:ok, _} ->
            socket
            |> assign(:members, Memberships.list_members(socket.assigns.room.id))
            |> put_flash(:info, "Removed #{username} from the room.")

          {:error, :forbidden} ->
            put_flash(socket, :error, "Only the room creator can remove members.")

          {:error, :cannot_remove_self} ->
            put_flash(socket, :error, "Use Leave room to leave.")

          {:error, _} ->
            put_flash(socket, :error, "Could not remove #{username}.")
        end
      else
        socket
      end

    {:noreply, socket}
  end

  def handle_event("leave_room", _params, socket) do
    if socket.assigns.room do
      socket = clear_local_typing(socket)

      _ =
        Matrix.leave_room(
          socket.assigns.principal_id,
          Identity.room_id(socket.assigns.room.id)
        )

      {:noreply,
       socket
       |> assign(:rooms, Rooms.list_rooms_for(socket.assigns.principal_id))
       |> assign(
         room: nil,
         members: [],
         messages: [],
         room_files: [],
         info_open?: false,
         typing_users: [],
         typing_label: nil
       )
       |> push_patch(to: ~p"/groups")}
    else
      {:noreply, socket}
    end
  end

  def handle_event("cancel_upload", %{"ref" => ref, "upload" => "chat_file"}, socket) do
    {:noreply, cancel_upload(socket, :chat_file, ref)}
  end

  def handle_event("cancel_upload", %{"ref" => ref, "upload" => "room_avatar"}, socket) do
    {:noreply, cancel_upload(socket, :room_avatar, ref)}
  end

  def handle_event("noop", _params, socket), do: {:noreply, socket}

  @impl true
  def handle_info({:room_event, room_id, msg}, socket) do
    socket =
      if socket.assigns.room && socket.assigns.room.id == room_id do
        case msg["type"] do
          "m.room.message" ->
            socket
            |> append_message(msg)
            |> maybe_refresh_files(msg)

          "m.room.member" ->
            assign(socket, :members, Memberships.list_members(room_id))

          "m.room.name" ->
            room = Rooms.get_room(room_id)

            socket
            |> assign(:room, room)
            |> assign(:name_draft, room && room.name)
            |> assign(:rooms, Rooms.list_rooms_for(socket.assigns.principal_id))

          "m.room.avatar" ->
            assign(socket, :room, Rooms.get_room(room_id))

          _ ->
            socket
        end
      else
        socket
      end

    {:noreply, socket}
  end

  def handle_info({:room_ephemeral, room_id, %{"type" => "m.typing"} = event}, socket) do
    socket =
      if socket.assigns.room && socket.assigns.room.id == room_id do
        users =
          event
          |> get_in(["content", "user_ids"])
          |> List.wrap()
          |> TypingLabel.usernames_from_mxids(socket.assigns.username)

        socket
        |> assign(:typing_users, users)
        |> assign(:typing_label, TypingLabel.format(users))
      else
        socket
      end

    {:noreply, socket}
  end

  def handle_info({:room_ephemeral, _room_id, _event}, socket), do: {:noreply, socket}

  def handle_info({:room_presence, _room_id, _presence}, socket), do: {:noreply, socket}

  def handle_info({:typing_idle, token}, socket) do
    socket =
      if socket.assigns.typing_idle_token == token and socket.assigns.i_am_typing? do
        clear_local_typing(socket)
      else
        socket
      end

    {:noreply, socket}
  end

  defp handle_chat_progress(:chat_file, entry, socket) do
    if entry.done? do
      {:noreply, consume_chat_entry(socket, entry)}
    else
      {:noreply, socket}
    end
  end

  defp handle_avatar_progress(:room_avatar, entry, socket) do
    if entry.done? do
      {:noreply, consume_avatar_entry(socket, entry)}
    else
      {:noreply, socket}
    end
  end

  defp consume_chat_entry(socket, entry) do
    room = socket.assigns.room

    if is_nil(room) do
      socket
    else
      case consume_uploaded_entry(socket, entry, fn %{path: path} ->
             body = File.read!(path)
             filename = entry.client_name || "upload.bin"
             content_type = entry.client_type || "application/octet-stream"

             case Media.upload(socket.assigns.principal_id, body,
                    filename: filename,
                    content_type: content_type
                  ) do
               {:ok, upload} ->
                 msgtype =
                   if String.starts_with?(upload.info["mimetype"] || content_type, "image/"),
                     do: "m.image",
                     else: "m.file"

                 content = %{
                   "msgtype" => msgtype,
                   "body" => filename,
                   "url" => upload.content_uri,
                   "info" => upload.info
                 }

                 txn = "lv-file-#{System.unique_integer([:positive])}"

                 case Matrix.send_message(socket.assigns.principal_id, room.id, txn, content) do
                   {:ok, event} -> {:ok, event}
                   {:error, reason} -> {:postpone, reason}
                 end

               {:error, reason} ->
                 {:postpone, reason}
             end
           end) do
        {:postpone, :too_large} ->
          put_flash(socket, :error, "File exceeds the 10MB limit.")

        {:postpone, :no_send_permission} ->
          put_flash(socket, :error, "Your account cannot send messages yet.")

        {:postpone, _} ->
          put_flash(socket, :error, "Could not upload file.")

        event when is_map(event) ->
          socket
          |> append_message(event)
          |> assign(:room_files, Matrix.list_room_files(socket.assigns.principal_id, room.id))
      end
    end
  end

  defp consume_avatar_entry(socket, entry) do
    room = socket.assigns.room

    if is_nil(room) do
      socket
    else
      case consume_uploaded_entry(socket, entry, fn %{path: path} ->
             body = File.read!(path)
             filename = entry.client_name || "avatar.png"
             content_type = entry.client_type || "image/png"

             case Media.upload(socket.assigns.principal_id, body,
                    filename: filename,
                    content_type: content_type
                  ) do
               {:ok, upload} ->
                 case Matrix.set_avatar(
                        socket.assigns.principal_id,
                        room.id,
                        upload.content_uri,
                        upload.info
                      ) do
                   {:ok, _} -> {:ok, upload.content_uri}
                   {:error, reason} -> {:postpone, reason}
                 end

               {:error, reason} ->
                 {:postpone, reason}
             end
           end) do
        {:postpone, :too_large} ->
          put_flash(socket, :error, "File exceeds the 10MB limit.")

        {:postpone, _} ->
          put_flash(socket, :error, "Could not update room photo.")

        _uri ->
          socket
          |> assign(:room, Rooms.get_room(room.id))
          |> assign(:rooms, Rooms.list_rooms_for(socket.assigns.principal_id))
          |> put_flash(:info, "Room photo updated.")
      end
    end
  end

  defp apply_room_param(socket, nil) do
    socket
    |> clear_local_typing()
    |> unsubscribe_room()
    |> assign(
      room: nil,
      members: [],
      messages: [],
      room_files: [],
      info_open?: false,
      typing_users: [],
      typing_label: nil
    )
  end

  defp apply_room_param(socket, room_id) do
    principal_id = socket.assigns.principal_id

    case Rooms.get_room(room_id) do
      nil ->
        socket
        |> clear_local_typing()
        |> unsubscribe_room()
        |> assign(
          room: nil,
          members: [],
          messages: [],
          room_files: [],
          info_open?: false,
          typing_users: [],
          typing_label: nil
        )
        |> put_flash(:error, "Room not found.")
        |> push_patch(to: ~p"/groups")

      room ->
        if Memberships.joined?(room.id, principal_id) do
          socket = clear_local_typing(socket)
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
          |> assign(:room_files, Matrix.list_room_files(principal_id, room.id))
          |> assign(:is_creator?, Matrix.creator?(room.id, principal_id))
          |> assign(:name_draft, room.name || "")
          |> assign(:info_open?, false)
          |> assign(:typing_users, [])
          |> assign(:typing_label, nil)
        else
          socket
          |> clear_local_typing()
          |> unsubscribe_room()
          |> assign(
            room: nil,
            members: [],
            messages: [],
            room_files: [],
            info_open?: false,
            typing_users: [],
            typing_label: nil
          )
          |> put_flash(:error, "You are not a member of this room.")
          |> push_patch(to: ~p"/groups")
        end
    end
  end

  defp sync_typing_state(socket, body) do
    room = socket.assigns.room
    trimmed = body |> to_string() |> String.trim()

    cond do
      is_nil(room) ->
        socket

      trimmed == "" ->
        clear_local_typing(socket)

      true ->
        now = System.system_time(:millisecond)
        last = socket.assigns.typing_sent_at || 0
        should_refresh = not socket.assigns.i_am_typing? or now - last >= @typing_refresh_ms

        socket =
          if should_refresh do
            :ok =
              RoomServer.set_typing(
                room.id,
                socket.assigns.principal_id,
                socket.assigns.username,
                true
              )

            socket
            |> assign(:i_am_typing?, true)
            |> assign(:typing_sent_at, now)
          else
            assign(socket, :i_am_typing?, true)
          end

        schedule_typing_idle(socket)
    end
  end

  defp schedule_typing_idle(socket) do
    token = System.unique_integer([:positive])
    Process.send_after(self(), {:typing_idle, token}, @typing_idle_ms)
    assign(socket, :typing_idle_token, token)
  end

  defp clear_local_typing(socket) do
    if socket.assigns[:i_am_typing?] and socket.assigns[:room] do
      :ok =
        RoomServer.set_typing(
          socket.assigns.room.id,
          socket.assigns.principal_id,
          socket.assigns.username,
          false
        )
    end

    socket
    |> assign(:i_am_typing?, false)
    |> assign(:typing_sent_at, 0)
    |> assign(:typing_idle_token, 0)
  end

  defp append_message(socket, msg) do
    if message_seen?(socket.assigns.messages, msg) do
      socket
    else
      update(socket, :messages, &(&1 ++ [msg]))
    end
  end

  defp maybe_refresh_files(socket, %{"content" => %{"msgtype" => type}})
       when type in ["m.file", "m.image"] do
    assign(
      socket,
      :room_files,
      Matrix.list_room_files(socket.assigns.principal_id, socket.assigns.room.id)
    )
  end

  defp maybe_refresh_files(socket, _), do: socket

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

  def message_msgtype(%{"content" => %{"msgtype" => type}}), do: type
  def message_msgtype(_), do: "m.text"

  def media_path(nil), do: ~p"/images/room-default.svg"

  def media_path("mxc://" <> rest) do
    case String.split(rest, "/", parts: 2) do
      [server, id] when id != "" -> ~p"/media/#{server}/#{id}"
      _ -> ~p"/images/room-default.svg"
    end
  end

  def media_path(_), do: ~p"/images/room-default.svg"

  def room_avatar_src(%{avatar_url: url}) when is_binary(url) and url != "", do: media_path(url)
  def room_avatar_src(_), do: ~p"/images/room-default.svg"

  def thumbnail_src(%{"content" => %{"info" => %{"thumbnail_url" => url}}}) when is_binary(url),
    do: media_path(url)

  def thumbnail_src(%{"content" => %{"url" => url}}) when is_binary(url), do: media_path(url)
  def thumbnail_src(_), do: nil

  def file_url(%{"content" => %{"url" => url}}) when is_binary(url), do: media_path(url)
  def file_url(_), do: nil
end
