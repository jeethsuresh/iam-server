defmodule LakehouseWeb.RoomChannel do
  use LakehouseWeb, :channel

  alias LakehouseMatrix.{Matrix, Memberships, RoomServer, Rooms}

  @impl true
  def join("room:" <> room_id, _payload, socket) do
    case Rooms.get_room(room_id) do
      nil ->
        {:error, %{reason: "room_not_found"}}

      room ->
        principal_id = socket.assigns.principal_id

        if Memberships.joined?(room.id, principal_id) and
             LakehouseMatrix.AccountModeration.check(principal_id, :read) == :ok do
          {:ok, _} = Rooms.ensure_started(room.id)

          Phoenix.PubSub.subscribe(LakehouseWeb.PubSub, "room:#{room.id}")

          _ = RoomServer.join(room.id, principal_id, self())

          socket = assign(socket, :room_db_id, room.id)

          send(self(), :after_join)

          {:ok, socket}
        else
          {:error, %{reason: "not_member"}}
        end
    end
  end

  @impl true
  def handle_info({:room_event, _room_id, msg}, socket) do
    if allowed?(socket) do
      push(socket, "event", msg)
      {:noreply, socket}
    else
      {:stop, :normal, socket}
    end
  end

  def handle_info({:room_ephemeral, _room_id, msg}, socket) do
    if allowed?(socket) do
      push(socket, "ephemeral", msg)
      {:noreply, socket}
    else
      {:stop, :normal, socket}
    end
  end

  def handle_info({:room_presence, _room_id, presence}, socket) do
    if allowed?(socket) do
      push(socket, "presence_state", presence)
      {:noreply, socket}
    else
      {:stop, :normal, socket}
    end
  end

  def handle_info(:after_join, socket) do
    if allowed?(socket) do
      meta = %{
        username: socket.assigns.username,
        online_at: System.system_time(:second)
      }

      _ = RoomServer.track_presence(socket.assigns.room_db_id, socket.assigns.principal_id, meta)
      push(socket, "presence_state", RoomServer.presence_list(socket.assigns.room_db_id))
      {:noreply, socket}
    else
      {:stop, :normal, socket}
    end
  end

  @impl true
  def handle_in("ping", payload, socket) do
    {:reply, {:ok, payload}, socket}
  end

  def handle_in("typing", %{"typing" => typing?}, socket) do
    if allowed?(socket, :write) do
      _ =
        RoomServer.set_typing(
          socket.assigns.room_db_id,
          socket.assigns.principal_id,
          socket.assigns.username,
          typing? in [true, "true", 1, "1"]
        )

      {:noreply, socket}
    else
      {:stop, :normal, socket}
    end
  end

  def handle_in("event", %{"type" => "m.room.message"} = payload, socket) do
    txn = "ch-#{System.unique_integer([:positive])}"
    body = Map.get(payload, "body") || get_in(payload, ["content", "body"]) || ""

    _ =
      Matrix.send_message(
        socket.assigns.principal_id,
        socket.assigns.room_db_id,
        txn,
        %{"body" => body, "msgtype" => "m.text"}
      )

    {:noreply, socket}
  end

  def handle_in("event", _payload, socket) do
    {:noreply, socket}
  end

  defp allowed?(socket, mode \\ :read),
    do:
      Memberships.joined?(socket.assigns.room_db_id, socket.assigns.principal_id) and
        LakehouseMatrix.AccountModeration.check(socket.assigns.principal_id, mode) == :ok

  @impl true
  def terminate(_reason, socket) do
    room_id = socket.assigns[:room_db_id]

    if room_id do
      _ = RoomServer.untrack_presence(room_id, socket.assigns.principal_id)
      _ = RoomServer.leave(room_id, self())
    end

    :ok
  end
end
