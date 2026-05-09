defmodule LakehouseWeb.RoomChannel do
  use LakehouseWeb, :channel

  alias LakehouseMatrix.{RoomServer, Rooms}
  alias LakehouseWeb.Presence

  @impl true
  def join("room:" <> room_id, _payload, socket) do
    case Rooms.get_room(room_id) do
      nil ->
        {:error, %{reason: "room_not_found"}}

      room ->
        {:ok, _} = Rooms.ensure_started(room.id)

        _ =
          RoomServer.join(room.id, socket.assigns.principal_id, self())

        socket = assign(socket, :room_db_id, room.id)

        send(self(), :after_join)

        {:ok, socket}
    end
  end

  @impl true
  def handle_info(:after_join, socket) do
    case Presence.track(socket, socket.assigns.principal_id, %{
           username: socket.assigns.username,
           online_at: System.system_time(:second)
         }) do
      {:ok, _} ->
        push(socket, "presence_state", Presence.list(socket))
        {:noreply, socket}

      {:error, _} ->
        {:noreply, socket}
    end
  end

  @impl true
  def handle_in("ping", payload, socket) do
    {:reply, {:ok, payload}, socket}
  end

  @impl true
  def handle_in("event", %{"type" => _} = payload, socket) do
    RoomServer.broadcast(socket.assigns.room_db_id, payload)
    {:noreply, socket}
  end

  def handle_in("event", payload, socket) do
    RoomServer.broadcast(socket.assigns.room_db_id, payload)
    {:noreply, socket}
  end

  @impl true
  def terminate(_reason, socket) do
    _ = RoomServer.leave(socket.assigns.room_db_id, self())
    :ok
  end
end
