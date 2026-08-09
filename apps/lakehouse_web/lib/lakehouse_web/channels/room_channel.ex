defmodule LakehouseWeb.RoomChannel do
  use LakehouseWeb, :channel

  alias LakehouseMatrix.{Matrix, Memberships, Rooms}
  alias LakehouseWeb.Presence

  @impl true
  def join("room:" <> room_id, _payload, socket) do
    case Rooms.get_room(room_id) do
      nil ->
        {:error, %{reason: "room_not_found"}}

      room ->
        principal_id = socket.assigns.principal_id

        if Memberships.joined?(room.id, principal_id) do
          {:ok, _} = Rooms.ensure_started(room.id)

          Phoenix.PubSub.subscribe(LakehouseWeb.PubSub, "room:#{room.id}")

          _ =
            LakehouseMatrix.RoomServer.join(room.id, principal_id, self())

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
    push(socket, "event", msg)
    {:noreply, socket}
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

  @impl true
  def terminate(_reason, socket) do
    _ = LakehouseMatrix.RoomServer.leave(socket.assigns.room_db_id, self())
    :ok
  end
end
