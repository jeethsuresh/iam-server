defmodule LakehouseMatrix.RoomServer do
  @moduledoc """
  Long-lived room actor: tracks participants and fans out persisted Matrix events.
  """
  use GenServer

  defstruct [:room_id, members: %{}]

  def start_link(room_id) do
    GenServer.start_link(__MODULE__, room_id, name: via(room_id))
  end

  defp via(room_id), do: {:via, Registry, {LakehouseMatrix.RoomRegistry, room_id}}

  def broadcast_event(room_id, event_map) when is_map(event_map) do
    GenServer.cast(via(room_id), {:broadcast, event_map})
  end

  def join(room_id, principal_id, pid) do
    GenServer.call(via(room_id), {:join, principal_id, pid})
  end

  def leave(room_id, pid) do
    GenServer.cast(via(room_id), {:leave, pid})
  end

  @impl true
  def init(room_id) do
    {:ok, %__MODULE__{room_id: room_id, members: %{}}}
  end

  @impl true
  def handle_call({:join, principal_id, pid}, _from, state) do
    {:reply, :ok, %{state | members: Map.put(state.members, pid, principal_id)}}
  end

  @impl true
  def handle_cast({:leave, pid}, state) do
    {:noreply, %{state | members: Map.delete(state.members, pid)}}
  end

  def handle_cast({:broadcast, event_map}, state) do
    pubsub = Application.fetch_env!(:lakehouse_matrix, :pubsub)
    topic = "room:#{state.room_id}"

    Phoenix.PubSub.broadcast(pubsub, topic, {:room_event, state.room_id, event_map})

    {:noreply, state}
  end
end
