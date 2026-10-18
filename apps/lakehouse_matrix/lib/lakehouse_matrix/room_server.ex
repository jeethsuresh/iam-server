defmodule LakehouseMatrix.RoomServer do
  @moduledoc """
  Long-lived room actor: subscriber set, membership/timeline caches, typing, and presence.
  """
  use GenServer

  alias LakehouseMatrix.{Events, Memberships}

  @timeline_limit 100
  # Slightly above LiveView's 2s idle clear so a missed "typing false" still expires soon.
  @typing_ttl_ms 4_000

  defstruct [
    :room_id,
    subscribers: %{},
    memberships: %{},
    timeline: [],
    typing: %{},
    presence: %{},
    caches_loaded: false
  ]

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

  @spec snapshot(Ecto.UUID.t()) :: map()
  def snapshot(room_id) do
    GenServer.call(via(room_id), :snapshot)
  end

  @spec set_typing(Ecto.UUID.t(), Ecto.UUID.t(), String.t(), boolean()) :: :ok
  def set_typing(room_id, principal_id, username, typing?) do
    GenServer.cast(via(room_id), {:set_typing, principal_id, username, typing?})
  end

  @spec track_presence(Ecto.UUID.t(), Ecto.UUID.t(), map()) :: :ok
  def track_presence(room_id, principal_id, meta) when is_map(meta) do
    GenServer.cast(via(room_id), {:track_presence, principal_id, meta})
  end

  @spec untrack_presence(Ecto.UUID.t(), Ecto.UUID.t()) :: :ok
  def untrack_presence(room_id, principal_id) do
    GenServer.cast(via(room_id), {:untrack_presence, principal_id})
  end

  @spec presence_list(Ecto.UUID.t()) :: map()
  def presence_list(room_id) do
    GenServer.call(via(room_id), :presence_list)
  end

  @impl true
  def init(room_id) do
    # Avoid DB access in init so SQL Sandbox tests can allow the pid first.
    {:ok, %__MODULE__{room_id: room_id}}
  end

  def load_caches(room_id) do
    GenServer.cast(via(room_id), :load_caches)
  end

  @impl true
  def handle_call({:join, principal_id, pid}, _from, state) do
    Process.monitor(pid)
    {:reply, :ok, %{state | subscribers: Map.put(state.subscribers, pid, principal_id)}}
  end

  def handle_call(:snapshot, _from, state) do
    state = ensure_caches(state)
    {:reply, snapshot_map(state), state}
  end

  def handle_call(:presence_list, _from, state) do
    {:reply, state.presence, state}
  end

  @impl true
  def handle_cast(:load_caches, state) do
    {:noreply, ensure_caches(state)}
  end

  def handle_cast({:leave, pid}, state) do
    {:noreply, %{state | subscribers: Map.delete(state.subscribers, pid)}}
  end

  def handle_cast({:broadcast, event_map}, state) do
    state =
      state
      |> append_timeline(event_map)
      |> maybe_update_membership(event_map)

    broadcast(state.room_id, {:room_event, state.room_id, event_map})
    {:noreply, state}
  end

  def handle_cast({:set_typing, principal_id, username, true}, state) do
    expires = System.system_time(:millisecond) + @typing_ttl_ms
    typing = Map.put(state.typing, principal_id, %{username: username, expires_at: expires})
    state = %{state | typing: typing}
    publish_typing(state)
    Process.send_after(self(), {:typing_expire, principal_id, expires}, @typing_ttl_ms)
    {:noreply, state}
  end

  def handle_cast({:set_typing, principal_id, _username, false}, state) do
    state = %{state | typing: Map.delete(state.typing, principal_id)}
    publish_typing(state)
    {:noreply, state}
  end

  def handle_cast({:track_presence, principal_id, meta}, state) do
    presence = Map.put(state.presence, principal_id, meta)
    state = %{state | presence: presence}
    broadcast(state.room_id, {:room_presence, state.room_id, presence})
    {:noreply, state}
  end

  def handle_cast({:untrack_presence, principal_id}, state) do
    presence = Map.delete(state.presence, principal_id)
    state = %{state | presence: presence}
    broadcast(state.room_id, {:room_presence, state.room_id, presence})
    {:noreply, state}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    principal_id = Map.get(state.subscribers, pid)

    state = %{
      state
      | subscribers: Map.delete(state.subscribers, pid),
        presence:
          if(principal_id, do: Map.delete(state.presence, principal_id), else: state.presence)
    }

    if principal_id do
      broadcast(state.room_id, {:room_presence, state.room_id, state.presence})
    end

    {:noreply, state}
  end

  def handle_info({:typing_expire, principal_id, expires}, state) do
    case Map.get(state.typing, principal_id) do
      %{expires_at: ^expires} ->
        state = %{state | typing: Map.delete(state.typing, principal_id)}
        publish_typing(state)
        {:noreply, state}

      _ ->
        {:noreply, state}
    end
  end

  defp ensure_caches(%{caches_loaded: true} = state), do: state

  defp ensure_caches(state) do
    try do
      %{
        state
        | memberships: Memberships.membership_map(state.room_id),
          timeline: Events.list_timeline(state.room_id, limit: @timeline_limit) |> Enum.reverse(),
          caches_loaded: true
      }
    rescue
      _ -> state
    catch
      :exit, _ -> state
    end
  end

  defp append_timeline(state, event_map) do
    timeline =
      [event_map | state.timeline]
      |> Enum.take(@timeline_limit)

    %{state | timeline: timeline}
  end

  defp maybe_update_membership(state, %{"type" => "m.room.member", "state_key" => mxid} = event) do
    membership = get_in(event, ["content", "membership"])

    case principal_id_for_mxid(mxid) do
      nil ->
        state

      principal_id when is_binary(membership) ->
        %{state | memberships: Map.put(state.memberships, principal_id, membership)}

      _ ->
        state
    end
  end

  defp maybe_update_membership(state, _), do: state

  defp publish_typing(state) do
    now = System.system_time(:millisecond)

    user_ids =
      state.typing
      |> Enum.filter(fn {_pid, meta} -> meta.expires_at > now end)
      |> Enum.map(fn {_pid, meta} ->
        "@#{meta.username}:#{LakehouseMatrix.Identity.homeserver_domain()}"
      end)

    event = %{
      "type" => "m.typing",
      "content" => %{"user_ids" => user_ids}
    }

    broadcast(state.room_id, {:room_ephemeral, state.room_id, event})
  end

  defp broadcast(room_id, message) do
    pubsub = Application.fetch_env!(:lakehouse_matrix, :pubsub)
    Phoenix.PubSub.broadcast(pubsub, "room:#{room_id}", message)
  end

  defp snapshot_map(state) do
    %{
      room_id: state.room_id,
      subscribers: map_size(state.subscribers),
      memberships: state.memberships,
      timeline: state.timeline,
      typing: state.typing,
      presence: state.presence
    }
  end

  defp principal_id_for_mxid(mxid) when is_binary(mxid) do
    case LakehouseMatrix.Identity.parse_user_id(mxid) do
      {:ok, user} ->
        case LakehouseIam.Accounts.fetch_user(user) do
          {:ok, p} -> p.id
          :error -> nil
        end

      _ ->
        nil
    end
  end
end
