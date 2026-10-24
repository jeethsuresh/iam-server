defmodule LakehouseIam.Changes do
  @moduledoc "Post-commit invalidations and connection presence. No message bodies or credentials enter notifications."
  use GenServer
  alias LakehouseIam.Repo

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  def subscribe(principal, origin), do: GenServer.call(__MODULE__, {:subscribe, self(), principal, origin})
  def online?(principal, origin), do: GenServer.call(__MODULE__, {:online, principal, origin})
  def notify(attrs) do
    # PostgreSQL delivers NOTIFY only when the enclosing transaction commits.
    Repo.query!("SELECT pg_notify('gravitas_changes', $1)", [Jason.encode!(attrs)])
    :ok
  end
  @impl true
  def init(_) do
    opts = Repo.config() |> Keyword.take([:url, :hostname, :port, :database, :username, :password, :ssl, :socket_dir])
    {:ok, listener} = Postgrex.Notifications.start_link(opts ++ [auto_reconnect: true, sync_connect: false])
    {:ok, _} = Postgrex.Notifications.listen(listener, "gravitas_changes")
    {:ok, %{watchers: %{}, listener: listener}}
  end
  @impl true
  def handle_call({:subscribe, pid, principal, origin}, _, state) do
    count = Enum.count(state.watchers, fn {_, {p, o, _}} -> p == principal and o == origin end)
    if count >= 8 do
      {:reply, {:error, :too_many_connections}, state}
    else
      ref = Process.monitor(pid)
      broadcast(state, %{"principal_id" => principal, "app_origin" => origin})
      {:reply, :ok, put_in(state.watchers[ref], {principal, origin, pid})}
    end
  end
  def handle_call({:online, principal, origin}, _, state) do
    {:reply, Enum.any?(state.watchers, fn {_, {p, o, _}} -> p == principal and o == origin end), state}
  end
  @impl true
  def handle_info({:notification, _, _, "gravitas_changes", payload}, state) do
    case Jason.decode(payload) do
      {:ok, attrs} when is_map(attrs) -> broadcast(state, attrs)
      _ -> :ok
    end
    {:noreply, state}
  end
  def handle_info({:DOWN, ref, :process, _, _}, state) do
    {old, watchers} = Map.pop(state.watchers, ref)
    next = %{state | watchers: watchers}
    if old do
      {principal, origin, _} = old
      broadcast(next, %{"principal_id" => principal, "app_origin" => origin})
    end
    {:noreply, next}
  end
  def handle_info(_, state), do: {:noreply, state}
  defp broadcast(state, attrs) do
    Enum.each(state.watchers, fn {_, {_, _, pid}} -> send(pid, {:gravitas_change, attrs}) end)
  end
end
