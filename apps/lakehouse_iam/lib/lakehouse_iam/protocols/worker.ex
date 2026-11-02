defmodule LakehouseIam.Protocols.Worker do
  use GenServer
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  @impl true
  def init(_) do
    :ok = LakehouseIam.Changes.subscribe(nil, "protocol_deliveries")
    {:ok, %{timer: :erlang.start_timer(0, self(), :deliver)}}
  end

  @impl true
  def handle_info({:timeout, timer, :deliver}, %{timer: timer} = state) do
    result =
      if Application.get_env(:lakehouse_iam, :protocol_worker_enabled, true) do
        try do
          LakehouseIam.Protocols.deliver_once()
        rescue
          _ -> :idle
        end
      else
        :idle
      end

    # Drain a burst promptly; only idle/error waits incur the one-second delay.
    {:noreply,
     %{
       state
       | timer: :erlang.start_timer(if(result == :worked, do: 0, else: 1000), self(), :deliver)
     }}
  end

  def handle_info({:gravitas_change, %{"protocol_delivery" => true}}, state) do
    Process.cancel_timer(state.timer)
    {:noreply, %{state | timer: :erlang.start_timer(0, self(), :deliver)}}
  end

  def handle_info(_, state), do: {:noreply, state}
end
