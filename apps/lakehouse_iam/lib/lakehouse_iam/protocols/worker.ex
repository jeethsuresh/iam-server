defmodule LakehouseIam.Protocols.Worker do
  use GenServer
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  @impl true
  def init(_) do
    send(self(), :deliver)
    {:ok, nil}
  end

  @impl true
  def handle_info(:deliver, state) do
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
    Process.send_after(self(), :deliver, if(result == :worked, do: 10, else: 1000))
    {:noreply, state}
  end
end
