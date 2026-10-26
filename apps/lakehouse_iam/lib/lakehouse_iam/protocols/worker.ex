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
    if Application.get_env(:lakehouse_iam, :protocol_worker_enabled, true) do
      try do
        LakehouseIam.Protocols.deliver_once()
      rescue
        _ -> :retry
      end
    end

    Process.send_after(self(), :deliver, 1000)
    {:noreply, state}
  end
end
