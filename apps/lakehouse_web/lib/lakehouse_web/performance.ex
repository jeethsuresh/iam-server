defmodule LakehouseWeb.Performance do
  @moduledoc "Request SQL cost and latency instrumentation without query text or account data."
  import Plug.Conn
  @key {__MODULE__, :request}

  def attach do
    case :telemetry.attach(
           __MODULE__,
           [:lakehouse_iam, :repo, :query],
           &__MODULE__.query/4,
           nil
         ) do
      :ok -> :ok
      {:error, :already_exists} -> :ok
    end
  end

  def init(opts), do: opts

  def call(conn, _) do
    Process.put(@key, %{queries: 0, query_time: 0, queue_time: 0, decode_time: 0})
    started = System.monotonic_time()

    register_before_send(conn, fn conn ->
      cost = Process.delete(@key) || %{}
      measurements = Map.put(cost, :duration, System.monotonic_time() - started)
      route = conn.private[:phoenix_route] || "unmatched"

      :telemetry.execute([:lakehouse, :request, :stop], measurements, %{
        method: conn.method,
        route: route,
        status: conn.status
      })

      timing =
        Enum.map_join(
          [{:app, :duration}, {:db, :query_time}, {:db_queue, :queue_time}],
          ", ",
          fn {name, key} ->
            ms = System.convert_time_unit(measurements[key] || 0, :native, :microsecond) / 1000
            "#{name};dur=#{Float.round(ms, 2)}"
          end
        )

      put_resp_header(
        conn,
        "server-timing",
        timing <> ", db_queries;desc=\"#{cost[:queries] || 0}\""
      )
    end)
  end

  def query(_, measurements, _, _) do
    if cost = Process.get(@key) do
      cost = Map.update!(cost, :queries, &(&1 + 1))

      updated =
        Enum.reduce([:query_time, :queue_time, :decode_time], cost, fn key, acc ->
          Map.update!(acc, key, &(&1 + (measurements[key] || 0)))
        end)

      Process.put(@key, updated)
    end
  end
end
