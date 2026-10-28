defmodule LakehouseMatrix.ReadSnapshot do
  @moduledoc "Bounded memoization confined to one stream-locked, read-only sync build."
  @key {__MODULE__, :values}
  @limit 512

  def run(fun) do
    if Process.get(@key) do
      fun.()
    else
      Process.put(@key, %{})

      try do
        fun.()
      after
        Process.delete(@key)
      end
    end
  end

  def fetch(key, load) do
    case Process.get(@key) do
      nil ->
        load.()

      cache ->
        case Map.fetch(cache, key) do
          {:ok, value} ->
            value

          :error ->
            value = load.()
            # A loader can itself memoize other reads; retain those entries.
            current = Process.get(@key)
            if map_size(current) < @limit, do: Process.put(@key, Map.put(current, key, value))
            value
        end
    end
  end
end
