defmodule LakehouseMatrix.ReadSnapshot do
  @moduledoc "Consistent read-only sync snapshots with bounded request-local memoization."
  alias LakehouseIam.Repo
  @key {__MODULE__, :values}
  @limit 512

  def transaction(callback) do
    nested =
      Repo.in_transaction?() or Repo.config()[:pool] == Ecto.Adapters.SQL.Sandbox

    Repo.transaction(fn ->
      # A sync must not hold the global writer lock while rendering rooms.
      # MVCC keeps every read at one committed snapshot while sends continue.
      # The SQL sandbox owns an outer transaction even when in_transaction?
      # reports false. Such callers retain their already-established isolation.
      unless nested,
        do: Repo.query!("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")

      callback.()
    end)
  end

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
