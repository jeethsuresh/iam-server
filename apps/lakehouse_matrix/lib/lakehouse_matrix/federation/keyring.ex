defmodule LakehouseMatrix.Federation.Keyring do
  @moduledoc "Persist and pin server verification keys, including historical keys needed by room PDUs."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, Identity}
  alias LakehouseMatrix.Federation.{Signing, Transport}

  def key(server, id, timestamp, fetch \\ nil) do
    fetch =
      fetch ||
        Application.get_env(:lakehouse_matrix, :federation_key_fetcher, &Transport.get_json/2)

    with {:ok, _} <- Transport.server_name(server),
         true <- is_binary(id) and String.starts_with?(id, "ed25519:") and is_integer(timestamp) do
      case local_key(server, id) do
        {:ok, _} = result ->
          result

        _ ->
          case cached(server, id, timestamp) do
            {:ok, _} = result ->
              result

            _ ->
              with {:ok, document} <- fetch_once(server, fetch),
                   :ok <- remember(server, document),
                   do: cached(server, id, timestamp)
          end
      end
    else
      _ -> {:error, :invalid_key}
    end
  end

  @cache_key {__MODULE__, :verification_fetches}
  @doc "Limit one verification to one key-document fetch per server, including unknown key IDs."
  def with_cache(callback) do
    previous = Process.get(@cache_key)
    Process.put(@cache_key, MapSet.new())

    try do
      callback.()
    after
      if is_nil(previous), do: Process.delete(@cache_key), else: Process.put(@cache_key, previous)
    end
  end

  defp fetch_once(server, fetch) do
    case Process.get(@cache_key) do
      nil ->
        fetch.(server, "/_matrix/key/v2/server")

      seen ->
        if MapSet.member?(seen, server) do
          {:error, :unknown_key}
        else
          Process.put(@cache_key, MapSet.put(seen, server))
          fetch.(server, "/_matrix/key/v2/server")
        end
    end
  end

  def remember(server, document) do
    with ^server <- document["server_name"],
         until when is_integer(until) <- document["valid_until_ts"],
         true <- until > System.system_time(:millisecond),
         keys when is_map(keys) <- document["verify_keys"],
         true <- map_size(keys) in 1..100,
         true <-
           Enum.any?(keys, fn {id, value} ->
             with {:ok, public} <- decode(value["key"]),
                  true <- String.starts_with?(id, "ed25519:"),
                  do: Signing.verify(document, public, id, server),
                  else: (_ -> false)
           end),
         old when is_map(old) <- document["old_verify_keys"] || %{},
         true <- map_size(old) <= 100 do
      entries =
        Enum.map(keys, fn {id, value} -> {id, value["key"], until, false} end) ++
          Enum.map(old, fn {id, value} -> {id, value["key"], value["expired_ts"], true} end)

      Repo.transaction(fn ->
        for {id, encoded, until, retired} <- entries, String.starts_with?(id, "ed25519:") do
          with {:ok, public} <- decode(encoded), true <- is_integer(until) do
            Repo.insert_all(
              "matrix_server_keys",
              [
                %{
                  server_name: server,
                  key_id: id,
                  public_key: public,
                  valid_until_ts: until,
                  fetched_at: ClientStore.now()
                }
              ],
              on_conflict: :nothing,
              conflict_target: [:server_name, :key_id]
            )

            current =
              Repo.one!(
                from k in "matrix_server_keys",
                  where: k.server_name == ^server and k.key_id == ^id,
                  lock: "FOR UPDATE",
                  select: %{public: k.public_key, until: k.valid_until_ts}
              )

            if current.public != public, do: Repo.rollback(:signing_key_reused)

            Repo.update_all(
              from(k in "matrix_server_keys", where: k.server_name == ^server and k.key_id == ^id),
              set: [
                valid_until_ts: if(retired, do: until, else: max(until, current.until)),
                fetched_at: ClientStore.now()
              ]
            )
          else
            _ -> Repo.rollback(:invalid_key)
          end
        end
      end)
      |> case do
        {:ok, _} -> :ok
        error -> error
      end
    else
      _ -> {:error, :invalid_key_document}
    end
  rescue
    _ -> {:error, :invalid_key_document}
  end

  defp cached(server, id, timestamp) do
    case Repo.one(
           from k in "matrix_server_keys",
             where:
               k.server_name == ^server and k.key_id == ^id and
                 k.valid_until_ts > ^timestamp,
             select: k.public_key
         ) do
      nil -> {:error, :unknown_key}
      public -> {:ok, public}
    end
  end

  defp local_key(server, id) do
    with true <- server == Identity.homeserver_domain(),
         {:ok, seed, ^id} <- Signing.config(),
         do: {:ok, Signing.public_key(seed)},
         else: (_ -> {:error, :unknown_key})
  end

  defp decode(value) when is_binary(value) do
    with {:ok, raw} <- Base.decode64(value, padding: false),
         true <- byte_size(raw) == 32,
         do: {:ok, raw},
         else: (_ -> {:error, :invalid_key})
  end

  defp decode(_), do: {:error, :invalid_key}
end
