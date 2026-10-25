defmodule LakehouseMatrix.AsyncMedia do
  @moduledoc "Expiring, owner-bound MXC reservations and bounded waiting without holding database connections."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, ClientSync, Identity, Media}

  def create(principal) do
    Repo.transaction(fn ->
      ClientStore.lock!()
      now = ClientStore.now()
      recent = DateTime.add(now, -60, :second)

      pending =
        Repo.aggregate(
          from(r in "matrix_media_reservations",
            where:
              r.principal_id == type(^principal, :binary_id) and is_nil(r.completed_at) and
                r.expires_at > ^now
          ),
          :count
        )

      created =
        Repo.aggregate(
          from(r in "matrix_media_reservations",
            where: r.principal_id == type(^principal, :binary_id) and r.created_at > ^recent
          ),
          :count
        )

      if pending >= 32 or created >= 60, do: Repo.rollback(:rate_limited)
      id = Ecto.UUID.generate()
      expires = DateTime.add(now, 24, :hour)

      Repo.insert_all("matrix_media_reservations", [
        %{
          media_id: ClientStore.dump_id(id),
          principal_id: ClientStore.dump_id(principal),
          created_at: now,
          expires_at: expires
        }
      ])

      %{
        "content_uri" => Media.content_uri(id),
        "unused_expires_at" => DateTime.to_unix(expires, :millisecond)
      }
    end)
  end

  def put(principal, server, ref, bytes, opts \\ []) do
    with true <- server == Identity.homeserver_domain(), {:ok, id} <- Ecto.UUID.cast(ref) do
      Repo.transaction(fn ->
        row =
          Repo.one(
            from r in "matrix_media_reservations",
              where: r.media_id == type(^id, :binary_id),
              lock: "FOR UPDATE",
              select: %{
                owner: type(r.principal_id, :binary_id),
                expires: type(r.expires_at, :utc_datetime_usec),
                completed: type(r.completed_at, :utc_datetime_usec)
              }
          )

        cond do
          is_nil(row) -> Repo.rollback(:not_found)
          row.owner != principal -> Repo.rollback(:forbidden)
          not is_nil(row.completed) -> Repo.rollback(:cannot_overwrite_media)
          DateTime.compare(row.expires, ClientStore.now()) != :gt -> Repo.rollback(:not_found)
          true -> :ok
        end

        # This row lock serializes writers for this blob. The global Matrix
        # stream lock is not held during storage I/O; readers see no metadata
        # until the complete upload commits.
        options = opts |> Keyword.put(:reserved_id, id) |> Keyword.put(:matrix_public, true)

        case Media.upload(principal, bytes, options) do
          {:ok, _} ->
            Repo.update_all(
              from(r in "matrix_media_reservations", where: r.media_id == type(^id, :binary_id)),
              set: [completed_at: ClientStore.now()]
            )

            %{}

          {:error, reason} ->
            Repo.rollback(reason)
        end
      end)
    else
      _ -> {:error, :not_found}
    end
  end

  def fetch(server, id, params, callback) do
    with {:ok, timeout} <-
           ClientSync.integer(params["timeout_ms"], 20_000, 0, 9_007_199_254_740_991),
         true <- params["allow_remote"] in [nil, true, false, "true", "false"] do
      if server != Identity.homeserver_domain() and params["allow_remote"] in [false, "false"],
        do: {:error, :not_found},
        else:
          await(server, id, callback, System.monotonic_time(:millisecond) + min(timeout, 20_000))
    else
      _ -> {:error, :invalid_param}
    end
  end

  defp await(server, id, callback, deadline) do
    case callback.() do
      {:error, :not_found} = error ->
        if server == Identity.homeserver_domain() and pending?(id) do
          left = deadline - System.monotonic_time(:millisecond)

          if left <= 0 do
            {:error, :not_yet_uploaded}
          else
            Process.sleep(min(left, 100))
            await(server, id, callback, deadline)
          end
        else
          error
        end

      {:error, :not_yet_uploaded} ->
        left = deadline - System.monotonic_time(:millisecond)

        if left <= 0 do
          {:error, :not_yet_uploaded}
        else
          Process.sleep(min(left, 1_000))
          await(server, id, callback, deadline)
        end

      result ->
        result
    end
  end

  def pending?(id) do
    with {:ok, id} <- Ecto.UUID.cast(id) do
      Repo.exists?(
        from r in "matrix_media_reservations",
          where:
            r.media_id == type(^id, :binary_id) and is_nil(r.completed_at) and
              r.expires_at > ^ClientStore.now()
      )
    else
      _ -> false
    end
  end
end
