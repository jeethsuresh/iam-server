defmodule LakehouseMatrix.ClientKeys do
  @moduledoc "Device keys are opaque client-signed objects; one-time keys are claimed atomically."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseMatrix.{ClientStore, CrossSigning, Identity}
  alias LakehouseMatrix.Federation.DeviceKeys

  def upload(principal, device, username, params) do
    Repo.transaction(fn ->
      ClientStore.lock!()
      LakehouseMatrix.AccountModeration.require!(principal, :read)

      if CrossSigning.reserved_device_id?(principal, device), do: Repo.rollback(:invalid_param)

      if keys = params["device_keys"] do
        unless is_map(keys) and keys["user_id"] == Identity.user_id(username) and
                 keys["device_id"] == device and
                 is_map(keys["keys"]) and is_list(keys["algorithms"]) and
                 byte_size(Jason.encode!(keys)) <= 65_536,
               do: Repo.rollback(:invalid_param)

        Repo.update_all(
          from(d in "matrix_devices",
            where: d.principal_id == type(^principal, :binary_id) and d.device_id == ^device
          ),
          set: [keys: keys, updated_at: ClientStore.now()]
        )
      end

      if params["device_keys"], do: DeviceKeys.changed!(principal, device)

      for {field, fallback} <- [{"one_time_keys", false}, {"fallback_keys", true}] do
        keys = params[field] || %{}
        unless is_map(keys) and map_size(keys) <= 1000, do: Repo.rollback(:invalid_param)

        for {id, value} <- keys do
          unless is_binary(id) and String.contains?(id, ":") and byte_size(id) <= 255 and
                   (is_map(value) or is_binary(value)) and
                   byte_size(Jason.encode!(value)) <= 16_384,
                 do: Repo.rollback(:invalid_param)

          if fallback do
            key_algorithm = algorithm(id)

            Repo.delete_all(
              from k in "matrix_one_time_keys",
                where:
                  k.principal_id == type(^principal, :binary_id) and
                    k.device_id == ^device and k.fallback == true and k.key_id != ^id and
                    fragment("split_part(?, ':', 1) = ?", k.key_id, ^key_algorithm)
            )
          end

          Repo.insert_all(
            "matrix_one_time_keys",
            [
              %{
                principal_id: ClientStore.dump_id(principal),
                device_id: device,
                key_id: id,
                key: %{"value" => value},
                fallback: fallback,
                used: false
              }
            ],
            on_conflict: :nothing,
            conflict_target: [:principal_id, :device_id, :key_id]
          )
        end
      end

      %{"one_time_key_counts" => counts(principal, device)}
    end)
  end

  def counts(principal, device) do
    Repo.all(
      from k in "matrix_one_time_keys",
        where:
          k.principal_id == type(^principal, :binary_id) and k.device_id == ^device and
            k.fallback == false,
        select: k.key_id
    )
    |> Enum.frequencies_by(&algorithm/1)
  end

  def unused_fallback(principal, device) do
    Repo.all(
      from k in "matrix_one_time_keys",
        where:
          k.principal_id == type(^principal, :binary_id) and k.device_id == ^device and
            k.fallback == true and k.used == false,
        select: k.key_id
    )
    |> Enum.map(&algorithm/1)
    |> Enum.uniq()
  end

  def query(requester, users) do
    with :ok <- validate_selection(users, :query),
         {:ok, local} <- local_query(requester, users) do
      remote = DeviceKeys.remote(users, "query")
      {:ok, DeviceKeys.merge(local, remote)}
    end
  end

  def local_query(requester, users) when is_map(users) and map_size(users) <= 100 do
    result =
      Enum.reduce(users, %{}, fn {mxid, device_ids}, acc ->
        with true <- is_list(device_ids) and length(device_ids) <= 100,
             {:ok, name} <- Identity.parse_user_id(mxid),
             {:ok, p} <- Accounts.fetch_user(name) do
          devices =
            Repo.all(
              from d in "matrix_devices",
                where: d.principal_id == type(^p.id, :binary_id),
                select: {d.device_id, d.keys, d.display_name}
            )

          keys =
            for {id, keys, display} <- devices,
                map_size(keys) > 0 and (device_ids == [] or id in device_ids),
                into: %{} do
              {id,
               CrossSigning.decorate(
                 Map.put(keys, "unsigned", %{"device_display_name" => display}),
                 mxid,
                 id,
                 requester
               )}
            end

          Map.put(acc, mxid, keys)
        else
          _ -> acc
        end
      end)

    cross =
      Enum.reduce(users, %{}, fn {user, _}, acc ->
        with {:ok, name} <- Identity.parse_user_id(user),
             {:ok, p} <- Accounts.fetch_user(name) do
          DeviceKeys.merge(acc, CrossSigning.query(p.id, user, requester))
        else
          _ -> acc
        end
      end)

    {:ok,
     Map.merge(
       %{
         "device_keys" => result,
         "failures" => %{},
         "master_keys" => %{},
         "self_signing_keys" => %{},
         "user_signing_keys" => %{}
       },
       cross
     )}
  end

  def local_query(_, _), do: {:error, :invalid_param}

  def claim(requester, users) do
    with :ok <- validate_selection(users, :claim),
         {:ok, local} <- local_claim(requester, users) do
      {:ok, DeviceKeys.merge(local, DeviceKeys.remote(users, "claim"))}
    end
  end

  def local_claim(_requester, users) when is_map(users) and map_size(users) <= 100 do
    Repo.transaction(fn ->
      result =
        Enum.reduce(users, %{}, fn {mxid, devices}, acc ->
          unless is_map(devices) and map_size(devices) <= 100, do: Repo.rollback(:invalid_param)

          with {:ok, name} <- Identity.parse_user_id(mxid),
               {:ok, p} <- Accounts.fetch_user(name) do
            keys =
              Enum.reduce(devices, %{}, fn {device, algorithm}, inner ->
                unless is_binary(algorithm), do: Repo.rollback(:invalid_param)

                base =
                  from k in "matrix_one_time_keys",
                    where:
                      k.principal_id == type(^p.id, :binary_id) and k.device_id == ^device and
                        fragment("split_part(?, ':', 1) = ?", k.key_id, ^algorithm),
                    select: %{id: k.id, key_id: k.key_id, key: k.key, fallback: k.fallback},
                    limit: 1,
                    lock: "FOR UPDATE SKIP LOCKED"

                key =
                  Repo.one(from k in base, where: k.fallback == false, order_by: k.id) ||
                    Repo.one(from k in base, where: k.fallback == true, order_by: [desc: k.id])

                if key do
                  if key.fallback,
                    do:
                      Repo.update_all(from(k in "matrix_one_time_keys", where: k.id == ^key.id),
                        set: [used: true]
                      ),
                    else:
                      Repo.delete_all(from k in "matrix_one_time_keys", where: k.id == ^key.id)

                  Map.put(inner, device, %{key.key_id => key.key["value"]})
                else
                  inner
                end
              end)

            Map.put(acc, mxid, keys)
          else
            _ -> acc
          end
        end)

      %{"one_time_keys" => result, "failures" => %{}}
    end)
  end

  def local_claim(_, _), do: {:error, :invalid_param}

  defp validate_selection(users, kind) when is_map(users) and map_size(users) <= 100 do
    valid =
      Enum.all?(users, fn {user, selection} ->
        match?({:ok, _}, LakehouseMatrix.Protocol.Event.user_domain(user)) and
          case kind do
            :query ->
              is_list(selection) and length(selection) <= 100 and
                Enum.all?(selection, &(is_binary(&1) and byte_size(&1) in 1..255))

            :claim ->
              is_map(selection) and map_size(selection) <= 100 and
                Enum.all?(selection, fn {device, algorithm} ->
                  is_binary(device) and byte_size(device) in 1..255 and is_binary(algorithm) and
                    byte_size(algorithm) in 1..255
                end)
          end
      end)

    if valid, do: :ok, else: {:error, :invalid_param}
  end

  defp validate_selection(_, _), do: {:error, :invalid_param}

  defp algorithm(id), do: id |> String.split(":", parts: 2) |> hd()
end
