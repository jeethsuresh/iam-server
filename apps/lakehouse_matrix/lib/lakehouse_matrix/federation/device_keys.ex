defmodule LakehouseMatrix.Federation.DeviceKeys do
  @moduledoc "Federated public device keys and one-time key claims; requests never run under the stream lock."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseMatrix.{ClientKeys, CrossSigning, Identity}
  alias LakehouseMatrix.Federation.{Edus, RoomAccess, Transport}
  alias LakehouseMatrix.Protocol.Event

  def changed!(principal, device, deleted \\ false) do
    user = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

    previous =
      Repo.one(
        from c in "matrix_device_changes", where: c.user_id == ^user, select: max(c.stream_id)
      )

    {1, [change]} =
      Repo.insert_all("matrix_device_changes", [%{user_id: user}], returning: [:stream_id])

    record =
      Repo.one(
        from d in "matrix_devices",
          where: d.principal_id == type(^principal, :binary_id) and d.device_id == ^device,
          select: %{keys: d.keys, display_name: d.display_name}
      )

    content = %{
      "user_id" => user,
      "device_id" => device,
      "stream_id" => change.stream_id,
      "prev_id" => if(previous, do: [previous], else: []),
      "deleted" => deleted
    }

    content =
      if record && not deleted do
        content
        |> Map.put("keys", record.keys)
        |> Map.put("device_display_name", record.display_name)
      else
        content
      end

    for destination <- destinations(user),
        do: Edus.outgoing!(destination, "m.device_list_update", content)

    :ok
  end

  def signing_changed!(principal) do
    user = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()
    keys = CrossSigning.keys(principal)

    content =
      %{"user_id" => user}
      |> maybe_put("master_key", keys["master"])
      |> maybe_put("self_signing_key", keys["self_signing"])

    Repo.insert_all("matrix_device_changes", [%{user_id: user}])

    for destination <- destinations(user),
        do: Edus.outgoing!(destination, "m.signing_key_update", content)
  end

  def user_devices(user) do
    with {:ok, name} <- Identity.parse_user_id(user),
         {:ok, p} <- Accounts.fetch_user(name),
         true <- p.active do
      devices =
        Repo.all(
          from d in "matrix_devices",
            where: d.principal_id == type(^p.id, :binary_id),
            select: %{id: d.device_id, keys: d.keys, display: d.display_name}
        )

      keys = CrossSigning.keys(p.id)

      {:ok,
       %{
         "user_id" => user,
         "stream_id" =>
           Repo.one(
             from c in "matrix_device_changes",
               where: c.user_id == ^user,
               select: max(c.stream_id)
           ) || 0,
         "devices" =>
           for(
             d <- devices,
             map_size(d.keys) > 0,
             do:
               %{
                 "device_id" => d.id,
                 "keys" => CrossSigning.decorate(d.keys, user, d.id, :public)
               }
               |> maybe_put("device_display_name", d.display)
           )
       }
       |> maybe_put("master_key", keys["master"])
       |> maybe_put("self_signing_key", keys["self_signing"])}
    else
      _ -> {:error, :not_found}
    end
  end

  def query(users), do: ClientKeys.local_query(:public, local_users(users))
  def claim(users), do: ClientKeys.local_claim(:public, local_users(users))

  defp local_users(users) when is_map(users),
    do: Map.filter(users, fn {user, _} -> match?({:ok, _}, Identity.parse_user_id(user)) end)

  defp local_users(_), do: nil

  def remote(users, kind, request \\ &Transport.request/4) do
    groups =
      users
      |> Enum.flat_map(fn {user, selection} ->
        case Event.user_domain(user) do
          {:ok, server} ->
            if(server != Identity.homeserver_domain(),
              do: [{server, {user, selection}}],
              else: []
            )

          _ ->
            []
        end
      end)
      |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))

    Enum.reduce(groups, %{"failures" => %{}}, fn {server, entries}, acc ->
      requested = Map.new(entries)
      path = "/_matrix/federation/v1/user/keys/" <> kind
      field = if kind == "query", do: "device_keys", else: "one_time_keys"
      body = %{field => requested}

      case request.(:post, server, path, body) do
        {:ok, response} when is_map(response) ->
          case sanitize(response, requested, kind) do
            {:ok, clean} ->
              if kind == "query", do: remember(clean)
              merge(acc, clean)

            _ ->
              put_in(acc, ["failures", server], %{
                "status" => 502,
                "message" => "Invalid key response"
              })
          end

        _ ->
          put_in(acc, ["failures", server], %{
            "status" => 503,
            "message" => "Homeserver unavailable"
          })
      end
    end)
  end

  defp remember(response) do
    Repo.transaction(fn ->
      LakehouseMatrix.ClientStore.lock!()

      for {user, master} <- response["master_keys"] || %{} do
        old =
          Repo.one(
            from u in "matrix_remote_users",
              where: u.user_id == ^user,
              select: %{master: u.master_key, self: u.self_signing_key}
          )

        self_key = response["self_signing_keys"][user]

        if is_nil(old) or old.master != master or (self_key && old.self != self_key) do
          values = [master_key: master] ++ if self_key, do: [self_signing_key: self_key], else: []

          Repo.insert_all(
            "matrix_remote_users",
            [%{user_id: user, master_key: master, self_signing_key: self_key, valid: false}],
            on_conflict: [set: values],
            conflict_target: [:user_id]
          )
        end
      end
    end)
  end

  def merge(left, right), do: Map.merge(left, right, fn _, a, b -> Map.merge(a, b) end)

  defp sanitize(response, requested, "query") do
    devices = if is_map(response["device_keys"]), do: response["device_keys"], else: %{}

    devices =
      for {user, selection} <- requested, is_map(devices[user]), into: %{} do
        selected =
          for {device, key} <- devices[user],
              is_binary(device),
              is_map(key),
              key["user_id"] == user and key["device_id"] == device,
              is_map(key["keys"]) and is_list(key["algorithms"]) and
                (selection == [] or device in selection),
              into: %{},
              do: {device, key}

        {user, selected}
      end

    result = %{"device_keys" => devices}

    result =
      Enum.reduce(
        [{"master_keys", "master"}, {"self_signing_keys", "self_signing"}],
        result,
        fn {field, usage}, acc ->
          values = if is_map(response[field]), do: response[field], else: %{}

          keys =
            for {user, key} <- values,
                Map.has_key?(requested, user),
                CrossSigning.valid?(key, user, usage),
                into: %{},
                do: {user, key}

          Map.put(acc, field, keys)
        end
      )

    {:ok, result}
  end

  defp sanitize(response, requested, "claim") do
    keys = response["one_time_keys"]

    if is_map(keys) do
      clean =
        for {user, devices} <- requested, is_map(keys[user]), into: %{} do
          selected =
            for {device, algorithm} <- devices,
                value = keys[user][device],
                is_map(value),
                map_size(value) == 1,
                into: %{} do
              {id, key} = Enum.at(value, 0)

              {device,
               if(
                 is_binary(id) and String.starts_with?(id, algorithm <> ":") and
                   (is_binary(key) or is_map(key)),
                 do: value,
                 else: %{}
               )}
            end

          {user, Map.reject(selected, fn {_, value} -> value == %{} end)}
        end

      {:ok, %{"one_time_keys" => clean}}
    else
      {:error, :invalid_peer_response}
    end
  end

  defp destinations(user) do
    servers =
      for room <- Edus.shared_rooms(user),
          {{"m.room.member", member}, event} <- RoomAccess.state(room),
          event["content"]["membership"] == "join",
          {:ok, server} <- [Event.user_domain(member)],
          server != Identity.homeserver_domain(),
          RoomAccess.allowed?(room, server),
          do: server

    Enum.uniq(servers)
  end

  defp maybe_put(map, _, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
