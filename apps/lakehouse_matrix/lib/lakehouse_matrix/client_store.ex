defmodule LakehouseMatrix.ClientStore do
  @moduledoc "Persistent device and user state shared by legacy and sliding sync."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseMatrix.Identity

  def now, do: DateTime.utc_now()
  def position, do: Repo.one(from s in "matrix_stream", where: s.id == 1, select: s.position)

  def lock!,
    do:
      Repo.one(
        from s in "matrix_stream", where: s.id == 1, lock: "FOR UPDATE", select: s.position
      )

  def room_forgotten?(principal, room, high \\ position()) do
    Repo.one(
      from f in "matrix_room_forgetting",
        where:
          f.principal_id == type(^principal, :binary_id) and
            f.local_room_id == type(^room, :binary_id) and f.stream_id <= ^high,
        order_by: [desc: f.stream_id],
        limit: 1,
        select: f.forgotten
    ) == true
  end

  def restore_room!(principal, room) do
    if room_forgotten?(principal, room),
      do:
        Repo.insert_all("matrix_room_forgetting", [
          %{principal_id: dump_id(principal), local_room_id: dump_id(room), forgotten: false}
        ])

    :ok
  end

  def hash(value), do: :crypto.hash(:sha256, value)
  def random, do: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

  def login(username, password, params) do
    username =
      case Identity.parse_user_id(username) do
        {:ok, local} ->
          local

        _ ->
          if is_binary(username) and not String.starts_with?(username, "@"),
            do: Accounts.normalize_username(username)
      end

    with true <- is_binary(username) and is_binary(password),
         {:ok, p} <- Accounts.fetch_user(username),
         true <- Accounts.password_valid?(username, password),
         true <- Accounts.active?(p) do
      LakehouseMatrix.ClientLogin.open(p, params)
    else
      _ -> {:error, :invalid_credentials}
    end
  end

  def authenticate(token), do: LakehouseMatrix.ClientLogin.authenticate(token)

  def logout(principal, device, all \\ false) do
    devices = if all, do: Enum.map(devices(principal), & &1.device_id), else: [device]

    {:ok, result} =
      LakehouseMatrix.Protocol.Policy.transaction(fn ->
        lock!()

        for batch <- Enum.chunk_every(devices, 100) do
          case delete_devices(principal, batch) do
            {:ok, _} -> :ok
            {:error, reason} -> Repo.rollback(reason)
          end
        end

        %{}
      end)

    result
  end

  def delete_devices(principal, devices) when is_list(devices) and length(devices) <= 100 do
    if Enum.all?(devices, &(is_binary(&1) and byte_size(&1) in 1..255)) do
      LakehouseMatrix.Protocol.Policy.transaction(fn ->
        lock!()

        for device <- Enum.uniq(devices) do
          Repo.delete_all(
            from p in "matrix_pushers",
              where: p.principal_id == type(^principal, :binary_id) and p.device_id == ^device
          )

          Repo.delete_all(
            from t in "matrix_login_tokens",
              where: t.principal_id == type(^principal, :binary_id) and t.source_device == ^device
          )

          {removed, _} =
            Repo.delete_all(
              from d in "matrix_devices",
                where: d.principal_id == type(^principal, :binary_id) and d.device_id == ^device
            )

          for table <-
                ~w(matrix_sessions matrix_to_device matrix_one_time_keys matrix_sync_connections matrix_hierarchy_cursors matrix_transactions) do
            Repo.delete_all(
              from row in table,
                where:
                  row.principal_id == type(^principal, :binary_id) and row.device_id == ^device
            )
          end

          if removed > 0,
            do: LakehouseMatrix.Federation.DeviceKeys.changed!(principal, device, true)
        end

        %{}
      end)
    else
      {:error, :invalid_param}
    end
  end

  def delete_devices(_, _), do: {:error, :invalid_param}

  def devices(principal) do
    Repo.all(
      from d in "matrix_devices",
        where: d.principal_id == type(^principal, :binary_id),
        select: %{device_id: d.device_id, display_name: d.display_name}
    )
  end

  def update_device(principal, device, name) when is_binary(name) or is_nil(name) do
    LakehouseMatrix.Protocol.Policy.transaction(fn ->
      lock!()

      {count, _} =
        Repo.update_all(
          from(d in "matrix_devices",
            where: d.principal_id == type(^principal, :binary_id) and d.device_id == ^device
          ),
          set: [display_name: name, updated_at: now()]
        )

      if count > 0 do
        LakehouseMatrix.Federation.DeviceKeys.changed!(principal, device)
        %{}
      else
        Repo.rollback(:not_found)
      end
    end)
  end

  def update_device(_, _, _), do: {:error, :invalid_param}

  def account_data(principal, room \\ "", since \\ 0, upto \\ nil) do
    upto = upto || position()

    events =
      Repo.all(
        from a in "matrix_account_data",
          where:
            a.principal_id == type(^principal, :binary_id) and
              a.room_id == ^room and a.stream_id > ^since and a.stream_id <= ^upto,
          select: %{"type" => a.type, "content" => a.content}
      )

    if room == "" and since == 0 and not Enum.any?(events, &(&1["type"] == "m.push_rules")),
      do:
        events ++
          [%{"type" => "m.push_rules", "content" => LakehouseMatrix.PushRules.get(principal)}],
      else: events
  end

  def get_data(principal, room, type) do
    Repo.one(
      from a in "matrix_account_data",
        where:
          a.principal_id == type(^principal, :binary_id) and a.room_id == ^room and
            a.type == ^type,
        select: a.content
    )
  end

  def create_filter(principal, content) do
    Repo.transaction(fn ->
      lock!()
      LakehouseMatrix.AccountModeration.require!(principal, :read)

      {1, [row]} =
        Repo.insert_all("matrix_filters", [%{principal_id: dump_id(principal), content: content}],
          returning: [:id]
        )

      %{"filter_id" => to_string(row.id)}
    end)
  end

  def put_data(principal, room, type, content) when is_map(content) do
    Repo.transaction(fn ->
      lock!()
      LakehouseMatrix.AccountModeration.require!(principal, :read)

      Repo.insert_all(
        "matrix_account_data",
        [%{principal_id: dump_id(principal), room_id: room, type: type, content: content}],
        on_conflict: [set: [content: content]],
        conflict_target: [:principal_id, :room_id, :type]
      )

      %{}
    end)
  end

  def link_direct(first, second, room) do
    for {owner, peer} <- [{first, second}, {second, first}] do
      mxid = Repo.get!(LakehouseIam.Schema.Principal, peer).username |> Identity.user_id()
      data = get_data(owner, "", "m.direct") || %{}
      rooms = if is_list(data[mxid]), do: data[mxid], else: []
      put_data(owner, "", "m.direct", Map.put(data, mxid, Enum.uniq([room | rooms])))
    end

    :ok
  end

  def transaction(principal, device, scope, txn, callback)
      when is_binary(txn) and byte_size(txn) in 1..255 do
    LakehouseMatrix.Protocol.Policy.transaction(fn ->
      lock!()

      existing =
        Repo.one(
          from t in "matrix_transactions",
            where:
              t.principal_id == type(^principal, :binary_id) and t.device_id == ^device and
                t.scope == ^scope and t.txn_id == ^txn,
            select: t.response
        )

      existing ||
        case callback.() do
          {:ok, response} ->
            Repo.insert_all("matrix_transactions", [
              %{
                principal_id: dump_id(principal),
                device_id: device,
                scope: scope,
                txn_id: txn,
                response: response
              }
            ])

            response

          {:error, reason} ->
            Repo.rollback(reason)
        end
    end)
  end

  def transaction(_, _, _, _, _), do: {:error, :invalid_param}

  def to_device(principal, device, since, upto) do
    Repo.all(
      from t in "matrix_to_device",
        where:
          t.principal_id == type(^principal, :binary_id) and
            t.device_id == ^device and t.stream_id > ^since and t.stream_id <= ^upto,
        order_by: t.stream_id,
        limit: 100,
        select: %{"type" => t.type, "sender" => t.sender, "content" => t.content}
    )
  end

  def device_batch(principal, device, since, upto) do
    rows =
      Repo.all(
        from t in "matrix_to_device",
          where:
            t.principal_id == type(^principal, :binary_id) and
              t.device_id == ^device and t.stream_id > ^since and t.stream_id <= ^upto,
          order_by: t.stream_id,
          limit: 101,
          select: %{position: t.stream_id, type: t.type, sender: t.sender, content: t.content}
      )

    position = if length(rows) > 100, do: Enum.at(rows, 99).position, else: upto

    events =
      rows
      |> Enum.take(100)
      |> Enum.map(&%{"type" => &1.type, "sender" => &1.sender, "content" => &1.content})

    {events, position}
  end

  def acknowledge(principal, device, position) do
    Repo.delete_all(
      from t in "matrix_to_device",
        where:
          t.principal_id == type(^principal, :binary_id) and t.device_id == ^device and
            t.stream_id <= ^position
    )
  end

  def send_to_device(principal, device, username, type, txn, messages)
      when is_map(messages) and map_size(messages) <= 100 and is_binary(type) and
             byte_size(type) in 1..255 do
    transaction(principal, device, "to_device", txn, fn ->
      remote =
        Enum.reduce(messages, %{}, fn {mxid, targets}, grouped ->
          unless match?({:ok, _}, LakehouseMatrix.Protocol.Event.user_domain(mxid)) and
                   is_map(targets) and map_size(targets) <= 100 and
                   Enum.all?(targets, fn {target, content} ->
                     is_binary(target) and byte_size(target) in 1..255 and is_map(content) and
                       byte_size(Jason.encode!(content)) <= 65_536
                   end),
                 do: Repo.rollback(:invalid_param)

          case Identity.parse_user_id(mxid) do
            {:ok, local} ->
              with {:ok, p} <- Accounts.fetch_user(local) do
                for {target, content} <- targets do
                  query =
                    from d in "matrix_devices", where: d.principal_id == type(^p.id, :binary_id)

                  query =
                    if target == "*",
                      do: query,
                      else: from(d in query, where: d.device_id == ^target)

                  for target_device <- Repo.all(from d in query, select: d.device_id) do
                    Repo.insert_all("matrix_to_device", [
                      %{
                        principal_id: dump_id(p.id),
                        device_id: target_device,
                        type: type,
                        sender: Identity.user_id(username),
                        content: content
                      }
                    ])
                  end
                end
              end

              grouped

            _ ->
              {:ok, server} = LakehouseMatrix.Protocol.Event.user_domain(mxid)

              unless match?({:ok, _}, LakehouseMatrix.Federation.Transport.server_name(server)),
                do: Repo.rollback(:invalid_param)

              Map.update(grouped, server, %{mxid => targets}, &Map.put(&1, mxid, targets))
          end
        end)

      for {server, targets} <- remote do
        LakehouseMatrix.Federation.Edus.outgoing!(server, "m.direct_to_device", %{
          "sender" => Identity.user_id(username),
          "type" => type,
          "message_id" => random(),
          "messages" => targets
        })
      end

      {:ok, %{}}
    end)
  end

  def send_to_device(_, _, _, _, _, _), do: {:error, :invalid_param}

  def dump_id(id), do: Ecto.UUID.dump!(id)
end
