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
      device = params["device_id"] || String.slice(random(), 0, 12)

      if is_binary(device) and byte_size(device) in 1..255 and
           (is_nil(params["initial_device_display_name"]) or
              is_binary(params["initial_device_display_name"])) do
        token = "mtx_" <> random()

        Repo.transaction(fn ->
          lock!()

          existing =
            Repo.one(
              from d in "matrix_devices",
                where: d.principal_id == type(^p.id, :binary_id) and d.device_id == ^device,
                select: d.id
            )

          if is_nil(existing) do
            Repo.insert_all("matrix_devices", [
              %{
                principal_id: dump_id(p.id),
                device_id: device,
                display_name: params["initial_device_display_name"],
                keys: %{},
                inserted_at: now(),
                updated_at: now()
              }
            ])
          end

          Repo.insert_all("matrix_sessions", [
            %{
              principal_id: dump_id(p.id),
              device_id: device,
              token_hash: hash(token),
              expires_at: DateTime.add(now(), 90, :day),
              inserted_at: now()
            }
          ])

          %{
            "user_id" => Identity.user_id(p.username),
            "device_id" => device,
            "access_token" => token,
            "home_server" => Identity.homeserver_domain(),
            "well_known" => %{
              "m.homeserver" => %{"base_url" => LakehouseIam.Discovery.public_url()}
            }
          }
        end)
      else
        {:error, :invalid_param}
      end
    else
      _ -> {:error, :invalid_credentials}
    end
  end

  def authenticate("mtx_" <> _ = token) do
    digest = hash(token)

    case Repo.one(
           from s in "matrix_sessions",
             join: p in LakehouseIam.Schema.Principal,
             on: s.principal_id == p.id,
             where: s.token_hash == ^digest and s.expires_at > ^now() and p.active == true,
             select: {p, s.device_id, s.id}
         ) do
      {p, device, id} -> {:ok, p, device, id}
      _ -> :error
    end
  end

  def authenticate(_), do: :error

  def logout(principal, device, all \\ false) do
    query = from s in "matrix_sessions", where: s.principal_id == type(^principal, :binary_id)
    Repo.delete_all(if all, do: query, else: from(s in query, where: s.device_id == ^device))
    %{}
  end

  def devices(principal) do
    Repo.all(
      from d in "matrix_devices",
        where: d.principal_id == type(^principal, :binary_id),
        select: %{device_id: d.device_id, display_name: d.display_name}
    )
  end

  def update_device(principal, device, name) when is_binary(name) do
    Repo.transaction(fn ->
      lock!()

      {count, _} =
        Repo.update_all(
          from(d in "matrix_devices",
            where: d.principal_id == type(^principal, :binary_id) and d.device_id == ^device
          ),
          set: [display_name: name, updated_at: now()]
        )

      if count > 0, do: %{}, else: Repo.rollback(:not_found)
    end)
  end

  def update_device(_, _, _), do: {:error, :invalid_param}

  def account_data(principal, room \\ "", since \\ 0, upto \\ nil) do
    upto = upto || position()

    Repo.all(
      from a in "matrix_account_data",
        where:
          a.principal_id == type(^principal, :binary_id) and
            a.room_id == ^room and a.stream_id > ^since and a.stream_id <= ^upto,
        select: %{"type" => a.type, "content" => a.content}
    )
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

  def put_data(principal, room, type, content) when is_map(content) do
    Repo.insert_all(
      "matrix_account_data",
      [%{principal_id: dump_id(principal), room_id: room, type: type, content: content}],
      on_conflict: [set: [content: content]],
      conflict_target: [:principal_id, :room_id, :type]
    )

    {:ok, %{}}
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
    Repo.transaction(fn ->
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
      when is_map(messages) and map_size(messages) <= 100 do
    transaction(principal, device, "to_device", txn, fn ->
      Enum.each(messages, fn {mxid, targets} ->
        with {:ok, local} <- Identity.parse_user_id(mxid),
             {:ok, p} <- Accounts.fetch_user(local),
             true <- is_map(targets) and map_size(targets) <= 100 do
          Enum.each(targets, fn {target, content} ->
            unless is_map(content) and byte_size(Jason.encode!(content)) <= 65_536,
              do: Repo.rollback(:invalid_param)

            query = from d in "matrix_devices", where: d.principal_id == type(^p.id, :binary_id)

            query =
              if target == "*", do: query, else: from(d in query, where: d.device_id == ^target)

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
          end)
        else
          _ -> Repo.rollback(:invalid_param)
        end
      end)

      {:ok, %{}}
    end)
  end

  def send_to_device(_, _, _, _, _, _), do: {:error, :invalid_param}

  def dump_id(id), do: Ecto.UUID.dump!(id)
end
