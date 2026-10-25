defmodule LakehouseMatrix.KeyBackups do
  @moduledoc "Account-private, versioned backups of client-encrypted Megolm session data."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.ClientStore

  def create(principal, params) do
    transact(fn ->
      validate_metadata!(params)

      {1, [%{id: id}]} =
        Repo.insert_all(
          "matrix_key_backups",
          [
            %{
              principal_id: ClientStore.dump_id(principal),
              algorithm: params["algorithm"],
              auth_data: params["auth_data"]
            }
          ],
          returning: [:id]
        )

      %{"version" => to_string(id)}
    end)
  end

  def version(principal, version \\ nil),
    do: transact(fn -> metadata(backup!(principal, version)) end)

  def update(principal, version, params) do
    transact(fn ->
      validate_metadata!(params)
      backup = backup!(principal, version)

      unless params["algorithm"] == backup.algorithm and
               (is_nil(params["version"]) or params["version"] == version),
             do: Repo.rollback(:invalid_param)

      Repo.update_all(from(b in "matrix_key_backups", where: b.id == ^backup.id),
        set: [auth_data: params["auth_data"]]
      )

      %{}
    end)
  end

  def delete_version(principal, version),
    do:
      transact(fn ->
        case Integer.parse(version) do
          {id, ""} when id > 0 and id <= 9_223_372_036_854_775_807 ->
            Repo.delete_all(
              from b in "matrix_key_backups",
                where: b.principal_id == type(^principal, :binary_id) and b.id == ^id
            )

          _ ->
            :ok
        end

        %{}
      end)

  def get(principal, version, room \\ nil, session \\ nil) do
    transact(fn ->
      backup = backup!(principal, version)

      rows =
        Repo.all(
          selection(backup.id, room, session)
          |> select([s], {s.room_id, s.session_id, s.data})
        )

      cond do
        session ->
          case rows do
            [{_, _, data}] -> data
            _ -> Repo.rollback(:not_found)
          end

        room ->
          %{"sessions" => Map.new(rows, fn {_, id, data} -> {id, data} end)}

        true ->
          %{
            "rooms" =>
              Enum.reduce(rows, %{}, fn {room, id, data}, acc ->
                Map.update(acc, room, %{"sessions" => %{id => data}}, fn value ->
                  update_in(value, ["sessions"], &Map.put(&1, id, data))
                end)
              end)
          }
      end
    end)
  end

  def put(principal, version, params, room \\ nil, session \\ nil) do
    transact(fn ->
      latest = backup!(principal, nil)

      if to_string(latest.id) != version,
        do: Repo.rollback({:wrong_backup_version, to_string(latest.id)})

      backup = latest
      entries = entries!(params, room, session)
      if length(entries) > 1000, do: Repo.rollback(:limit_exceeded)

      changed =
        Enum.reduce(entries, 0, fn {ref, id, data}, changed ->
          unless identifier?(ref) and String.starts_with?(ref, "!") and identifier?(id) and
                   valid_data?(data),
                 do: Repo.rollback(:invalid_param)

          old =
            Repo.one(
              from s in "matrix_backup_sessions",
                where: s.backup_id == ^backup.id and s.room_id == ^ref and s.session_id == ^id,
                select: s.data
            )

          if is_nil(old) or quality(data) < quality(old) do
            Repo.insert_all(
              "matrix_backup_sessions",
              [%{backup_id: backup.id, room_id: ref, session_id: id, data: data}],
              on_conflict: [set: [data: data]],
              conflict_target: [:backup_id, :room_id, :session_id]
            )

            changed + 1
          else
            changed
          end
        end)

      if changed > 0,
        do:
          Repo.update_all(from(b in "matrix_key_backups", where: b.id == ^backup.id),
            inc: [etag: 1]
          )

      %{
        "etag" => to_string(backup.etag + if(changed > 0, do: 1, else: 0)),
        "count" => count(backup.id)
      }
    end)
  end

  def delete(principal, version, room \\ nil, session \\ nil),
    do:
      transact(fn ->
        backup = backup!(principal, version)
        {changed, _} = Repo.delete_all(selection(backup.id, room, session))

        if changed > 0,
          do:
            Repo.update_all(from(b in "matrix_key_backups", where: b.id == ^backup.id),
              inc: [etag: 1]
            )

        %{
          "etag" => to_string(backup.etag + if(changed > 0, do: 1, else: 0)),
          "count" => count(backup.id)
        }
      end)

  defp entries!(data, room, session) do
    cond do
      session ->
        [{room, session, data}]

      room ->
        unless is_map(data["sessions"]) and map_size(data["sessions"]) <= 1000,
          do: Repo.rollback(:invalid_param)

        Enum.map(data["sessions"], fn {id, value} -> {room, id, value} end)

      true ->
        unless is_map(data["rooms"]) and map_size(data["rooms"]) <= 1000,
          do: Repo.rollback(:invalid_param)

        Enum.flat_map(data["rooms"], fn {room, value} ->
          unless is_map(value), do: Repo.rollback(:invalid_param)
          entries!(value, room, nil)
        end)
    end
  end

  defp backup!(principal, version) do
    query =
      from b in "matrix_key_backups",
        where: b.principal_id == type(^principal, :binary_id),
        order_by: [desc: b.id],
        limit: 1,
        select: %{id: b.id, algorithm: b.algorithm, auth_data: b.auth_data, etag: b.etag}

    query =
      if version do
        id =
          case Integer.parse(version) do
            {id, ""} when id > 0 and id <= 9_223_372_036_854_775_807 -> id
            _ -> Repo.rollback(:not_found)
          end

        from b in query, where: b.id == ^id
      else
        query
      end

    Repo.one(query) || Repo.rollback(:not_found)
  end

  defp metadata(backup),
    do: %{
      "algorithm" => backup.algorithm,
      "auth_data" => backup.auth_data,
      "version" => to_string(backup.id),
      "etag" => to_string(backup.etag),
      "count" => count(backup.id)
    }

  defp count(id),
    do: Repo.aggregate(from(s in "matrix_backup_sessions", where: s.backup_id == ^id), :count)

  defp selection(id, room, session) do
    query = from s in "matrix_backup_sessions", where: s.backup_id == ^id
    query = if room, do: from(s in query, where: s.room_id == ^room), else: query
    if session, do: from(s in query, where: s.session_id == ^session), else: query
  end

  defp valid_data?(data) when is_map(data),
    do:
      is_integer(data["first_message_index"]) and data["first_message_index"] >= 0 and
        is_integer(data["forwarded_count"]) and data["forwarded_count"] >= 0 and
        is_boolean(data["is_verified"]) and
        is_map(data["session_data"]) and byte_size(Jason.encode!(data)) <= 65_536

  defp valid_data?(_), do: false

  defp quality(data),
    do:
      {if(data["is_verified"], do: 0, else: 1), data["first_message_index"],
       data["forwarded_count"]}

  defp validate_metadata!(params) do
    unless is_binary(params["algorithm"]) and byte_size(params["algorithm"]) in 1..255 and
             is_map(params["auth_data"]) and
             byte_size(Jason.encode!(params["auth_data"])) <= 65_536,
           do: Repo.rollback(:invalid_param)
  end

  defp identifier?(value), do: is_binary(value) and byte_size(value) in 1..255

  defp transact(fun),
    do:
      Repo.transaction(fn ->
        ClientStore.lock!()
        fun.()
      end)
end
