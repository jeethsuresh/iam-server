defmodule LakehouseMatrix.Directory do
  @moduledoc "Local aliases and an explicitly published, paginated Matrix room directory."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientRooms, ClientStore, Cursor, Identity, Memberships, Rooms}
  alias LakehouseMatrix.Protocol.{Authorization, Event, Graph, Policy}
  alias LakehouseMatrix.Federation.{RoomAccess, Transport}

  def parse("#" <> rest = ref) when byte_size(ref) <= 255 do
    case String.split(rest, ":", parts: 2) do
      [name, server] when name != "" ->
        if String.valid?(name) and not String.contains?(name, "\x00") and
             match?({:ok, _}, Transport.server_name(server)),
           do: {:ok, name, server},
           else: {:error, :invalid_param}

      _ ->
        {:error, :invalid_param}
    end
  end

  def parse(_), do: {:error, :invalid_param}

  def resolve(ref) do
    with {:ok, name, server} <- parse(ref) do
      if server == Identity.homeserver_domain() do
        with {:ok, room} <- Rooms.get_room_by_alias(name) do
          {:ok, %{"room_id" => Identity.room_id(room.id), "servers" => servers(room.id)}}
        else
          _ -> {:error, :not_found}
        end
      else
        with {:ok, body} <-
               Transport.request(
                 :get,
                 server,
                 "/_matrix/federation/v1/query/directory?room_alias=" <> URI.encode_www_form(ref),
                 nil
               ),
             true <- valid_resolution?(body) do
          {:ok, Map.take(body, ["room_id", "servers"])}
        else
          _ -> {:error, :not_found}
        end
      end
    end
  end

  def register(principal, room, name) do
    {count, _} =
      Repo.insert_all(
        "matrix_room_aliases",
        [
          %{
            name: name,
            local_room_id: ClientStore.dump_id(room),
            creator_id: ClientStore.dump_id(principal)
          }
        ],
        on_conflict: :nothing
      )

    if count == 1, do: {:ok, %{}}, else: {:error, :alias_in_use}
  end

  def put(principal, ref, room_ref) do
    with {:ok, name, server} <- parse(ref),
         true <- server == Identity.homeserver_domain(),
         {:ok, room} <- ClientRooms.readable(principal, room_ref) do
      Policy.transaction(fn ->
        ClientStore.lock!()

        case register(principal, room.id, name) do
          {:ok, result} -> result
          {:error, reason} -> Repo.rollback(reason)
        end
      end)
    else
      {:error, _} = error -> error
      _ -> {:error, :forbidden}
    end
  end

  def delete(principal, ref) do
    with {:ok, name, server} <- parse(ref), true <- server == Identity.homeserver_domain() do
      Policy.transaction(fn ->
        ClientStore.lock!()

        row =
          Repo.one(
            from a in "matrix_room_aliases",
              where: a.name == ^name,
              select: %{room: a.local_room_id, creator: a.creator_id}
          ) || Repo.rollback(:not_found)

        room = Ecto.UUID.load!(row.room)

        unless row.creator == ClientStore.dump_id(principal) or manager?(principal, room),
          do: Repo.rollback(:forbidden)

        Repo.delete_all(from a in "matrix_room_aliases", where: a.name == ^name)

        Repo.update_all(
          from(r in LakehouseMatrix.Schema.Room, where: r.id == ^room and r.alias == ^name),
          set: [alias: nil]
        )

        %{}
      end)
    else
      {:error, _} = error -> error
      _ -> {:error, :forbidden}
    end
  end

  def aliases(principal, ref) do
    with {:ok, room} <- ClientRooms.room(ref),
         true <- Memberships.joined?(room.id, principal) or world_readable?(room.id) do
      names =
        Repo.all(
          from a in "matrix_room_aliases",
            where: a.local_room_id == type(^room.id, :binary_id),
            order_by: a.name,
            select: a.name
        )

      {:ok, %{"aliases" => Enum.map(names, &Identity.room_alias/1)}}
    else
      _ -> {:error, :forbidden}
    end
  end

  def visibility(ref) do
    with {:ok, room} <- ClientRooms.room(ref),
         do: {:ok, %{"visibility" => room.visibility}},
         else: (_ -> {:error, :not_found})
  end

  def visibility(principal, ref, visibility) when visibility in ["private", "public"] do
    Policy.transaction(fn ->
      ClientStore.lock!()

      room =
        case ClientRooms.room(ref) do
          {:ok, room} -> room
          _ -> Repo.rollback(:not_found)
        end

      unless manager?(principal, room.id), do: Repo.rollback(:forbidden)
      room |> Ecto.Changeset.change(visibility: visibility) |> Repo.update!()
      %{}
    end)
  end

  def visibility(_, _, _), do: {:error, :invalid_param}

  def public_rooms(params, origin \\ nil)

  def public_rooms(params, origin) when is_map(params) do
    filter = params["filter"] || %{}

    with true <- is_map(filter),
         term <- filter["generic_search_term"] || "",
         types <- filter["room_types"],
         true <-
           is_binary(term) and byte_size(term) <= 255 and
             (is_nil(types) or
                (is_list(types) and length(types) <= 100 and
                   Enum.all?(types, &(is_nil(&1) or is_binary(&1))))),
         true <-
           params["include_all_networks"] in [nil, true, false] and
             (is_nil(params["third_party_instance_id"]) or
                is_binary(params["third_party_instance_id"])),
         {:ok, limit} <- LakehouseMatrix.ClientSync.integer(params["limit"], 100, 1, 100),
         binding <-
           :crypto.hash(:sha256, LakehouseMatrix.Federation.Signing.canonical(filter))
           |> Base.url_encode64(padding: false),
         {:ok, offset} <- Cursor.decode(params["since"], "directory", origin || "", binding) do
      rows =
        Repo.all(
          from r in LakehouseMatrix.Schema.Room, where: r.visibility == "public", order_by: r.id
        )

      chunk =
        if params["third_party_instance_id"] not in [nil, ""],
          do: [],
          else: Enum.flat_map(rows, &public_room(&1, origin))

      term = String.downcase(term)

      chunk =
        Enum.filter(chunk, fn room ->
          (is_nil(types) or room["room_type"] in types) and
            Enum.any?(
              ~w(name topic canonical_alias),
              &String.contains?(String.downcase(room[&1] || ""), term)
            )
        end)

      result = %{
        "chunk" => Enum.slice(chunk, offset, limit),
        "total_room_count_estimate" => length(chunk)
      }

      result =
        if offset + limit < length(chunk),
          do:
            Map.put(
              result,
              "next_batch",
              Cursor.encode("directory", origin || "", binding, offset + limit)
            ),
          else: result

      result =
        if offset > 0,
          do:
            Map.put(
              result,
              "prev_batch",
              Cursor.encode("directory", origin || "", binding, max(offset - limit, 0))
            ),
          else: result

      {:ok, result}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_param}
    end
  end

  def public_rooms(_, _), do: {:error, :invalid_param}

  def client_public_rooms(params) do
    case params["server"] do
      server when server in [nil, ""] ->
        public_rooms(params)

      server when is_binary(server) ->
        if server == Identity.homeserver_domain() do
          public_rooms(params)
        else
          with {:ok, _} <- Transport.server_name(server),
               {:ok, body} <-
                 Transport.request(
                   :post,
                   server,
                   "/_matrix/federation/v1/publicRooms",
                   Map.take(
                     params,
                     ~w(limit since filter include_all_networks third_party_instance_id)
                   )
                 ),
               true <- is_map(body) and is_list(body["chunk"]) and length(body["chunk"]) <= 1000 do
            {:ok, body}
          else
            _ -> {:error, :unavailable}
          end
        end

      _ ->
        {:error, :invalid_param}
    end
  end

  defp public_room(room, origin) do
    case Graph.room(room.id) do
      nil ->
        []

      metadata ->
        state = RoomAccess.state(metadata)

        if is_nil(origin) or RoomAccess.allowed?(metadata, origin) do
          content = fn type -> get_in(state, [{type, ""}, "content"]) || %{} end

          result = %{
            "room_id" => metadata.room_id,
            "name" => text(content.("m.room.name")["name"]),
            "topic" => text(content.("m.room.topic")["topic"]),
            "avatar_url" => text(content.("m.room.avatar")["url"]),
            "canonical_alias" => text(content.("m.room.canonical_alias")["alias"]),
            "num_joined_members" =>
              Enum.count(state, fn {{type, _}, e} ->
                type == "m.room.member" and e["content"]["membership"] == "join"
              end),
            "world_readable" =>
              content.("m.room.history_visibility")["history_visibility"] == "world_readable",
            "guest_can_join" => content.("m.room.guest_access")["guest_access"] == "can_join",
            "join_rule" => content.("m.room.join_rules")["join_rule"] || "invite",
            "room_type" => text(content.("m.room.create")["type"])
          }

          [Map.reject(result, fn {_, value} -> is_nil(value) end)]
        else
          []
        end
    end
  end

  defp text(value), do: if(is_binary(value), do: value)

  defp manager?(principal, room) do
    case Graph.room(room) do
      nil ->
        false

      metadata ->
        state = RoomAccess.state(metadata)
        user = Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

        Authorization.membership(state, user) == "join" and
          Authorization.gte?(
            Authorization.power(state, user, metadata.version),
            Authorization.level(state, "state_default", 50)
          )
    end
  end

  defp world_readable?(room) do
    case Graph.room(room) do
      nil ->
        false

      metadata ->
        get_in(RoomAccess.state(metadata), [
          {"m.room.history_visibility", ""},
          "content",
          "history_visibility"
        ]) == "world_readable"
    end
  end

  defp servers(room) do
    case Graph.room(room) do
      nil ->
        [Identity.homeserver_domain()]

      metadata ->
        RoomAccess.state(metadata)
        |> Enum.flat_map(fn
          {{"m.room.member", user}, e} ->
            case Event.user_domain(user) do
              {:ok, server} -> if e["content"]["membership"] == "join", do: [server], else: []
              _ -> []
            end

          _ ->
            []
        end)
        |> Enum.uniq()
        |> Enum.take(20)
    end
  end

  defp valid_resolution?(body) when is_map(body) do
    is_binary(body["room_id"]) and String.starts_with?(body["room_id"], "!") and
      byte_size(body["room_id"]) <= 255 and
      is_list(body["servers"]) and length(body["servers"]) <= 100 and
      Enum.all?(body["servers"], &match?({:ok, _}, Transport.server_name(&1)))
  end

  defp valid_resolution?(_), do: false
end
