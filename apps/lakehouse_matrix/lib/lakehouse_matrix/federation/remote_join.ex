defmodule LakehouseMatrix.Federation.RemoteJoin do
  @moduledoc "Join a remote room only after verifying the resident's signed state and complete auth chain."
  import Ecto.Query
  alias LakehouseIam.{IAM, Repo}
  alias LakehouseMatrix.{ClientStore, Identity, Memberships, Rooms}
  alias LakehouseMatrix.Federation.{Invites, Keyring, RoomAccess, Signing, Transport}
  alias LakehouseMatrix.Protocol.{Event, Graph, Import}

  def join(
        principal,
        ref,
        servers \\ [],
        params \\ %{},
        request \\ &Transport.request/4,
        lookup \\ &Keyring.key/3
      ) do
    with true <- IAM.can?(principal, "matrix.room.join", nil),
         {:ok, ref, servers} <- resolve(ref, servers, request),
         true <- is_binary(ref) and String.starts_with?(ref, "!") and byte_size(ref) <= 255 do
      account = Repo.get!(LakehouseIam.Schema.Principal, principal)
      user = account.username |> Identity.user_id()

      params =
        Map.put(params, "_local_profile", LakehouseMatrix.ClientProfiles.membership(account))

      metadata = Graph.room_by_id(ref)
      pending = metadata && Invites.pending(metadata.local_room_id, user)

      known =
        if metadata do
          for {{"m.room.member", member}, event} <- RoomAccess.state(metadata),
              event["content"]["membership"] == "join",
              {:ok, server} <- [Event.user_domain(member)],
              server != Identity.homeserver_domain(),
              do: server
        else
          []
        end

      servers =
        Enum.uniq(if(pending, do: [pending.origin], else: []) ++ servers ++ known)
        |> Enum.filter(
          &(is_binary(&1) and &1 != Identity.homeserver_domain() and
              match?({:ok, _}, Transport.server_name(&1)))
        )
        |> Enum.take(10)

      if metadata && Memberships.joined?(metadata.local_room_id, principal) do
        {:ok, %{"room_id" => ref}}
      else
        Enum.reduce_while(servers, {:error, :unavailable}, fn server, _ ->
          case through(server, ref, user, params, request, lookup) do
            {:ok, _} = result -> {:halt, result}
            error -> {:cont, error}
          end
        end)
      end
    else
      {:error, _} = error -> error
      _ -> {:error, :forbidden}
    end
  end

  defp through(server, ref, user, params, request, lookup) do
    path =
      "/_matrix/federation/v1/make_join/" <>
        escape(ref) <> "/" <> escape(user) <> "?ver=11&ver=12"

    with {:ok, response} <- request.(:get, server, path, nil),
         version when version in ["11", "12"] <- response["room_version"],
         template when is_map(template) <- response["event"],
         true <- is_map(template["content"]),
         true <-
           template["room_id"] == ref and template["sender"] == user and
             template["state_key"] == user and
             template["type"] == "m.room.member" and
             get_in(template, ["content", "membership"]) == "join",
         {:ok, seed, key} <- Signing.config(),
         template <-
           template
           |> Map.put("origin_server_ts", System.system_time(:millisecond))
           |> join_content(params),
         event <- Event.sign(template, version, seed, key, Identity.homeserver_domain()),
         :ok <- Event.validate(event, version),
         id <- Event.id(event, version),
         {:ok, joined} <-
           request.(
             :put,
             server,
             "/_matrix/federation/v2/send_join/" <> escape(ref) <> "/" <> escape(id),
             event
           ),
         returned <- joined["event"] || event,
         true <- Event.id(returned, version) == id,
         {:ok, snapshot} <-
           Import.snapshot(ref, version, returned, joined["state"], joined["auth_chain"], lookup) do
      before_state = Map.new(snapshot.state, fn {key, id} -> {key, snapshot.graph[id]} end)
      signed = LakehouseMatrix.Protocol.Policy.recover(snapshot.event, before_state, version)

      snapshot = %{
        snapshot
        | event: signed,
          graph: Map.put(snapshot.graph, signed["event_id"], signed)
      }

      Repo.transaction(fn ->
        ClientStore.lock!()
        metadata = Graph.room_by_id(ref)
        local_id = if metadata, do: metadata.local_room_id, else: create_record(snapshot)

        case Graph.install_snapshot(local_id, ref, version, snapshot, :join) do
          {:ok, _} ->
            Repo.delete_all(
              from i in "matrix_pending_invites",
                where: i.local_room_id == type(^local_id, :binary_id) and i.user_id == ^user
            )

            %{"room_id" => ref}

          {:error, reason} ->
            Repo.rollback(reason)
        end
      end)
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_room_snapshot}
    end
  rescue
    _ -> {:error, :invalid_room_snapshot}
  end

  defp resolve("#" <> alias_name = ref, _, request) do
    with [local, server] when local != "" <- String.split(alias_name, ":", parts: 2),
         {:ok, _} <- Transport.server_name(server),
         {:ok, response} <-
           request.(
             :get,
             server,
             "/_matrix/federation/v1/query/directory?room_alias=" <> URI.encode_www_form(ref),
             nil
           ),
         room when is_binary(room) <- response["room_id"],
         servers when is_list(servers) <- response["servers"] do
      {:ok, room, [server | Enum.take(servers, 20)]}
    else
      _ -> {:error, :not_found}
    end
  end

  defp resolve(ref, servers, _) when is_binary(ref) and is_list(servers) do
    inferred =
      case String.split(ref, ":", parts: 2) do
        ["!" <> _, server] -> [server]
        _ -> []
      end

    {:ok, ref, Enum.take(servers, 20) ++ inferred}
  end

  defp resolve(_, _, _), do: {:error, :invalid_param}

  defp join_content(event, params) do
    content =
      Map.drop(event["content"], ~w(displayname avatar_url))
      |> Map.merge(params["_local_profile"] || %{})

    event = Map.put(event, "content", content)

    if is_binary(params["reason"]),
      do: put_in(event, ["content", "reason"], params["reason"]),
      else: event
  end

  defp create_record(snapshot) do
    name = get_in(snapshot.graph, [snapshot.state[{"m.room.name", ""}], "content", "name"])
    name = if is_binary(name) and name != "", do: String.slice(name, 0, 255), else: "Room"
    {:ok, room} = Rooms.create_room_record(%{name: name})
    room.id
  end

  defp escape(value), do: URI.encode(value, &URI.char_unreserved?/1)
end
