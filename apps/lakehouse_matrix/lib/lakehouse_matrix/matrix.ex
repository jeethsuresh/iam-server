defmodule LakehouseMatrix.Matrix do
  @moduledoc """
  Matrix Client-Server API operations (create/join/leave/send/sync).
  """
  require Logger

  alias LakehouseIam.{Accounts, IAM}
  alias LakehouseMatrix.{
    Events,
    Events.Context,
    Events.Processor,
    Identity,
    Memberships,
    Rooms,
    State,
    Sync
  }

  @spec login(String.t(), String.t()) ::
          {:ok, map()} | {:error, :invalid_credentials | :inactive}
  def login(username, password) do
    canonical = Accounts.normalize_username(username)

    case Accounts.fetch_user(canonical) do
      {:ok, principal} ->
        cond do
          not Accounts.password_valid?(canonical, password) ->
            {:error, :invalid_credentials}

          not Accounts.active?(principal) ->
            {:error, :inactive}

          true ->
            {:ok, session_for_principal(principal)}
        end

      :error ->
        {:error, :invalid_credentials}
    end
  end

  defp session_for_principal(principal) do
    token = LakehouseIam.Auth.Token.issue(principal.username)

    %{
      "user_id" => Identity.user_id(principal.username),
      "access_token" => token,
      "device_id" => "LAKEHOUSE_WEB",
      "home_server" => Identity.homeserver_domain()
    }
  end

  @spec create_room(Ecto.UUID.t(), map()) :: {:ok, map()} | {:error, term()}
  def create_room(principal_id, params) do
    if can_create?(principal_id) do
      with {:ok, principal} <- fetch_principal(principal_id),
           {:ok, room} <- Rooms.create_room_record(room_attrs(params)),
           :ok <- ensure_room_started(room),
           :ok <- emit_create_events(room, principal) do
        {:ok, %{"room_id" => Identity.room_id(room.id)}}
      end
    else
      {:error, :forbidden}
    end
  end

  # First-party Matrix membership mutations use the same row-locked policy as apps.
  def join_room(principal_id, room_ref) do
    with {:ok, room} <- resolve_room(room_ref) do
      if delegated?(room.id) do
        with {:ok, _} <- delegated_membership(principal_id, room.id, "accept"),
          do: {:ok, %{"room_id" => Identity.room_id(room.id)}}
      else
        legacy_join_room(principal_id, room_ref)
      end
    end
  end

  def leave_room(principal_id, room_ref) do
    with {:ok, room} <- resolve_room(room_ref) do
      if delegated?(room.id),
        do: delegated_membership(principal_id, room.id, "leave"),
        else: legacy_leave_room(principal_id, room_ref)
    end
  end

  def invite(actor, room_ref, username) when is_binary(username) do
    with {:ok, room} <- resolve_room(room_ref) do
      if delegated?(room.id),
        do: delegated_membership(actor, room.id, "invite", username),
        else: legacy_invite(actor, room_ref, username)
    end
  end

  def remove_member(actor, room_ref, username) when is_binary(username) do
    with {:ok, room} <- resolve_room(room_ref) do
      if delegated?(room.id),
        do: delegated_membership(actor, room.id, "remove", username),
        else: legacy_remove_member(actor, room_ref, username)
    end
  end

  def add_member(room_id, actor, username) when is_binary(username) do
    if delegated?(room_id) do
      # River requires the invitee to accept. The legacy add operation auto-joins.
      {:error, :forbidden}
    else
      legacy_add_member(room_id, actor, username)
    end
  end

  defp delegated_membership(principal, id, action, username \\ nil) do
    grant = %LakehouseIam.Schema.AppGrant{principal_id: principal,
      app_origin: "https://" <> Identity.homeserver_domain(),
      scopes: ["groups.manage"], room_mode: :all}
    params = %{"action" => action}
    params = if username, do: Map.put(params, "user_id", Identity.user_id(Accounts.normalize_username(username))), else: params
    LakehouseMatrix.DelegatedGroups.membership(grant, id, params)
  end

  @spec join_room(Ecto.UUID.t(), Ecto.UUID.t() | String.t()) :: {:ok, map()} | {:error, term()}
  defp legacy_join_room(principal_id, room_id_or_alias) do
    with {:ok, room} <- resolve_room(room_id_or_alias),
         {:ok, principal} <- fetch_principal(principal_id) do
      invited = Memberships.invited?(room.id, principal_id)
      allowed = if delegated?(room.id), do: invited, else: invited or can_join?(principal_id, room.id)

      if allowed do
        with :ok <- ensure_room_started(room),
             {:ok, _} <- emit_member_event(room.id, principal, "join", principal) do
          {:ok, %{"room_id" => Identity.room_id(room.id)}}
        end
      else
        {:error, :forbidden}
      end
    end
  end

  @doc """
  Invite a user to a room (`m.room.member` with membership `invite`).
  """
  @spec invite(Ecto.UUID.t(), Ecto.UUID.t() | String.t(), String.t()) ::
          {:ok, map()} | {:error, term()}
  defp legacy_invite(actor_principal_id, room_id_or_alias, username) when is_binary(username) do
    canonical = Accounts.normalize_username(username)

    with {:ok, room} <- resolve_room(room_id_or_alias),
         {:ok, actor} <- fetch_principal(actor_principal_id),
         {:ok, target} <- fetch_active_user(canonical) do
      cond do
        not Memberships.joined?(room.id, actor_principal_id) ->
          {:error, :forbidden}

        delegated?(room.id) and not creator?(room.id, actor_principal_id) ->
          {:error, :forbidden}

        target.id == actor.id ->
          {:error, :cannot_invite_self}

        Memberships.joined?(room.id, target.id) ->
          {:error, :already_member}

        Memberships.invited?(room.id, target.id) ->
          {:error, :already_invited}

        true ->
          with :ok <- ensure_member_role(target.id),
               :ok <- ensure_room_started(room),
               {:ok, _} <- emit_member_event(room.id, actor, "invite", target) do
            {:ok, %{"room_id" => Identity.room_id(room.id)}}
          end
      end
    end
  end

  @spec add_member(Ecto.UUID.t(), Ecto.UUID.t(), String.t()) :: {:ok, map()} | {:error, term()}
  defp legacy_add_member(room_id, actor_principal_id, username) when is_binary(username) do
    canonical = Accounts.normalize_username(username)

    cond do
      not Memberships.joined?(room_id, actor_principal_id) ->
        {:error, :forbidden}

      not creator?(room_id, actor_principal_id) ->
        {:error, :forbidden}

      true ->
        with {:ok, actor} <- fetch_principal(actor_principal_id),
             {:ok, target} <- fetch_active_user(canonical),
             false <- target.id == actor.id,
             false <- Memberships.joined?(room_id, target.id),
             :ok <- ensure_member_role(target.id),
             {:ok, _} <- emit_member_event(room_id, actor, "join", target) do
          {:ok, %{"user_id" => Identity.user_id(target.username)}}
        else
          {:error, _} = err -> err
          true -> {:error, :already_member}
        end
    end
  end

  @spec remove_member(Ecto.UUID.t(), Ecto.UUID.t() | String.t(), String.t()) ::
          {:ok, map()} | {:error, term()}
  defp legacy_remove_member(actor_principal_id, room_id_or_alias, username) when is_binary(username) do
    canonical = Accounts.normalize_username(username)

    with {:ok, room} <- resolve_room(room_id_or_alias),
         {:ok, actor} <- fetch_principal(actor_principal_id),
         {:ok, target} <- fetch_active_user(canonical) do
      cond do
        not Memberships.joined?(room.id, actor_principal_id) ->
          {:error, :forbidden}

        not creator?(room.id, actor_principal_id) ->
          {:error, :forbidden}

        target.id == actor.id ->
          {:error, :cannot_remove_self}

        not Memberships.joined?(room.id, target.id) ->
          {:error, :not_member}

        true ->
          emit_member_event(room.id, actor, "leave", target)
      end
    end
  end

  @spec set_name(Ecto.UUID.t(), Ecto.UUID.t() | String.t(), String.t()) ::
          {:ok, map()} | {:error, term()}
  def set_name(principal_id, room_id_or_alias, name) when is_binary(name) do
    name = String.trim(name)

    with {:ok, room} <- resolve_room(room_id_or_alias),
         {:ok, principal} <- fetch_principal(principal_id) do
      cond do
        delegated?(room.id) and not creator?(room.id, principal_id) ->
          {:error, :not_member}

        name == "" ->
          {:error, :invalid_name}

        not Memberships.joined?(room.id, principal_id) ->
          {:error, :not_member}

        true ->
          ctx =
            build_context(
              room.id,
              principal,
              "m.room.name",
              %{"name" => name},
              "",
              "name-#{System.unique_integer([:positive])}"
            )

          Processor.process(ctx)
      end
    end
  end

  @spec set_avatar(Ecto.UUID.t(), Ecto.UUID.t() | String.t(), String.t(), map()) ::
          {:ok, map()} | {:error, term()}
  def set_avatar(principal_id, room_id_or_alias, content_uri, info \\ %{})
      when is_binary(content_uri) do
    with {:ok, room} <- resolve_room(room_id_or_alias),
         {:ok, principal} <- fetch_principal(principal_id) do
      if Memberships.joined?(room.id, principal_id) and (not delegated?(room.id) or creator?(room.id, principal_id)) do
        content =
          %{"url" => content_uri}
          |> then(fn c -> if map_size(info) > 0, do: Map.put(c, "info", info), else: c end)

        ctx =
          build_context(
            room.id,
            principal,
            "m.room.avatar",
            content,
            "",
            "avatar-#{System.unique_integer([:positive])}"
          )

        Processor.process(ctx)
      else
        {:error, :not_member}
      end
    end
  end

  @spec list_room_files(Ecto.UUID.t(), Ecto.UUID.t() | String.t(), keyword()) :: [map()]
  def list_room_files(principal_id, room_id_or_alias, opts \\ []) do
    case resolve_room(room_id_or_alias) do
      {:ok, room} ->
        if Memberships.joined?(room.id, principal_id) and (not delegated?(room.id) or creator?(room.id, principal_id)) do
          Events.list_file_messages(room.id, opts)
        else
          []
        end

      _ ->
        []
    end
  end

  @spec creator?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def creator?(room_id, principal_id) do
    with {:ok, principal} <- fetch_principal(principal_id),
         %{"content" => %{"creator" => creator}} <- State.get(room_id, "m.room.create", "") do
      creator == Identity.user_id(principal.username)
    else
      _ -> false
    end
  end

  @spec set_topic(Ecto.UUID.t(), Ecto.UUID.t() | String.t(), String.t()) ::
          {:ok, map()} | {:error, term()}
  def set_topic(principal_id, room_id_or_alias, topic) when is_binary(topic) do
    with {:ok, room} <- resolve_room(room_id_or_alias),
         {:ok, principal} <- fetch_principal(principal_id) do
      if Memberships.joined?(room.id, principal_id) and (not delegated?(room.id) or creator?(room.id, principal_id)) do
        ctx =
          build_context(
            room.id,
            principal,
            "m.room.topic",
            %{"topic" => topic},
            "",
            "topic-#{System.unique_integer([:positive])}"
          )

        Processor.process(ctx)
      else
        {:error, :not_member}
      end
    end
  end

  @spec leave_room(Ecto.UUID.t(), Ecto.UUID.t() | String.t()) :: {:ok, map()} | {:error, term()}
  defp legacy_leave_room(principal_id, room_id_or_alias) do
    with {:ok, room} <- resolve_room(room_id_or_alias),
         true <- Memberships.joined?(room.id, principal_id),
         {:ok, principal} <- fetch_principal(principal_id),
         {:ok, _} <- emit_member_event(room.id, principal, "leave", principal) do
      {:ok, %{}}
    end
  end

  @spec send_message(Ecto.UUID.t(), Ecto.UUID.t(), String.t(), map()) ::
          {:ok, map()} | {:error, term()}
  def send_message(principal_id, room_id, txn_id, content) do
    if delegated?(room_id) do
      grant = %LakehouseIam.Schema.AppGrant{principal_id: principal_id,
        app_origin: "https://" <> Identity.homeserver_domain(), scopes: ["chats.write"], room_mode: :all}
      LakehouseMatrix.DelegatedGroups.send(grant, room_id, "m.room.message", txn_id, content)
    else
      legacy_send_message(principal_id, room_id, txn_id, content)
    end
  end

  defp legacy_send_message(principal_id, room_id, txn_id, content) do
    joined = Memberships.joined?(room_id, principal_id)
    can_send = can_send?(principal_id, room_id)

    Logger.info(
      "matrix.send_message principal=#{principal_id} room=#{room_id} joined=#{joined} can_send=#{can_send}"
    )

    cond do
      not joined ->
        Logger.warning("matrix.send_message denied: not a room member principal=#{principal_id}")
        {:error, :not_member}

      not can_send ->
        Logger.warning(
          "matrix.send_message denied: missing matrix.room.send principal=#{principal_id}"
        )

        {:error, :no_send_permission}

      true ->
        with {:ok, principal} <- fetch_principal(principal_id) do
          ctx = build_context(room_id, principal, "m.room.message", content, nil, txn_id)

          case Processor.process(ctx) do
            {:ok, _} = ok ->
              ok

            {:error, reason} = err ->
              Logger.warning(
                "matrix.send_message processor error principal=#{principal_id} reason=#{inspect(reason)}"
              )

              err
          end
        end
    end
  end

  @spec sync(Ecto.UUID.t(), String.t() | nil, keyword()) :: map()
  def sync(principal_id, since \\ nil, opts \\ []) do
    Sync.sync(principal_id, since, opts)
  end

  @spec room_messages(Ecto.UUID.t(), Ecto.UUID.t(), keyword()) :: map()
  def room_messages(principal_id, room_id, opts \\ []) do
    if Memberships.joined?(room_id, principal_id) do
      events = Events.list_timeline(room_id, opts)

      %{
        "chunk" => events,
        "start" => Sync.current_token(),
        "end" => Sync.current_token()
      }
    else
      %{"errcode" => "M_FORBIDDEN", "error" => "You are not in this room."}
    end
  end

  defp emit_create_events(room, principal) do
    sender = Identity.user_id(principal.username)

    with {:ok, _} <-
           Processor.process(
             build_context(
               room.id,
               principal,
               "m.room.create",
               %{"creator" => sender},
               "",
               "create"
             )
           ),
         {:ok, _} <-
           Processor.process(
             build_context(
               room.id,
               principal,
               "m.room.name",
               %{"name" => room.name},
               "",
               "name"
             )
           ),
         {:ok, _} <- emit_member_event(room.id, principal, "join", principal) do
      :ok
    end
  end

  defp emit_member_event(room_id, actor_principal, membership, target_principal) do
    content = %{
      "membership" => membership,
      "displayname" => target_principal.username
    }

    Processor.process(
      build_context(
        room_id,
        actor_principal,
        "m.room.member",
        content,
        Identity.user_id(target_principal.username),
        "#{membership}-#{target_principal.username}"
      )
    )
  end

  defp ensure_member_role(principal_id) do
    if IAM.roles_for(principal_id) == [] do
      case IAM.assign_role(principal_id, "member") do
        {:ok, _} ->
          Logger.info("matrix.ensure_member_role assigned member to principal=#{principal_id}")
          :ok

        {:error, reason} ->
          Logger.warning(
            "matrix.ensure_member_role failed principal=#{principal_id} reason=#{inspect(reason)}"
          )

          {:error, reason}
      end
    else
      :ok
    end
  end

  defp fetch_active_user(canonical_username) do
    case Accounts.fetch_user(canonical_username) do
      {:ok, principal} ->
        if Accounts.active?(principal), do: {:ok, principal}, else: {:error, :inactive}

      :error ->
        {:error, :user_not_found}
    end
  end

  defp build_context(room_id, principal, type, content, state_key, txn_id) do
    %Context{
      room_id: room_id,
      principal_id: principal.id,
      sender: Identity.user_id(principal.username),
      event_id: Identity.new_event_id(),
      type: type,
      content: content,
      state_key: blank_state_key(state_key),
      origin_server_ts: origin_ts(txn_id)
    }
  end

  defp blank_state_key(""), do: ""
  defp blank_state_key(nil), do: nil
  defp blank_state_key(key), do: key

  defp origin_ts(txn_id) do
  base = System.system_time(:millisecond)

  case txn_id do
    id when is_binary(id) ->
      # Nudge txn-based ids so rapid sends stay ordered without a central sequencer.
      base + rem(:erlang.phash2(id), 1000)

    _ ->
      base
  end
  end

  defp resolve_room(room_id_or_alias) do
    cond do
      match?({:ok, _}, Identity.parse_room_id(room_id_or_alias)) ->
        {:ok, uuid} = Identity.parse_room_id(room_id_or_alias)
        fetch_room(uuid)

      match?({:ok, _}, Identity.parse_room_alias(room_id_or_alias)) ->
        {:ok, alias_name} = Identity.parse_room_alias(room_id_or_alias)
        Rooms.get_room_by_alias(alias_name)

      true ->
        fetch_room(room_id_or_alias)
    end
  end

  defp fetch_room(id) do
    case Rooms.get_room(id) do
      nil -> {:error, :room_not_found}
      room -> {:ok, room}
    end
  end

  defp fetch_principal(principal_id) do
    case LakehouseIam.Repo.get(LakehouseIam.Schema.Principal, principal_id) do
      nil -> {:error, :unknown_principal}
      p -> {:ok, p}
    end
  end

  defp delegated?(id), do: State.get(id, "cool.gravitas.river.group.v1") != nil

  defp can_create?(principal_id) do
    IAM.can?(principal_id, "matrix.room.create", nil)
  end

  defp can_join?(principal_id, room_id) do
    IAM.can?(principal_id, "matrix.room.join", Identity.resource_arn(room_id))
  end

  defp can_send?(principal_id, room_id) do
    IAM.can?(principal_id, "matrix.room.send", Identity.resource_arn(room_id))
  end

  defp room_attrs(params) do
    name =
      params
      |> Map.get("name")
      |> case do
        n when is_binary(n) and n != "" -> n
        _ -> Map.get(params, "room_alias_name", "Room") |> to_string()
      end

    %{
      name: name,
      topic: Map.get(params, "topic"),
      alias: Map.get(params, "room_alias_name")
    }
  end

  defp ensure_room_started(room) do
    case Rooms.ensure_started(room.id) do
      {:ok, _} -> :ok
      err -> err
    end
  end
end
