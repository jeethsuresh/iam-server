defmodule LakehouseMatrix.ClientRooms do
  @moduledoc "Standard client operations with River's existing authorization and membership policy."
  import Ecto.Query
  alias LakehouseIam.{IAM, Repo}

  alias LakehouseMatrix.{
    ClientStore,
    DelegatedGroups,
    Events,
    Identity,
    Matrix,
    Memberships,
    Rooms,
    State
  }

  alias LakehouseMatrix.Events.Context
  alias LakehouseMatrix.Schema.RoomEvent

  def create(principal, params) do
    if LakehouseMatrix.Protocol.Rooms.enabled?(),
      do: LakehouseMatrix.Protocol.Rooms.create(principal, params),
      else: create_legacy(principal, params)
  end

  defp create_legacy(principal, params) do
    initial = params["initial_state"] || []
    invites = params["invite"] || []

    cond do
      params["room_version"] not in [nil, "11"] ->
        {:error, :unsupported_room_version}

      not is_list(initial) or length(initial) > 100 or not is_list(invites) or
          length(invites) > 100 ->
        {:error, :invalid_param}

      params["preset"] not in [nil, "private_chat", "trusted_private_chat", "public_chat"] ->
        {:error, :invalid_param}

      not is_nil(params["power_level_content_override"]) and
          not is_map(params["power_level_content_override"]) ->
        {:error, :invalid_param}

      true ->
        LakehouseMatrix.Protocol.Policy.transaction(fn ->
          ClientStore.lock!()

          response =
            case Matrix.create_room(principal, params) do
              {:ok, response} -> response
              {:error, reason} -> Repo.rollback(reason)
            end

          {:ok, room} = Identity.parse_room_id(response["room_id"])
          public = params["preset"] == "public_chat"

          defaults = [
            %{
              "type" => "m.room.join_rules",
              "state_key" => "",
              "content" => %{"join_rule" => if(public, do: "public", else: "invite")}
            },
            %{
              "type" => "m.room.history_visibility",
              "state_key" => "",
              "content" => %{"history_visibility" => "shared"}
            },
            %{
              "type" => "m.room.power_levels",
              "state_key" => "",
              "content" => %{
                "users" => %{user_id(principal) => 100},
                "users_default" => 0,
                "events_default" => 0,
                "state_default" => 50,
                "invite" => 0,
                "kick" => 50,
                "ban" => 50,
                "redact" => 50
              }
            }
          ]

          creation = params["creation_content"] || %{}
          unless is_map(creation), do: Repo.rollback(:invalid_param)

          if Map.has_key?(creation, "type") and not is_binary(creation["type"]),
            do: Repo.rollback(:invalid_param)

          # The local room store cannot yet produce federation-valid historical
          # PDUs. Mark native rooms non-federating rather than making a promise
          # that could expose an existing River policy room to foreign servers.
          create_event =
            Repo.one!(
              from e in RoomEvent, where: e.room_id == ^room and e.type == "m.room.create"
            )

          create_content =
            Map.merge(create_event.content, Map.take(creation, ["type"]))
            |> Map.merge(%{"room_version" => "11", "m.federate" => false})

          create_event |> Ecto.Changeset.change(content: create_content) |> Repo.update!()

          State.upsert(
            room,
            "",
            "m.room.create",
            create_content,
            create_event.event_id,
            create_event.origin_server_ts
          )

          for e <- defaults ++ initial do
            unless is_map(e) and is_binary(e["type"]) and is_binary(e["state_key"] || "") and
                     is_map(e["content"]),
                   do: Repo.rollback(:invalid_param)

            case put_state(
                   principal,
                   response["room_id"],
                   e["type"],
                   e["state_key"] || "",
                   e["content"]
                 ) do
              {:ok, _} -> :ok
              {:error, reason} -> Repo.rollback(reason)
            end
          end

          if is_binary(params["topic"]),
            do: Matrix.set_topic(principal, response["room_id"], params["topic"])

          for invite <- invites do
            with {:ok, local} <- Identity.parse_user_id(invite),
                 {:ok, _} <- Matrix.invite(principal, response["room_id"], local) do
              :ok
            else
              _ -> Repo.rollback(:invalid_param)
            end
          end

          if params["power_level_content_override"] do
            override =
              Map.merge(List.last(defaults)["content"], params["power_level_content_override"])

            case put_state(principal, response["room_id"], "m.room.power_levels", "", override) do
              {:ok, _} -> :ok
              {:error, reason} -> Repo.rollback(reason)
            end
          end

          response
        end)
    end
  end

  def moderate(principal, ref, action, user, reason \\ nil) do
    with true <- action in ~w(kick ban unban),
         {:ok, _} <- LakehouseMatrix.Protocol.Event.user_domain(user),
         true <- is_nil(reason) or (is_binary(reason) and byte_size(reason) <= 16_384),
         {:ok, room} <- readable(principal, ref) do
      if metadata = LakehouseMatrix.Protocol.Graph.room(room.id) do
        sender = user_id(principal)
        state = LakehouseMatrix.Federation.RoomAccess.state(metadata)
        membership = LakehouseMatrix.Protocol.Authorization.membership(state, user)

        cond do
          user == sender ->
            {:error, :forbidden}

          action == "kick" and membership not in ~w(join invite knock) ->
            {:error, :not_found}

          action == "unban" and membership != "ban" ->
            {:error, :invalid_param}

          true ->
            content = %{"membership" => if(action == "ban", do: "ban", else: "leave")}
            content = if reason, do: Map.put(content, "reason", reason), else: content

            case LakehouseMatrix.Protocol.Graph.send(
                   room.id,
                   sender,
                   "m.room.member",
                   content,
                   user
                 ) do
              {:ok, _} -> {:ok, %{}}
              error -> error
            end
        end
      else
        if action == "kick",
          do: Matrix.remove_member(principal, ref, user),
          else: {:error, :forbidden}
      end
    else
      _ -> {:error, :invalid_param}
    end
  end

  def room(ref) do
    with {:ok, id} <- Identity.parse_room_id(ref),
         room when not is_nil(room) <- Rooms.get_room(id),
         do: {:ok, room}
  end

  def knock(principal, ref, servers, params) do
    with true <- IAM.can?(principal, "matrix.room.join", nil),
         true <-
           is_nil(params["reason"]) or
             (is_binary(params["reason"]) and byte_size(params["reason"]) <= 16_384),
         {:ok, ref, peers} <- knock_reference(ref, servers) do
      metadata = LakehouseMatrix.Protocol.Graph.room_by_id(ref)
      local = Identity.homeserver_domain()
      state = if metadata, do: LakehouseMatrix.Federation.RoomAccess.state(metadata), else: %{}
      creator = state[{"m.room.create", ""}]

      local_room =
        creator && LakehouseMatrix.Protocol.Event.user_domain(creator["sender"]) == {:ok, local}

      if metadata && metadata.extremities != [] &&
           (local_room or LakehouseMatrix.Federation.RoomAccess.joined?(state, local)) do
        with {:ok, _} <-
               LakehouseMatrix.Protocol.Rooms.membership(
                 principal,
                 metadata.local_room_id,
                 "knock",
                 Map.take(params, ["reason"])
               ),
             do: {:ok, %{"room_id" => ref}}
      else
        LakehouseMatrix.Federation.RemoteMembership.knock(principal, ref, peers, params)
      end
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_param}
    end
  end

  defp knock_reference("#" <> _ = ref, servers) do
    with {:ok, room} <- LakehouseMatrix.Directory.resolve(ref),
         do: {:ok, room["room_id"], Enum.take(servers, 20) ++ room["servers"]}
  end

  defp knock_reference(ref, servers) when is_binary(ref) and is_list(servers) do
    inferred =
      case String.split(ref, ":", parts: 2) do
        ["!" <> _, domain] -> [domain]
        _ -> []
      end

    if String.starts_with?(ref, "!") and byte_size(ref) <= 255,
      do: {:ok, ref, Enum.take(servers, 20) ++ inferred},
      else: {:error, :invalid_param}
  end

  defp knock_reference(_, _), do: {:error, :invalid_param}

  def forget(principal, ref) do
    with {:ok, room} <- room(ref) do
      LakehouseMatrix.Protocol.Policy.transaction(fn ->
        ClientStore.lock!()

        unless Memberships.membership(room.id, principal) in ~w(leave ban),
          do: Repo.rollback(:forbidden)

        unless ClientStore.room_forgotten?(principal, room.id),
          do:
            Repo.insert_all("matrix_room_forgetting", [
              %{
                principal_id: ClientStore.dump_id(principal),
                local_room_id: ClientStore.dump_id(room.id),
                forgotten: true
              }
            ])

        %{}
      end)
    else
      _ -> {:error, :not_found}
    end
  end

  def history_access(principal, ref) do
    alias LakehouseMatrix.ClientSync

    with {:ok, room} <- room(ref),
         true <-
           not ClientStore.room_forgotten?(principal, room.id) and
             LakehouseMatrix.RiverRtc.chat_allowed?(room.id, principal) and
             LakehouseMatrix.RiverPublishing.reader_allowed?(room.id, principal) do
      high = ClientStore.position()
      membership = ClientSync.last_membership(principal, room.id, high)

      world =
        get_in(State.get(room.id, "m.room.history_visibility") || %{}, [
          "content",
          "history_visibility"
        ]) == "world_readable"

      cond do
        world or (membership && membership.content["membership"] == "join") ->
          {:ok, room, high}

        not is_nil(membership) and membership.content["membership"] in ~w(leave ban) and
          ClientSync.ever_joined?(principal, room.id, high) and
            not ClientStore.room_forgotten?(principal, room.id, high) ->
          {:ok, room, membership.stream_id}

        true ->
          {:error, :forbidden}
      end
    else
      _ -> {:error, :not_found}
    end
  end

  def readable(principal, ref) do
    with {:ok, room} <- room(ref),
         true <- Memberships.joined?(room.id, principal),
         do: {:ok, room}
  end

  def system_grant(principal) do
    %LakehouseIam.Schema.AppGrant{
      principal_id: principal,
      app_origin: "https://" <> Identity.homeserver_domain(),
      scopes: ~w(chats.read chats.write groups.manage groups.join spaces.channels calls.join),
      room_mode: :all
    }
  end

  def river?(room),
    do:
      not is_nil(State.get(room, "cool.gravitas.river.group.v1")) or
        not is_nil(Repo.get(LakehouseMatrix.Schema.RiverChannel, room)) or
        not is_nil(LakehouseMatrix.RiverRtc.chat_record(room))

  def send(principal, device, ref, "m.room.redaction", txn, content) when is_map(content) do
    with {:ok, room} <- readable(principal, ref),
         true <- not is_nil(LakehouseMatrix.Protocol.Graph.room(room.id)),
         true <- byte_size(Jason.encode!(content)) < 60_000,
         true <- IAM.can?(principal, "matrix.room.send", Identity.resource_arn(room.id)) do
      ClientStore.transaction(principal, device, "send:" <> room.id, txn, fn ->
        redact_event(principal, room, content["redacts"], content)
      end)
    else
      _ -> {:error, :forbidden}
    end
  end

  def send(principal, device, ref, type, txn, content) do
    with {:ok, room} <- readable(principal, ref),
         true <-
           is_map(content) and is_binary(type) and byte_size(type) in 1..255 and
             byte_size(Jason.encode!(content)) < 60_000,
         true <-
           type not in ~w(m.room.create m.room.member m.room.power_levels m.room.join_rules m.room.encryption m.room.redaction m.rtc.member),
         true <- IAM.can?(principal, "matrix.room.send", Identity.resource_arn(room.id)) do
      ClientStore.transaction(principal, device, "send:" <> room.id, txn, fn ->
        if river?(room.id) and is_nil(LakehouseMatrix.Protocol.Graph.room(room.id)) do
          DelegatedGroups.send(
            system_grant(principal),
            room.id,
            type,
            digest(device <> ":" <> txn),
            content
          )
          |> event_result()
        else
          if allowed_event?(principal, room.id, type, false) do
            with :ok <-
                   LakehouseMatrix.ClientRelations.validate_send(
                     room.id,
                     user_id(principal),
                     type,
                     content
                   ),
                 do: persist(principal, room.id, type, content, nil) |> event_result()
          else
            {:error, :forbidden}
          end
        end
      end)
    else
      _ -> {:error, :forbidden}
    end
  end

  def put_state(principal, ref, type, key, content) do
    with {:ok, room} <- readable(principal, ref),
         true <- is_map(content) and byte_size(Jason.encode!(content)) < 60_000,
         true <-
           type != "m.room.create" and
             (not is_nil(LakehouseMatrix.Protocol.Graph.room(room.id)) or
                (type not in ~w(m.room.member m.room.tombstone) and
                   not String.starts_with?(type, "cool.gravitas."))),
         true <- valid_state_content?(type, content) do
      LakehouseMatrix.Protocol.Policy.transaction(fn ->
        ClientStore.lock!()

        native = not is_nil(LakehouseMatrix.Protocol.Graph.room(room.id))

        unless Memberships.joined?(room.id, principal) and
                 (native or allowed_event?(principal, room.id, type, true)),
               do: Repo.rollback(:forbidden)

        if not native and river?(room.id) and
             (type not in ~w(m.room.name m.room.topic m.room.avatar) or key != "" or
                not Matrix.creator?(room.id, principal)),
           do: Repo.rollback(:forbidden)

        if type != "m.room.member" and String.starts_with?(key, "@") and
             key != user_id(principal),
           do: Repo.rollback(:forbidden)

        if not native and type == "m.room.power_levels" and
             not valid_power?(principal, room.id, content),
           do: Repo.rollback(:forbidden)

        encryption = State.get(room.id, "m.room.encryption", key)

        if type == "m.room.encryption" and
             (content["algorithm"] != "m.megolm.v1.aes-sha2" or
                (encryption && encryption["content"]["algorithm"] != content["algorithm"])),
           do: Repo.rollback(:forbidden)

        if type == "m.room.join_rules" and
             content["join_rule"] not in ~w(invite public knock restricted knock_restricted private),
           do: Repo.rollback(:invalid_param)

        if type == "m.room.history_visibility" and
             content["history_visibility"] not in ~w(invited joined shared world_readable),
           do: Repo.rollback(:invalid_param)

        result =
          if native do
            persist(principal, room.id, type, content, key)
          else
            case {type, key} do
              {"m.room.name", ""} ->
                Matrix.set_name(principal, ref, content["name"])

              {"m.room.topic", ""} ->
                Matrix.set_topic(principal, ref, content["topic"])

              {"m.room.avatar", ""} ->
                Matrix.set_avatar(principal, ref, content["url"] || "", content["info"] || %{})

              _ ->
                persist(principal, room.id, type, content, key)
            end
          end

        case event_result(result) do
          {:ok, response} -> response
          {:error, reason} -> Repo.rollback(reason)
        end
      end)
    else
      _ -> {:error, :forbidden}
    end
  end

  defp valid_state_content?("m.room.name", content),
    do: is_nil(content["name"]) or is_binary(content["name"])

  defp valid_state_content?("m.room.topic", content),
    do: is_nil(content["topic"]) or is_binary(content["topic"])

  defp valid_state_content?("m.room.avatar", content),
    do: is_binary(content["url"] || "") and is_map(content["info"] || %{})

  defp valid_state_content?(_, _), do: true

  def persist(principal, room, type, content, key) do
    with {:ok, content} <- LakehouseMatrix.RiverContent.bind_space(room, type, content) do
      if LakehouseMatrix.Protocol.Graph.room(room) do
        case LakehouseMatrix.Protocol.Graph.send(room, user_id(principal), type, content, key) do
          {:ok, event} ->
            {:ok, Events.to_client_event(Repo.get_by!(RoomEvent, event_id: event["event_id"]))}

          error ->
            error
        end
      else
        ctx = %Context{
          room_id: room,
          principal_id: principal,
          sender: user_id(principal),
          event_id: Identity.new_event_id(),
          type: type,
          content: content,
          state_key: key,
          origin_server_ts: System.system_time(:millisecond)
        }

        if not is_nil(key),
          do: State.upsert(room, key, type, content, ctx.event_id, ctx.origin_server_ts)

        with {:ok, record} <- Events.persist(ctx, %{"content" => content}),
             do: {:ok, Events.to_client_event(record)}
      end
    end
  end

  def event(principal, ref, event) do
    with {:ok, room} <- room(ref) do
      if LakehouseMatrix.Protocol.Graph.room(room.id),
        do:
          with(
            {:ok, found} <- LakehouseMatrix.ClientHistory.event(principal, room.id, event),
            do: {:ok, hd(LakehouseMatrix.ClientRelations.bundle(principal, room.id, [found]))}
          ),
        else: legacy_event(principal, ref, event)
    else
      _ -> {:error, :not_found}
    end
  end

  defp legacy_event(principal, ref, event) do
    with {:ok, room, boundary} <- history_access(principal, ref),
         query <-
           from(e in RoomEvent,
             where: e.room_id == ^room.id and e.event_id == ^event and e.stream_id <= ^boundary
           ),
         %{} = e <- Repo.one(LakehouseMatrix.ClientSync.visible_query(query, principal)) do
      {:ok, Map.put(Events.to_client_event(e, principal), "room_id", Identity.room_id(room.id))}
    else
      _ -> {:error, :not_found}
    end
  end

  def redact(principal, device, ref, target, txn, content) do
    with {:ok, room} <- readable(principal, ref) do
      ClientStore.transaction(principal, device, "redact:" <> room.id, txn, fn ->
        redact_event(principal, room, target, content)
      end)
    else
      _ -> {:error, :forbidden}
    end
  end

  defp redact_event(principal, room, target, content)
       when is_binary(target) and is_map(content) do
    original = Repo.get_by(RoomEvent, room_id: room.id, event_id: target)

    native = not is_nil(LakehouseMatrix.Protocol.Graph.room(room.id))
    stored = if native and is_binary(target), do: LakehouseMatrix.Protocol.Graph.event(target)

    own_pdu =
      stored && stored.local_room_id == room.id && stored.pdu["sender"] == user_id(principal)

    allowed =
      (not is_nil(original) and original.principal_id == principal) or own_pdu == true or
        LakehouseMatrix.Protocol.Authorization.gte?(
          power(principal, room.id),
          level(room.id, "redact", 50)
        )

    # River's control events are also its policy database. Only timeline content
    # may be redacted through Matrix; policy changes use the existing app API.
    if allowed and is_binary(target) and byte_size(target) <= 255 and
         String.starts_with?(target, "$") and
         (native or (not is_nil(original) and is_nil(original.state_key))) and
         allowed_event?(principal, room.id, "m.room.redaction", false) do
      persist(
        principal,
        room.id,
        "m.room.redaction",
        Map.put(Map.take(content, ["reason"]), "redacts", target),
        nil
      )
      |> event_result()
    else
      {:error, :forbidden}
    end
  end

  defp redact_event(_, _, _, _), do: {:error, :invalid_param}

  def read_markers(principal, ref, params) do
    keys = ~w(m.fully_read m.read m.read.private)

    with {:ok, _} <- readable(principal, ref),
         true <- Enum.all?(keys, &(not Map.has_key?(params, &1) or is_binary(params[&1]))) do
      LakehouseMatrix.Protocol.Policy.transaction(fn ->
        ClientStore.lock!()
        LakehouseMatrix.AccountModeration.require!(principal, :read)

        for key <- ~w(m.read m.read.private), id = params[key], not is_nil(id) do
          case receipt(principal, ref, key, id, %{}) do
            {:ok, _} -> :ok
            {:error, reason} -> Repo.rollback(reason)
          end
        end

        if id = params["m.fully_read"] do
          case event(principal, ref, id) do
            {:ok, _} ->
              case ClientStore.put_data(principal, ref, "m.fully_read", %{"event_id" => id}) do
                {:ok, _} -> :ok
                {:error, reason} -> Repo.rollback(reason)
              end

            _ ->
              Repo.rollback(:invalid_param)
          end
        end

        %{}
      end)
    else
      false -> {:error, :invalid_param}
      _ -> {:error, :forbidden}
    end
  end

  def receipt(principal, ref, type, event, data) do
    with {:ok, room} <- readable(principal, ref),
         true <- type in ~w(m.read m.read.private),
         %{} = target <- receipt_event(principal, room.id, event),
         true <- valid_receipt_thread?(principal, room.id, target, data["thread_id"]) do
      LakehouseMatrix.Protocol.Policy.transaction(fn ->
        ClientStore.lock!()
        LakehouseMatrix.AccountModeration.require!(principal, :read)
        thread = data["thread_id"] || ""

        unless LakehouseMatrix.Notifications.receipt_forward?(
                 principal,
                 room.id,
                 type,
                 thread,
                 target.event_id
               ),
               do: Repo.rollback(:receipt_unchanged)

        receipt = Map.put(Map.take(data, ["thread_id"]), "ts", System.system_time(:millisecond))

        Repo.insert_all(
          "matrix_receipts",
          [
            %{
              principal_id: ClientStore.dump_id(principal),
              room_id: ClientStore.dump_id(room.id),
              type: type,
              thread_id: thread,
              event_id: target.event_id,
              data: receipt
            }
          ],
          conflict_target: [:principal_id, :room_id, :type, :thread_id],
          on_conflict: [set: [event_id: target.event_id, data: receipt]]
        )

        if type == "m.read" do
          with metadata when not is_nil(metadata) <- LakehouseMatrix.Protocol.Graph.room(room.id) do
            LakehouseMatrix.Federation.Edus.broadcast!(metadata, "m.receipt", %{
              metadata.room_id => %{
                "m.read" => %{
                  user_id(principal) => %{"event_ids" => [target.event_id], "data" => receipt}
                }
              }
            })
          end
        end

        LakehouseMatrix.Pushers.queue!(principal)

        %{}
      end)
      |> then(fn
        {:error, :receipt_unchanged} -> {:ok, %{}}
        result -> result
      end)
    else
      _ -> {:error, :forbidden}
    end
  end

  defp receipt_event(principal, room, event) when is_binary(event) do
    if LakehouseMatrix.Protocol.Graph.room(room) do
      case LakehouseMatrix.ClientHistory.event(principal, room, event) do
        {:ok, found} -> %{event_id: found["event_id"], content: found["content"]}
        _ -> nil
      end
    else
      Repo.get_by(RoomEvent, room_id: room, event_id: event)
    end
  end

  defp receipt_event(_, _, _), do: nil

  defp valid_receipt_thread?(_, _, _, nil), do: true

  defp valid_receipt_thread?(principal, room, event, thread)
       when is_binary(thread) and byte_size(thread) in 1..255 do
    relation = event.content["m.relates_to"] || %{}
    in_thread = is_map(relation) and relation["rel_type"] == "m.thread"

    if thread == "main",
      do: not in_thread,
      else:
        (event.event_id == thread or (in_thread and relation["event_id"] == thread)) and
          not is_nil(receipt_event(principal, room, thread))
  end

  defp valid_receipt_thread?(_, _, _, _), do: false

  def allowed_event?(principal, room, type, state),
    do:
      LakehouseMatrix.Protocol.Authorization.gte?(
        power(principal, room),
        get_in(power_content(room), ["events", type]) ||
          level(
            room,
            if(state, do: "state_default", else: "events_default"),
            if(state, do: 50, else: 0)
          )
      )

  def power(principal, room) do
    case LakehouseMatrix.Protocol.Graph.room(room) do
      nil ->
        get_in(power_content(room), ["users", user_id(principal)]) ||
          if(Matrix.creator?(room, principal), do: 100, else: level(room, "users_default", 0))

      metadata ->
        LakehouseMatrix.Protocol.Authorization.power(
          LakehouseMatrix.Federation.RoomAccess.state(metadata),
          user_id(principal),
          metadata.version
        )
    end
  end

  def level(room, key, default), do: power_content(room)[key] || default

  defp power_content(room),
    do: get_in(State.get(room, "m.room.power_levels") || %{}, ["content"]) || %{}

  defp valid_power?(principal, room, content) do
    own = power(principal, room)
    old = power_content(room)
    integer_fields = ~w(users_default events_default state_default ban kick redact invite)

    Enum.all?(integer_fields, fn key ->
      new =
        Map.get(content, key, if(key in ~w(users_default events_default invite), do: 0, else: 50))

      prior =
        Map.get(old, key, if(key in ~w(users_default events_default invite), do: 0, else: 50))

      is_integer(new) and new <= own and (new == prior or prior <= own)
    end) and
      Enum.all?(~w(users events notifications), fn group ->
        values = content[group] || %{}
        previous = old[group] || %{}

        is_map(values) and
          Enum.all?(Enum.uniq(Map.keys(values) ++ Map.keys(previous)), fn key ->
            new = values[key] || 0
            prior = previous[key] || 0

            is_integer(new) and new <= own and
              (new == prior or prior < own or (group == "users" and key == user_id(principal)))
          end)
      end)
  end

  defp user_id(principal),
    do: Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

  defp event_result({:ok, event}), do: {:ok, %{"event_id" => event["event_id"]}}
  defp event_result(error), do: error
  defp digest(text), do: :crypto.hash(:sha256, text) |> Base.url_encode64(padding: false)
end
