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
        Repo.transaction(fn ->
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

  def room(ref) do
    with {:ok, id} <- Identity.parse_room_id(ref),
         room when not is_nil(room) <- Rooms.get_room(id),
         do: {:ok, room}
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

  def send(principal, device, ref, type, txn, content) do
    with {:ok, room} <- readable(principal, ref),
         true <-
           is_map(content) and is_binary(type) and byte_size(type) in 1..255 and
             byte_size(Jason.encode!(content)) < 60_000,
         true <-
           type not in ~w(m.room.create m.room.member m.room.power_levels m.room.join_rules m.room.encryption m.room.redaction m.rtc.member),
         true <- IAM.can?(principal, "matrix.room.send", Identity.resource_arn(room.id)) do
      ClientStore.transaction(principal, device, "send:" <> room.id, txn, fn ->
        if river?(room.id) do
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
            persist(principal, room.id, type, content, nil) |> event_result()
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
           type not in ~w(m.room.create m.room.member m.room.tombstone) and
             not String.starts_with?(type, "cool.gravitas."),
         true <- valid_state_content?(type, content) do
      Repo.transaction(fn ->
        ClientStore.lock!()

        unless Memberships.joined?(room.id, principal) and
                 allowed_event?(principal, room.id, type, true),
               do: Repo.rollback(:forbidden)

        if river?(room.id) and
             (type not in ~w(m.room.name m.room.topic m.room.avatar) or key != "" or
                not Matrix.creator?(room.id, principal)),
           do: Repo.rollback(:forbidden)

        if String.starts_with?(key, "@") and key != user_id(principal),
          do: Repo.rollback(:forbidden)

        if type == "m.room.power_levels" and not valid_power?(principal, room.id, content),
          do: Repo.rollback(:forbidden)

        if type == "m.room.encryption" and
             (content["algorithm"] != "m.megolm.v1.aes-sha2" or
                not is_nil(State.get(room.id, type, key))),
           do: Repo.rollback(:forbidden)

        if type == "m.room.join_rules" and content["join_rule"] not in ~w(invite public),
          do: Repo.rollback(:invalid_param)

        if type == "m.room.history_visibility" and
             content["history_visibility"] not in ~w(invited joined shared world_readable),
           do: Repo.rollback(:invalid_param)

        result =
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

        case event_result(result) do
          {:ok, response} -> response
          {:error, reason} -> Repo.rollback(reason)
        end
      end)
    else
      _ -> {:error, :forbidden}
    end
  end

  defp valid_state_content?("m.room.name", content), do: is_binary(content["name"])
  defp valid_state_content?("m.room.topic", content), do: is_binary(content["topic"])

  defp valid_state_content?("m.room.avatar", content),
    do: is_binary(content["url"] || "") and is_map(content["info"] || %{})

  defp valid_state_content?(_, _), do: true

  def persist(principal, room, type, content, key) do
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

  def event(principal, ref, event) do
    with {:ok, room} <- readable(principal, ref),
         query <- from(e in RoomEvent, where: e.room_id == ^room.id and e.event_id == ^event),
         %{} = e <- Repo.one(LakehouseMatrix.ClientSync.visible_query(query, principal)) do
      {:ok, Map.put(Events.to_client_event(e), "room_id", Identity.room_id(room.id))}
    else
      _ -> {:error, :not_found}
    end
  end

  def redact(principal, device, ref, target, txn, content) do
    with {:ok, room} <- readable(principal, ref) do
      ClientStore.transaction(principal, device, "redact:" <> room.id, txn, fn ->
        original = Repo.get_by(RoomEvent, room_id: room.id, event_id: target)

        allowed =
          original &&
            (original.principal_id == principal or
               power(principal, room.id) >= level(room.id, "redact", 50))

        # River's control events are also its policy database. Only timeline content
        # may be redacted through Matrix; policy changes use the existing app API.
        if allowed and is_nil(original.state_key) and
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
      end)
    else
      _ -> {:error, :forbidden}
    end
  end

  def receipt(principal, ref, type, event, data) do
    with {:ok, room} <- readable(principal, ref),
         true <- type in ~w(m.read m.read.private),
         %{} = target <- Repo.get_by(RoomEvent, room_id: room.id, event_id: event),
         true <- is_nil(data["thread_id"]) or is_binary(data["thread_id"]) do
      thread = data["thread_id"] || ""
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

      {:ok, %{}}
    else
      _ -> {:error, :forbidden}
    end
  end

  def allowed_event?(principal, room, type, state),
    do:
      power(principal, room) >=
        (get_in(power_content(room), ["events", type]) ||
           level(
             room,
             if(state, do: "state_default", else: "events_default"),
             if(state, do: 50, else: 0)
           ))

  def power(principal, room),
    do:
      get_in(power_content(room), ["users", user_id(principal)]) ||
        if(Matrix.creator?(room, principal), do: 100, else: level(room, "users_default", 0))

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
