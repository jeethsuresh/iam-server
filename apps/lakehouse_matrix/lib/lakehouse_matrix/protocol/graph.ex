defmodule LakehouseMatrix.Protocol.Graph do
  @moduledoc "Persist authenticated PDUs and state snapshots; project accepted events into River's shared stream."
  import Ecto.Query
  alias LakehouseIam.{Accounts, Repo}
  alias LakehouseMatrix.{ClientStore, Events, Identity, Memberships, State}
  alias LakehouseMatrix.Events.Context
  alias LakehouseMatrix.Federation.Signing
  alias LakehouseMatrix.Protocol.{Authorization, Event, Policy, StateResolution}
  alias LakehouseMatrix.Schema.{Pdu, ProtocolRoom, Room, RoomEvent, RoomState, RoomMembership}

  def room(local_id), do: Repo.get(ProtocolRoom, local_id)
  def room_by_id(id), do: Repo.get_by(ProtocolRoom, room_id: id)
  def event(id), do: Repo.get(Pdu, id)

  def ancestor?(local_id, ancestor, descendants) do
    if descendants == [] do
      false
    else
      Repo.query!(
        """
        WITH RECURSIVE ancestors(event_id) AS (
          SELECT event_id FROM matrix_pdus WHERE local_room_id = $1 AND event_id = ANY($2::text[])
          UNION
          SELECT parent.id FROM ancestors a JOIN matrix_pdus p ON p.event_id = a.event_id
          CROSS JOIN LATERAL jsonb_array_elements_text(p.pdu->'prev_events') parent(id)
          WHERE p.local_room_id = $1
        ) SELECT EXISTS (SELECT 1 FROM ancestors WHERE event_id = $3)
        """,
        [ClientStore.dump_id(local_id), descendants, ancestor]
      ).rows == [[true]]
    end
  end

  def encode_state(state),
    do: Map.new(state, fn {{type, key}, id} -> {Jason.encode!([type, key]), id} end)

  def decode_state(state),
    do:
      Map.new(state, fn {key, id} ->
        [type, state_key] = Jason.decode!(key)
        {{type, state_key}, id}
      end)

  def create(local_id, sender, version \\ "12", content \\ %{}) do
    transact(fn ->
      unless version in Event.versions() and is_map(content),
        do: Repo.rollback(:unsupported_room_version)

      require_local_sender!(sender)

      require_ok!(
        LakehouseMatrix.AccountModeration.event(sender, local_id, "m.room.create", content, "")
      )

      if not is_nil(room(local_id)) or
           Repo.exists?(from e in RoomEvent, where: e.room_id == ^local_id),
         do: Repo.rollback(:room_reset_required)

      content =
        content
        |> Map.put("room_version", version)
        |> Map.delete("creator")

      event =
        Policy.draft({:create, local_id, sender, version, content}, fn ->
          event = %{
            "type" => "m.room.create",
            "sender" => sender,
            "state_key" => "",
            "content" => Map.put(content, "cool.gravitas.create_nonce", ClientStore.random()),
            "depth" => 0,
            "origin_server_ts" => System.system_time(:millisecond),
            "prev_events" => [],
            "auth_events" => []
          }

          event =
            if version == "11",
              do: Map.put(event, "room_id", "!#{local_id}:#{Identity.homeserver_domain()}"),
              else: event

          seal!(event, version)
        end)

      require_ok!(Event.validate(event, version))
      require_ok!(Authorization.check(event, %{}, version))
      id = Event.id(event, version)

      metadata =
        Repo.insert!(%ProtocolRoom{
          local_room_id: local_id,
          room_id: Event.room_id(event, version),
          version: version,
          create_id: id
        })

      record =
        Repo.insert!(%Pdu{
          event_id: id,
          local_room_id: local_id,
          pdu: event,
          state_after: encode_state(%{{"m.room.create", ""} => id}),
          received_at: ClientStore.now()
        })

      metadata
      |> Ecto.Changeset.change(current_state: record.state_after, extremities: [id])
      |> Repo.update!()

      project!(metadata, record, %{})
      Map.put(event, "event_id", id)
    end)
  end

  def send(local_id, sender, type, content, state_key \\ nil) do
    transact(fn ->
      metadata = room(local_id) || Repo.rollback(:room_not_found)
      require_local_sender!(sender)

      require_ok!(
        LakehouseMatrix.AccountModeration.event(sender, local_id, type, content, state_key)
      )

      graph = load_graph(metadata.local_room_id)
      current = materialize(decode_state(metadata.current_state), graph)
      event = template(metadata, graph, sender, type, content, state_key)
      require_ok!(Authorization.check(event, current, metadata.version))
      event = seal!(event, metadata.version)
      event = Policy.prepare!(metadata, event, current)
      require_ok!(Event.validate(event, metadata.version))

      case accept_locked(
             metadata,
             Map.put(event, "event_id", Event.id(event, metadata.version)),
             graph
           ) do
        {:ok, pdu} -> pdu
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  def template(metadata, graph, sender, type, content, state_key) do
    parents = Enum.take(Enum.sort(metadata.extremities), 20)
    depth = parents |> Enum.map(&graph[&1]["depth"]) |> Enum.max(fn -> 0 end)

    event = %{
      "type" => type,
      "content" => content,
      "sender" => sender,
      "room_id" => metadata.room_id,
      "depth" => min(depth + 1, 9_007_199_254_740_991),
      "prev_events" => parents,
      "origin_server_ts" => System.system_time(:millisecond)
    }

    event = if is_binary(state_key), do: Map.put(event, "state_key", state_key), else: event
    state = materialize(decode_state(metadata.current_state), graph)
    Map.put(event, "auth_events", Authorization.select_auth(event, state, metadata.version))
  end

  @doc "Cryptographic verification happens before acquiring the stream lock or touching room state."
  def receive_pdu(local_id, wire, key_lookup \\ &LakehouseMatrix.Federation.Keyring.key/3) do
    with %ProtocolRoom{} = metadata <- room(local_id),
         {:ok, verified} <- Event.verify(wire, metadata.version, key_lookup),
         verified <-
           Policy.recover(
             verified,
             LakehouseMatrix.Federation.RoomAccess.state(metadata),
             metadata.version
           ),
         true <- wire["room_id"] == metadata.room_id do
      transact(fn ->
        metadata = room(local_id)

        case accept_locked(
               metadata,
               verified,
               load_graph(local_id, verified["prev_events"] ++ verified["auth_events"])
             ) do
          {:ok, pdu} -> {:accepted, pdu}
          {:error, reason} -> {:rejected, reason}
        end
      end)
      |> case do
        {:ok, {:accepted, pdu}} -> {:ok, pdu}
        {:ok, {:rejected, reason}} -> {:error, reason}
        error -> error
      end
    else
      nil -> {:error, :room_not_found}
      false -> {:error, :wrong_room}
      error -> error
    end
  end

  def load_graph(local_id, extra \\ []) do
    metadata = room(local_id)

    if metadata do
      heads = Enum.uniq(metadata.extremities ++ extra)

      parents =
        Repo.all(from p in Pdu, where: p.local_room_id == ^local_id and p.event_id in ^heads)

      roots =
        Enum.uniq(
          Map.values(metadata.current_state) ++
            heads ++
            Enum.flat_map(parents, &(Map.values(&1.state_before) ++ Map.values(&1.state_after)))
        )

      Repo.query!(
        """
        WITH RECURSIVE needed(event_id) AS (
          SELECT unnest($1::text[])
          UNION
          SELECT jsonb_array_elements_text(p.pdu->'auth_events') FROM matrix_pdus p
          JOIN needed n ON n.event_id = p.event_id WHERE p.local_room_id = $2
        )
        SELECT p.event_id, p.pdu, p.auth_rejected FROM matrix_pdus p
        JOIN needed n ON n.event_id = p.event_id WHERE p.local_room_id = $2
        """,
        [roots, ClientStore.dump_id(local_id)]
      ).rows
      |> Map.new(fn [id, pdu, rejected] ->
        {id, pdu |> Map.put("event_id", id) |> Map.put(:auth_rejected, rejected)}
      end)
    else
      %{}
    end
  end

  def state_at(id, after_event \\ false) do
    case event(id) do
      nil -> {:error, :not_found}
      pdu -> {:ok, decode_state(if after_event, do: pdu.state_after, else: pdu.state_before)}
    end
  end

  @doc "Install only a snapshot validated by Protocol.Import; network I/O must finish before this transaction."
  def store_auth(local_id, snapshot) do
    transact(fn ->
      metadata = room(local_id) || Repo.rollback(:room_not_found)
      unless metadata.create_id == snapshot.create["event_id"], do: Repo.rollback(:wrong_room)
      insert_outliers!(local_id, snapshot.graph, snapshot.event["event_id"])
    end)
  end

  def install_snapshot(local_id, ref, version, snapshot, mode \\ :live) do
    transact(fn ->
      case event(snapshot.event["event_id"]) do
        %Pdu{outlier: false} = existing ->
          if existing.local_room_id != local_id or existing.auth_rejected or
               existing.state_rejected,
             do: Repo.rollback(:rejected_event)

          Map.put(existing.pdu, "event_id", existing.event_id)

        _ ->
          install_snapshot_locked(local_id, ref, version, snapshot, mode)
      end
    end)
  end

  defp install_snapshot_locked(local_id, ref, version, snapshot, mode) do
    metadata =
      case room(local_id) do
        nil ->
          Repo.insert!(%ProtocolRoom{
            local_room_id: local_id,
            room_id: ref,
            version: version,
            create_id: snapshot.create["event_id"]
          })

        metadata ->
          unless metadata.room_id == ref and metadata.version == version and
                   metadata.create_id in ["", snapshot.create["event_id"]],
                 do: Repo.rollback(:wrong_room)

          if metadata.create_id == "",
            do:
              metadata
              |> Ecto.Changeset.change(create_id: snapshot.create["event_id"])
              |> Repo.update!(),
            else: metadata
      end

    event = preserve_content(event(snapshot.event["event_id"]), snapshot.event)
    id = event["event_id"]
    insert_outliers!(local_id, snapshot.graph, id)
    before = snapshot.state

    after_state =
      if Map.has_key?(event, "state_key"),
        do: Map.put(before, Authorization.key(event), id),
        else: before

    existing = event(id)
    current = decode_state(metadata.current_state)
    graph = load_graph(local_id, Map.keys(snapshot.graph)) |> Map.merge(snapshot.graph)

    current_auth =
      if metadata.extremities == [] or mode == :backfill,
        do: :ok,
        else: Authorization.check(event, materialize(current, graph), version)

    policy_state = if metadata.extremities == [], do: before, else: current
    policy_rejected = not Policy.recommended?(event, materialize(policy_state, graph), version)
    if mode == :join and policy_rejected, do: Repo.rollback(:policy_unavailable)
    if mode == :join and current_auth != :ok, do: Repo.rollback(:forbidden)
    record = existing || %Pdu{event_id: id, local_room_id: local_id}

    unless record.local_room_id == local_id and not record.auth_rejected,
      do: Repo.rollback(:rejected_event)

    record =
      record
      |> Ecto.Changeset.change(
        pdu: Map.drop(event, ["event_id", :auth_rejected]),
        state_before: encode_state(before),
        state_after: encode_state(after_state),
        outlier: false,
        soft_failed: current_auth != :ok or policy_rejected,
        policy_rejected: policy_rejected,
        received_at: ClientStore.now()
      )

    record = if existing, do: Repo.update!(record), else: Repo.insert!(record)
    LakehouseMatrix.Erasure.capture_pdus!([record.event_id])

    if mode != :backfill and current_auth == :ok and not policy_rejected do
      graph = Map.put(graph, id, event)
      heads = Enum.reject(metadata.extremities, &(&1 in event["prev_events"]))

      states = [
        after_state | Enum.map(heads, fn head -> decode_state(event(head).state_after) end)
      ]

      case StateResolution.resolve(states, graph, version) do
        {:ok, resolved} ->
          metadata
          |> Ecto.Changeset.change(
            current_state: encode_state(resolved),
            extremities: Enum.uniq([id | heads])
          )
          |> Repo.update!()

          previous =
            if metadata.extremities == [] do
              project_state!(metadata, %{}, before)
              before
            else
              current
            end

          unless Repo.exists?(from e in RoomEvent, where: e.event_id == ^id),
            do: project!(metadata, record, previous, resolved)

          enqueue!(metadata, event, resolved, graph)

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end

    LakehouseMatrix.Protocol.Redactions.apply!(metadata, id)
    event
  end

  defp insert_outliers!(local_id, graph, target) do
    for chunk <- Enum.chunk_every(Map.to_list(graph), 500) do
      entries =
        for {event_id, wire} <- chunk, event_id != target do
          %{
            event_id: event_id,
            local_room_id: ClientStore.dump_id(local_id),
            pdu: Map.drop(wire, ["event_id", :auth_rejected]),
            outlier: true,
            received_at: ClientStore.now()
          }
        end

      if entries != [],
        do:
          Repo.insert_all("matrix_pdus", entries,
            on_conflict: :nothing,
            conflict_target: [:event_id]
          )

      LakehouseMatrix.Erasure.capture_pdus!(Enum.map(entries, & &1.event_id))
    end

    :ok
  end

  def state_at_stream(local_id, high) do
    Repo.all(
      from c in "matrix_state_changes",
        where: c.local_room_id == type(^local_id, :binary_id) and c.stream_id <= ^high,
        distinct: [c.type, c.state_key],
        order_by: [c.type, c.state_key, desc: c.stream_id],
        select: {c.type, c.state_key, c.event_id}
    )
    |> Enum.reject(fn {_, _, id} -> is_nil(id) end)
    |> Map.new(fn {type, key, id} -> {{type, key}, id} end)
  end

  def state_position(local_id, event_id, high) do
    Repo.one(
      from c in "matrix_state_changes",
        where:
          c.local_room_id == type(^local_id, :binary_id) and c.event_id == ^event_id and
            c.stream_id <= ^high,
        select: max(c.stream_id)
    ) || 0
  end

  def activity(local_ids, high) do
    Repo.all(
      from c in "matrix_state_changes",
        where: c.local_room_id in type(^local_ids, {:array, :binary_id}) and c.stream_id <= ^high,
        group_by: c.local_room_id,
        select: {type(c.local_room_id, :binary_id), max(c.stream_id)}
    )
    |> Map.new()
  end

  def auth_chain(ids, graph) do
    refs = Enum.flat_map(ids, fn id -> graph[id]["auth_events"] || [] end)
    collect_auth(refs, graph, MapSet.new()) |> MapSet.to_list() |> Enum.sort()
  end

  defp collect_auth([], _, seen), do: seen

  defp collect_auth([id | rest], graph, seen) do
    if MapSet.member?(seen, id),
      do: collect_auth(rest, graph, seen),
      else: collect_auth((graph[id]["auth_events"] || []) ++ rest, graph, MapSet.put(seen, id))
  end

  defp accept_locked(metadata, verified, graph) do
    id = verified["event_id"]
    existing = event(id)
    verified = preserve_content(existing, verified)

    cond do
      existing &&
          (existing.local_room_id != metadata.local_room_id or
             (not existing.outlier and
                not (existing.policy_rejected and
                         Policy.recommended?(
                           verified,
                           materialize(decode_state(metadata.current_state), graph),
                           metadata.version
                         )))) ->
        if existing.local_room_id == metadata.local_room_id and not existing.auth_rejected and
             not existing.state_rejected,
           do: {:ok, Map.put(existing.pdu, "event_id", id)},
           else: {:error, :rejected_event}

      verified["type"] == "m.room.create" ->
        {:error, :conflicting_create_event}

      Enum.any?(verified["prev_events"], &is_nil(graph[&1])) ->
        {:error, :missing_prev_event}

      Enum.any?(verified["auth_events"], &is_nil(graph[&1])) ->
        {:error, :missing_auth_event}

      verified["prev_events"] == [] ->
        {:error, :missing_prev_event}

      true ->
        states =
          Enum.map(verified["prev_events"], fn parent ->
            record = event(parent)
            if record.outlier, do: Repo.rollback(:missing_prev_state)
            decode_state(record.state_after)
          end)

        before =
          case StateResolution.resolve(states, graph, metadata.version) do
            {:ok, state} -> state
            {:error, reason} -> Repo.rollback(reason)
          end

        create = graph[metadata.create_id]
        auth = Authorization.check_auth_events(verified, graph, metadata.version, create)

        if auth != :ok do
          reject!(metadata, verified, before)
          auth
        else
          with true <- true do
            at_event = Authorization.check(verified, materialize(before, graph), metadata.version)
            current = decode_state(metadata.current_state)

            policy_rejected =
              not Policy.recommended?(verified, materialize(current, graph), metadata.version)

            soft_failed =
              policy_rejected or
                Authorization.check(verified, materialize(current, graph), metadata.version) !=
                  :ok

            state_after =
              if at_event == :ok and Map.has_key?(verified, "state_key"),
                do: Map.put(before, Authorization.key(verified), id),
                else: before

            record =
              persist_record!(existing, metadata.local_room_id, id, %{
                pdu: Map.drop(verified, ["event_id", :auth_rejected]),
                state_before: encode_state(before),
                state_after: encode_state(state_after),
                outlier: false,
                state_rejected: at_event != :ok,
                soft_failed: soft_failed,
                policy_rejected: policy_rejected,
                received_at: ClientStore.now()
              })

            if at_event != :ok do
              at_event
            else
              graph = Map.put(graph, id, Map.put(verified, :auth_rejected, false))
              # A late parent must not become an extremity when an accepted
              # child is already known. Soft-failed events cannot become local
              # prev events or advance the visible state.
              unless soft_failed do
                referenced = Enum.any?(graph, fn {_, e} -> id in (e["prev_events"] || []) end)
                extremities = Enum.reject(metadata.extremities, &(&1 in verified["prev_events"]))
                extremities = if referenced, do: extremities, else: Enum.uniq([id | extremities])

                states =
                  Enum.map(extremities, fn parent -> decode_state(event(parent).state_after) end)

                case StateResolution.resolve(states, graph, metadata.version) do
                  {:ok, resolved} ->
                    metadata
                    |> Ecto.Changeset.change(
                      current_state: encode_state(resolved),
                      extremities: extremities
                    )
                    |> Repo.update!()

                    project!(metadata, record, current, resolved)
                    enqueue!(metadata, verified, resolved, graph)

                  {:error, reason} ->
                    Repo.rollback(reason)
                end
              end

              {:ok, verified}
            end
          end
        end
    end
  end

  defp reject!(metadata, event, before) do
    persist_record!(event(event["event_id"]), metadata.local_room_id, event["event_id"], %{
      pdu: Map.drop(event, ["event_id", :auth_rejected]),
      state_before: encode_state(before),
      state_after: encode_state(before),
      outlier: false,
      auth_rejected: true,
      received_at: ClientStore.now()
    })
  end

  defp persist_record!(nil, room, id, attrs),
    do:
      %Pdu{event_id: id, local_room_id: room}
      |> Ecto.Changeset.change(attrs)
      |> Repo.insert!()
      |> tap(fn _ -> LakehouseMatrix.Erasure.capture_pdus!([id]) end)

  defp persist_record!(record, _, _, attrs),
    do:
      record
      |> Ecto.Changeset.change(attrs)
      |> Repo.update!()
      |> tap(fn updated -> LakehouseMatrix.Erasure.capture_pdus!([updated.event_id]) end)

  # A pruned copy received later must not destroy an already verified body.
  # Signatures from the newly verified envelope still apply to the same reference
  # hash, including its original content hash.
  defp preserve_content(existing, verified) do
    if not is_nil(existing) and is_nil(existing.redacted_by) and
         Event.content_intact?(existing.pdu) and not Event.content_intact?(verified) do
      existing.pdu
      |> Map.put("event_id", existing.event_id)
      |> Map.put("signatures", verified["signatures"])
    else
      verified
    end
  end

  defp project!(metadata, record, previous, resolved \\ nil) do
    event = Map.put(record.pdu, "event_id", record.event_id)
    ctx = context(metadata.local_room_id, event)

    case Repo.get_by(RoomEvent, event_id: record.event_id) do
      nil ->
        case Events.persist(ctx, %{
               "content" => event["content"],
               "timeline_visible" => event["type"] != "m.room.redaction"
             }) do
          {:ok, _} -> :ok
          {:error, reason} -> Repo.rollback(reason)
        end

      existing ->
        unless existing.room_id == metadata.local_room_id, do: Repo.rollback(:wrong_room)
        existing |> Ecto.Changeset.change(content: event["content"]) |> Repo.update!()
    end

    resolved = resolved || decode_state(record.state_after)
    project_state!(metadata, previous, resolved)
    LakehouseMatrix.Protocol.Redactions.apply!(metadata, record.event_id)

    LakehouseMatrix.MediaReferences.capture!(
      Repo.get_by!(RoomEvent, event_id: record.event_id),
      metadata
    )

    if record.pdu["type"] != "m.room.redaction" and is_nil(event(record.event_id).redacted_by),
      do: LakehouseMatrix.Notifications.record!(metadata, record)
  end

  defp project_state!(metadata, previous, resolved) do
    graph = load_graph(metadata.local_room_id)

    for {key, id} <- resolved, previous[key] != id do
      e = graph[id]

      unless Repo.exists?(from record in RoomEvent, where: record.event_id == ^id) do
        case Events.persist(context(metadata.local_room_id, e), %{
               "content" => e["content"],
               "timeline_visible" => false
             }) do
          {:ok, _} -> :ok
          {:error, reason} -> Repo.rollback(reason)
        end
      end

      {type, state_key} = key

      State.upsert(
        metadata.local_room_id,
        state_key,
        type,
        e["content"],
        id,
        e["origin_server_ts"]
      )

      state_change!(metadata.local_room_id, type, state_key, id)
      project_member!(metadata.local_room_id, e)
      project_room!(metadata.local_room_id, e)
    end

    for {{type, key}, _} <- previous, not Map.has_key?(resolved, {type, key}) do
      Repo.delete_all(
        from s in RoomState,
          where: s.room_id == ^metadata.local_room_id and s.type == ^type and s.state_key == ^key
      )

      state_change!(metadata.local_room_id, type, key, nil)

      if type == "m.room.member" do
        with {:ok, name} <- Identity.parse_user_id(key), {:ok, p} <- Accounts.fetch_user(name) do
          Repo.delete_all(
            from m in RoomMembership,
              where: m.room_id == ^metadata.local_room_id and m.principal_id == ^p.id
          )
        end
      end
    end
  end

  defp project_member!(room, %{"type" => "m.room.member"} = event) do
    with {:ok, name} <- Identity.parse_user_id(event["state_key"]),
         {:ok, p} <- Accounts.fetch_user(name) do
      case Memberships.upsert_membership(
             room,
             p.id,
             event["content"]["membership"],
             context(room, event)
           ) do
        {:ok, _} -> :ok
        {:error, reason} -> Repo.rollback(reason)
      end
    end
  end

  defp project_member!(_, _), do: :ok

  defp project_room!(room, event) do
    attrs =
      case {event["type"], event["state_key"]} do
        {"m.room.name", ""} ->
          [name: if(is_binary(event["content"]["name"]), do: event["content"]["name"], else: "")]

        {"m.room.topic", ""} ->
          [
            topic:
              if(is_binary(event["content"]["topic"]), do: event["content"]["topic"], else: "")
          ]

        {"m.room.avatar", ""} ->
          [avatar_url: if(is_binary(event["content"]["url"]), do: event["content"]["url"])]

        _ ->
          []
      end

    if attrs != [], do: Repo.update_all(from(r in Room, where: r.id == ^room), set: attrs)
  end

  defp context(room, event) do
    principal =
      with {:ok, name} <- Identity.parse_user_id(event["sender"]),
           {:ok, p} <- Accounts.fetch_user(name),
           do: p.id

    %Context{
      room_id: room,
      principal_id: if(is_binary(principal), do: principal),
      sender: event["sender"],
      event_id: event["event_id"],
      type: event["type"],
      content: event["content"],
      state_key: event["state_key"],
      origin_server_ts: event["origin_server_ts"]
    }
  end

  defp enqueue!(metadata, event, resolved, graph) do
    local = Identity.homeserver_domain()
    {:ok, author} = Event.user_domain(event["sender"])
    # Only a server that authored or co-signed an event sends it onward; received
    # transactions are never broadcast back around the federation graph.
    signed_locally =
      case Signing.config() do
        {:ok, seed, key} ->
          Signing.verify(
            Event.redact(Map.delete(event, "event_id"), metadata.version),
            Signing.public_key(seed),
            key,
            local
          )

        _ ->
          false
      end

    if signed_locally do
      memberships = Map.to_list(resolved) ++ Map.to_list(decode_state(metadata.current_state))

      destinations =
        for {{"m.room.member", user}, id} <- memberships,
            graph[id]["content"]["membership"] == "join",
            {:ok, server} <- [Event.user_domain(user)],
            server != local and server != author,
            do: server

      for server <- Enum.uniq(destinations) do
        wire = event(event["event_id"]).pdu

        Repo.insert_all(
          "matrix_federation_outbox",
          [
            %{
              destination: server,
              event_id: event["event_id"],
              kind: "pdu",
              payload: %{
                "origin" => local,
                "origin_server_ts" => System.system_time(:millisecond),
                "pdus" => [wire],
                "edus" => []
              },
              attempts: 0,
              available_at: ClientStore.now(),
              transaction_id: ClientStore.random()
            }
          ],
          on_conflict: :nothing,
          conflict_target: [:destination, :event_id]
        )
      end

      if event["type"] == "m.room.member" and get_in(event, ["content", "membership"]) == "invite" do
        with {:ok, server} <- Event.user_domain(event["state_key"]), true <- server != local do
          stripped =
            Enum.map(resolved, fn {_, id} -> graph[id] end)
            |> Enum.filter(
              &(&1["type"] in ~w(m.room.create m.room.name m.room.avatar m.room.topic m.room.join_rules m.room.encryption m.room.canonical_alias))
            )
            |> Enum.map(&Map.take(&1, ~w(type state_key sender content)))

          payload = %{
            "room_version" => metadata.version,
            "event" => Map.drop(event, ["event_id", :auth_rejected]),
            "invite_room_state" => stripped
          }

          Repo.insert_all(
            "matrix_federation_outbox",
            [
              %{
                destination: server,
                event_id: event["event_id"],
                kind: "invite",
                payload: payload,
                attempts: 0,
                available_at: ClientStore.now(),
                transaction_id: ClientStore.random()
              }
            ],
            on_conflict: [set: [kind: "invite", payload: payload]],
            conflict_target: [:destination, :event_id]
          )
        end
      end
    end

    metadata
  end

  defp materialize(state, graph), do: Map.new(state, fn {key, id} -> {key, graph[id]} end)

  defp state_change!(room, type, key, id) do
    Repo.insert_all("matrix_state_changes", [
      %{local_room_id: ClientStore.dump_id(room), type: type, state_key: key, event_id: id}
    ])
  end

  defp seal!(event, version) do
    case Signing.config() do
      {:ok, seed, key} -> Event.sign(event, version, seed, key, Identity.homeserver_domain())
      _ -> Repo.rollback(:signing_not_configured)
    end
  rescue
    ArgumentError -> Repo.rollback(:invalid_param)
  end

  defp require_ok!(:ok), do: :ok
  defp require_ok!({:error, reason}), do: Repo.rollback(reason)

  defp require_local_sender!(sender) do
    unless Event.user_domain(sender) == {:ok, Identity.homeserver_domain()},
      do: Repo.rollback(:foreign_sender)
  end

  defp transact(fun),
    do:
      Policy.transaction(fn ->
        ClientStore.lock!()
        fun.()
      end)
end
