defmodule LakehouseMatrix.Protocol.Redactions do
  @moduledoc "Apply v11/v12 redactions only after both events and the redaction's authenticated state are known."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.ClientStore
  alias LakehouseMatrix.Protocol.{Authorization, Event, Graph}
  alias LakehouseMatrix.Schema.{Pdu, Room, RoomEvent, RoomState}

  def apply!(metadata, id) do
    record = Graph.event(id)

    if record.pdu["type"] == "m.room.redaction" do
      with target when is_binary(target) <- get_in(record.pdu, ["content", "redacts"]),
           target when not is_nil(target) <- Graph.event(target),
           do: apply_one!(metadata, record, target)
    else
      for redaction <-
            Repo.all(
              from p in Pdu,
                where:
                  p.local_room_id == ^metadata.local_room_id and
                    fragment(
                      "?->>'type' = 'm.room.redaction' AND ?->'content'->>'redacts' = ?",
                      p.pdu,
                      p.pdu,
                      ^id
                    )
            ) do
        apply_one!(metadata, redaction, Graph.event(id))
      end
    end
  end

  def allowed?(metadata, redaction, target) do
    if redaction.local_room_id == target.local_room_id and
         redaction.local_room_id == metadata.local_room_id and
         not (redaction.auth_rejected or redaction.state_rejected or redaction.soft_failed or
                redaction.outlier) do
      graph = Graph.load_graph(metadata.local_room_id, [redaction.event_id, target.event_id])

      state =
        Map.new(Graph.decode_state(redaction.state_before), fn {key, id} -> {key, graph[id]} end)

      Authorization.gte?(
        Authorization.power(state, redaction.pdu["sender"], metadata.version),
        Authorization.level(state, "redact", 50)
      ) or
        Event.user_domain(redaction.pdu["sender"]) == Event.user_domain(target.pdu["sender"])
    else
      false
    end
  end

  defp apply_one!(metadata, redaction, target) do
    if allowed?(metadata, redaction, target) do
      Repo.update_all(from(p in Pdu, where: p.event_id == ^redaction.event_id),
        set: [redaction_applied: true]
      )

      if is_nil(target.redacted_by) do
        pruned = Event.redact(target.pdu, metadata.version)
        # Unsigned information is not included in hashes or signatures. Never
        # reintroduce the original content through unsigned.redacted_because.
        pruned =
          if is_map(target.pdu["unsigned"]),
            do:
              Map.put(pruned, "unsigned", Map.drop(target.pdu["unsigned"], ["redacted_because"])),
            else: pruned

        Repo.update_all(from(p in Pdu, where: p.event_id == ^target.event_id),
          set: [pdu: pruned, redacted_by: redaction.event_id]
        )

        Repo.update_all(from(e in RoomEvent, where: e.event_id == ^target.event_id),
          set: [content: pruned["content"]]
        )

        state_content =
          Map.merge(pruned["content"], %{
            "_event_id" => target.event_id,
            "_origin_server_ts" => pruned["origin_server_ts"]
          })

        {changed, _} =
          Repo.update_all(
            from(s in RoomState,
              where:
                s.room_id == ^metadata.local_room_id and
                  fragment("?->>'_event_id' = ?", s.content, ^target.event_id)
            ),
            set: [content: state_content]
          )

        if changed > 0 do
          Repo.insert_all("matrix_state_changes", [
            %{
              local_room_id: ClientStore.dump_id(metadata.local_room_id),
              type: pruned["type"],
              state_key: pruned["state_key"],
              event_id: target.event_id
            }
          ])

          attrs =
            case {pruned["type"], pruned["state_key"]} do
              {"m.room.name", ""} -> [name: ""]
              {"m.room.topic", ""} -> [topic: ""]
              {"m.room.avatar", ""} -> [avatar_url: nil]
              _ -> []
            end

          if attrs != [],
            do:
              Repo.update_all(from(r in Room, where: r.id == ^metadata.local_room_id), set: attrs)
        end
      end

      reveal!(redaction.event_id)
    end
  end

  defp reveal!(id) do
    record = Repo.get_by(RoomEvent, event_id: id)

    if record && not record.timeline_visible do
      [[position]] =
        Repo.query!(
          "UPDATE matrix_stream SET position = position + 1 WHERE id = 1 RETURNING position",
          []
        ).rows

      Repo.update_all(from(e in RoomEvent, where: e.event_id == ^id),
        set: [timeline_visible: true, stream_id: position]
      )
    end
  end
end
