defmodule LakehouseMatrix.RiverFiles do
  @moduledoc "Room-authorized peer file manifests. Bytes stay on participating devices, as in Orbit."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{DelegatedGroups, Identity, Erasure}
  alias LakehouseMatrix.Schema.RiverFile
  @key "cool.gravitas.river.attachments"
  def list(g, room, p) do
    DelegatedGroups.with_room(g, room, "chats.read", fn ->
      events = Erasure.event_query(g.principal_id)

      query =
        from f in RiverFile,
          join: event in subquery(events),
          on: event.event_id == f.event_id,
          where: f.room_id == ^room,
          where:
            fragment(
              "COALESCE(?->'cool.gravitas.river.attachments', '[]'::jsonb) @> jsonb_build_array(?)",
              event.content,
              f.manifest
            ),
          order_by: [desc: f.inserted_at, desc: f.id]

      if p["file_id"] do
        unless uuid?(p["file_id"]), do: Repo.rollback(:invalid_request)
        file = Repo.one(from f in query, where: f.id == ^p["file_id"])
        if is_nil(file), do: Repo.rollback(:not_found)
        %{attachment: file.manifest}
      else
        %{attachments: Repo.all(from f in query, limit: 200) |> Enum.map(& &1.manifest)}
      end
    end)
  end

  def validate(content, room) do
    files = content[@key] || []

    valid =
      is_list(files) and length(files) <= 5 and Enum.all?(files, &valid?(&1, room)) and
        Enum.uniq_by(files, & &1["id"]) == files and
        Enum.sum(Enum.map(files, & &1["size"])) <= 50 * 1024 * 1024

    if valid, do: :ok, else: {:error, :invalid_attachment}
  end

  def register!(g, room, event, content) do
    for file <- content[@key] || [] do
      case Repo.get(RiverFile, file["id"]) do
        nil ->
          Repo.insert!(%RiverFile{
            id: file["id"],
            room_id: room,
            uploader_id: g.principal_id,
            event_id: event["event_id"],
            manifest: file
          })

          DelegatedGroups.content_event!(
            g,
            room,
            "cool.gravitas.river.attachment.v1",
            %{
              "version" => 1,
              "file" => file,
              "m.relates_to" => %{"rel_type" => "m.reference", "event_id" => event["event_id"]},
              "room_id" => Identity.room_id(room)
            },
            "attachment-" <> file["id"]
          )

        existing ->
          unless existing.room_id == room and existing.uploader_id == g.principal_id and
                   existing.event_id == event["event_id"] and existing.manifest == file,
                 do: Repo.rollback(:transaction_conflict)
      end
    end

    :ok
  end

  defp valid?(f, room) when is_map(f) do
    uuid?(f["id"]) and f["scope"] == "room" and f["targetId"] == room and
      text?(f["name"], 255) and not String.match?(f["name"], ~r/[\x00-\x1f\x7f\/\\]/) and
      is_integer(f["size"]) and f["size"] in 1..(25 * 1024 * 1024) and
      text?(f["mime"], 120) and
      String.match?(f["mime"], ~r/^[a-z0-9!\#$&^_.+-]+\/[a-z0-9!\#$&^_.+-]+$/) and
      is_binary(f["sha256"]) and String.match?(f["sha256"], ~r/^[a-f0-9]{64}$/)
  end

  defp valid?(_, _), do: false
  defp uuid?(s), do: is_binary(s) and match?({:ok, _}, Ecto.UUID.cast(s))
  defp text?(s, n), do: is_binary(s) and byte_size(s) in 1..n and String.trim(s) != ""
end
