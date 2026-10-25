defmodule LakehouseMatrix.MediaReferences do
  @moduledoc "Private legacy media grants require an authorized, typed attachment reference; federation sharing promotes only readable assets."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientRooms, ClientStore, Events, Identity, Media, State}
  alias LakehouseMatrix.Protocol.Graph
  alias LakehouseMatrix.Schema.{MediaObject, RoomEvent, RoomMembership}

  def capture!(%RoomEvent{principal_id: nil}, _), do: :ok

  def capture!(event, metadata) do
    ids = event |> Events.to_client_event() |> ids()
    records = Repo.all(from m in MediaObject, where: m.id in ^ids and m.matrix_public == false)
    records = Enum.filter(records, &Media.accessible?(event.principal_id, &1))

    if records != [] do
      Repo.insert_all(
        "matrix_private_media_refs",
        Enum.map(
          records,
          &%{
            media_id: ClientStore.dump_id(&1.id),
            event_id: ClientStore.dump_id(event.id),
            room_id: ClientStore.dump_id(event.room_id)
          }
        ),
        on_conflict: :nothing
      )

      if metadata && Graph.event(metadata.create_id).pdu["content"]["m.federate"] != false,
        do: Enum.each(records, &publish!/1)
    end

    :ok
  end

  def publish_profile!(principal, uri) do
    with id when is_binary(id) <- own_id(uri),
         %MediaObject{} = record <- Repo.get(MediaObject, id),
         true <- Media.accessible?(principal, record),
         do: publish!(record)

    :ok
  end

  defp publish!(%{matrix_public: true}), do: :ok

  defp publish!(record) do
    ids = Enum.reject([record.id, record.thumbnail_id], &is_nil/1)

    Repo.update_all(
      from(m in MediaObject, where: m.id in ^ids and m.uploader_id == ^record.uploader_id),
      set: [matrix_public: true]
    )
  end

  def can_read?(principal, record) do
    references =
      Repo.all(
        from r in "matrix_private_media_refs",
          join: e in RoomEvent,
          on: e.id == r.event_id,
          join: m in RoomMembership,
          on: m.room_id == r.room_id,
          where:
            r.media_id == type(^record.id, :binary_id) and m.principal_id == ^principal and
              fragment("?->>'membership' = 'join'", m.membership_state),
          select: e
      )

    Enum.any?(references, fn event ->
      allowed =
        LakehouseMatrix.RiverRtc.chat_allowed?(event.room_id, principal) and
          LakehouseMatrix.RiverPublishing.reader_allowed?(event.room_id, principal)

      allowed and record.id in ids(Events.to_client_event(event, principal)) and
        (current_state?(event) or
           match?(
             {:ok, _},
             ClientRooms.event(principal, Identity.room_id(event.room_id), event.event_id)
           ))
    end)
  end

  defp current_state?(%{state_key: nil}), do: false

  defp current_state?(event) do
    case Graph.room(event.room_id) do
      nil ->
        (State.get(event.room_id, event.type, event.state_key) || %{})["event_id"] ==
          event.event_id

      metadata ->
        metadata.current_state[Jason.encode!([event.type, event.state_key])] == event.event_id
    end
  end

  def ids(event) do
    content = event["content"] || %{}

    paths =
      case event["type"] do
        type when type in ["m.room.message", "m.sticker", "m.room.avatar"] ->
          [["url"], ["file", "url"], ["info", "thumbnail_url"], ["info", "thumbnail_file", "url"]]

        "m.room.member" ->
          [["avatar_url"]]

        _ ->
          []
      end

    paths
    |> Enum.map(fn path ->
      Enum.reduce(path, content, fn key, data -> if is_map(data), do: data[key] end)
    end)
    |> Enum.map(&own_id/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp own_id("mxc://" <> rest) do
    with [server, id] <- String.split(rest, "/"),
         true <- server == Identity.homeserver_domain(),
         {:ok, id} <- Ecto.UUID.cast(id),
         do: id,
         else: (_ -> nil)
  end

  defp own_id(_), do: nil
end
