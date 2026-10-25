defmodule LakehouseMatrix.Reports do
  @moduledoc "Private moderation reports with bounded reasons, per-user limits and concealed unknown targets."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientRoomData, ClientRooms, ClientStore}
  alias LakehouseMatrix.Protocol.Event

  def submit(principal, kind, target, params, event \\ nil) do
    reason = params["reason"]
    reason = if is_nil(reason) and kind == "event", do: "", else: reason

    valid_target =
      case kind do
        "user" ->
          is_binary(target) and byte_size(target) <= 255 and
            match?({:ok, _}, Event.user_domain(target))

        kind when kind in ["room", "event"] ->
          ClientRoomData.valid_room_ref?(target)

        _ ->
          false
      end

    cond do
      not valid_target ->
        {:error, :invalid_param}

      is_nil(reason) ->
        {:error, :missing_param}

      not is_binary(reason) ->
        {:error, :invalid_param}

      byte_size(reason) > 16_384 ->
        {:error, :limit_exceeded}

      kind == "event" and
          not (is_binary(event) and byte_size(event) in 2..255 and String.starts_with?(event, "$")) ->
        {:error, :invalid_param}

      true ->
        Repo.transaction(fn ->
          ClientStore.lock!()
          recent = DateTime.add(ClientStore.now(), -60, :second)

          count =
            Repo.aggregate(
              from(r in "matrix_reports",
                where: r.principal_id == type(^principal, :binary_id) and r.inserted_at >= ^recent
              ),
              :count
            )

          if count >= 10, do: Repo.rollback(:rate_limited)

          if kind != "event" or event_visible?(principal, target, event) do
            Repo.insert_all("matrix_reports", [
              %{
                id: ClientStore.dump_id(Ecto.UUID.generate()),
                principal_id: ClientStore.dump_id(principal),
                kind: kind,
                room_ref: if(kind in ["room", "event"], do: target),
                event_id: event,
                user_id: if(kind == "user", do: target),
                reason: reason,
                inserted_at: ClientStore.now()
              }
            ])
          end

          %{}
        end)
    end
  end

  defp event_visible?(principal, ref, id),
    do:
      match?({:ok, _}, ClientRooms.readable(principal, ref)) and
        match?({:ok, _}, ClientRooms.event(principal, ref, id))
end
