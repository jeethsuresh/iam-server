defmodule LakehouseMatrix.Events.Handlers.RoomMember do
  @moduledoc false
  @behaviour LakehouseMatrix.Events.Handler

  alias LakehouseMatrix.Events.Context
  alias LakehouseMatrix.{Memberships, State}

  @impl true
  def handle(%Context{state_key: state_key} = ctx) when is_binary(state_key) do
    membership = Map.get(ctx.content, "membership")

    with :ok <- validate_membership(membership),
         {:ok, _} <- Memberships.apply_membership(ctx.room_id, state_key, membership, ctx),
         :ok <- State.upsert(ctx.room_id, state_key, ctx.type, ctx.content, ctx.event_id, ctx.origin_server_ts) do
      {:ok, to_event_map(ctx)}
    end
  end

  def handle(_), do: {:error, :missing_state_key}

  defp validate_membership(m) when m in ["join", "leave", "invite", "ban"], do: :ok
  defp validate_membership(_), do: {:error, :invalid_membership}

  defp to_event_map(ctx) do
    %{
      "event_id" => ctx.event_id,
      "type" => ctx.type,
      "sender" => ctx.sender,
      "origin_server_ts" => ctx.origin_server_ts,
      "content" => ctx.content,
      "state_key" => ctx.state_key
    }
  end
end
