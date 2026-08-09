defmodule LakehouseMatrix.Sync do
  @moduledoc """
  Incremental sync token helpers.
  """
  import Ecto.Query

  alias LakehouseIam.Repo
  alias LakehouseMatrix.{Events, Identity, Memberships, State}
  alias LakehouseMatrix.Schema.RoomEvent

  @spec current_token() :: String.t()
  def current_token do
    case Repo.one(from e in RoomEvent, select: max(e.origin_server_ts)) do
      nil -> "s0"
      ts -> "s#{ts}"
    end
  end

  @spec parse_token(String.t() | nil) :: integer()
  def parse_token(nil), do: 0
  def parse_token("s" <> rest), do: String.to_integer(rest)
  def parse_token(_), do: 0

  @spec sync(Ecto.UUID.t(), String.t() | nil, keyword()) :: map()
  def sync(principal_id, since_token, opts \\ []) do
    since_ts = parse_token(since_token)
    full_state = Keyword.get(opts, :full_state, since_token == nil)

    room_ids = Memberships.joined_room_ids(principal_id)

    rooms_join =
      Enum.into(room_ids, %{}, fn room_id ->
        {Identity.room_id(room_id), room_payload(room_id, principal_id, since_ts, full_state)}
      end)

  %{
    "next_batch" => current_token(),
    "rooms" => %{"join" => rooms_join}
  }
  end

  defp room_payload(room_id, _principal_id, since_ts, full_state) do
    timeline_events =
      if full_state do
        Events.list_timeline(room_id, limit: 100)
      else
        Events.list_since(since_ts, room_ids: [room_id])
        |> Enum.reject(& &1.state_key)
        |> Enum.map(&Events.to_client_event/1)
      end

    state_events =
      if full_state do
        State.list_for_room(room_id)
      else
        Events.list_since(since_ts, room_ids: [room_id])
        |> Enum.filter(& &1.state_key)
        |> Enum.map(&Events.to_client_event/1)
      end

    %{
      "timeline" => %{
        "events" => timeline_events,
        "limited" => false,
        "prev_batch" => "t#{since_ts}"
      },
      "state" => %{"events" => state_events},
      "summary" => %{
        "m.joined_member_count" => Memberships.member_count(room_id),
        "m.invited_member_count" => 0
      }
    }
  end
end
