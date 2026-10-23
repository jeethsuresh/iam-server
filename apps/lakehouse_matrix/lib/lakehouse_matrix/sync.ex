defmodule LakehouseMatrix.Sync do
  @moduledoc """
  Incremental sync token helpers and Client-Server `/sync` payload builder.
  """
  import Ecto.Query

  alias LakehouseIam.Repo
  alias LakehouseMatrix.{Events, Identity, Memberships, State}
  alias LakehouseMatrix.Schema.RoomEvent

  @default_timeout_ms 0
  @max_timeout_ms 30_000
  @poll_ms 200

  @spec current_token() :: String.t()
  def current_token do
    case Repo.one(from e in RoomEvent, select: max(e.origin_server_ts)) do
      nil -> "s0"
      ts -> "s#{ts}"
    end
  end

  @spec parse_token(String.t() | nil) :: integer()
  def parse_token(nil), do: 0
  def parse_token("s" <> rest) do
    case Integer.parse(rest) do
      {n, _} -> n
      :error -> 0
    end
  end

  def parse_token(_), do: 0

  @spec sync(Ecto.UUID.t(), String.t() | nil, keyword()) :: map()
  def sync(principal_id, since_token, opts \\ []) do
    timeout =
      opts
      |> Keyword.get(:timeout, @default_timeout_ms)
      |> clamp_timeout()

    full_state = Keyword.get(opts, :full_state, since_token == nil)
    since_ts = parse_token(since_token)

    payload = build_sync(principal_id, since_ts, full_state)

    if timeout > 0 and empty_delta?(payload) and since_token != nil do
      wait_for_delta(principal_id, since_token, since_ts, full_state, timeout)
    else
      payload
    end
  end

  defp wait_for_delta(principal_id, since_token, since_ts, full_state, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout

    Stream.repeatedly(fn ->
      remaining = deadline - System.monotonic_time(:millisecond)

      if remaining <= 0 do
        {:halt, build_sync(principal_id, since_ts, full_state)}
      else
        Process.sleep(min(@poll_ms, remaining))
        payload = build_sync(principal_id, since_ts, full_state)

        if empty_delta?(payload) do
          :continue
        else
          {:halt, payload}
        end
      end
    end)
    |> Enum.reduce_while(nil, fn
      :continue, _ -> {:cont, nil}
      {:halt, payload}, _ -> {:halt, payload}
    end)
    |> case do
      nil -> build_sync(principal_id, parse_token(since_token), full_state)
      payload -> payload
    end
  end

  defp build_sync(principal_id, since_ts, full_state) do
    join_ids = Memberships.joined_room_ids(principal_id)

    rooms_join =
      Enum.into(join_ids, %{}, fn room_id ->
        {Identity.room_id(room_id), room_payload(room_id, since_ts, full_state)}
      end)

    invite_ids =
      if full_state or since_ts == 0 do
        Memberships.invited_room_ids(principal_id)
      else
        Memberships.room_ids_changed_since(principal_id, "invite", since_ts)
      end

    rooms_invite =
      Enum.into(invite_ids, %{}, fn room_id ->
        {Identity.room_id(room_id), invite_payload(room_id)}
      end)

    leave_ids =
      if full_state or since_ts == 0 do
        []
      else
        Memberships.room_ids_changed_since(principal_id, "leave", since_ts)
      end

    rooms_leave =
      Enum.into(leave_ids, %{}, fn room_id ->
        {Identity.room_id(room_id), leave_payload(room_id, since_ts)}
      end)

    %{
      "next_batch" => current_token(),
      "rooms" => %{
        "join" => rooms_join,
        "invite" => rooms_invite,
        "leave" => rooms_leave
      }
    }
  end

  defp empty_delta?(%{"rooms" => rooms}) do
    joins = rooms["join"] || %{}
    invites = rooms["invite"] || %{}
    leaves = rooms["leave"] || %{}

    no_join_updates =
      Enum.all?(joins, fn {_id, payload} ->
        timeline = get_in(payload, ["timeline", "events"]) || []
        state = get_in(payload, ["state", "events"]) || []
        timeline == [] and state == []
      end)

    no_join_updates and map_size(invites) == 0 and map_size(leaves) == 0
  end

  defp room_payload(room_id, since_ts, full_state) do
    timeline_events =
      if full_state do
        Events.list_all_timeline(room_id, 100)
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
        "m.invited_member_count" => Memberships.invited_count(room_id)
      }
    }
  end

  defp invite_payload(room_id) do
    %{
      "invite_state" => %{
        "events" => State.list_for_room(room_id)
      }
    }
  end

  defp leave_payload(room_id, since_ts) do
    timeline =
      Events.list_since(since_ts, room_ids: [room_id])
      |> Enum.map(&Events.to_client_event/1)

    %{
      "timeline" => %{
        "events" => timeline,
        "limited" => false,
        "prev_batch" => "t#{since_ts}"
      }
    }
  end

  defp clamp_timeout(t) when is_integer(t) and t > 0, do: min(t, @max_timeout_ms)
  defp clamp_timeout(_), do: 0
end
