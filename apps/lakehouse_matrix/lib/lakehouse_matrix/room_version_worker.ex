defmodule LakehouseMatrix.RoomVersionWorker do
  @moduledoc "Periodic, durable reconciliation of managed rooms against confirmed peer capabilities."
  use GenServer
  import Ecto.Query
  alias LakehouseIam.{Accounts, IAM, Repo}
  alias LakehouseMatrix.{ClientStore, Identity, RoomUpgrades, RoomVersions}
  alias LakehouseMatrix.Federation.RoomAccess
  alias LakehouseMatrix.Protocol.{Authorization, Graph, Policy}

  def start_link(options), do: GenServer.start_link(__MODULE__, options, name: __MODULE__)
  def init(_), do: {:ok, schedule()}

  def handle_info(:check, _) do
    run_once()
    {:noreply, schedule()}
  end

  defp schedule, do: Process.send_after(self(), :check, 10_000)

  def run_once do
    now = ClientStore.now()

    rooms =
      Repo.all(
        from r in LakehouseMatrix.Schema.ProtocolRoom,
          left_join: c in "matrix_room_version_checks",
          on: c.room_id == r.local_room_id,
          where: is_nil(c.room_id) or c.next_check_at <= ^now,
          order_by: [asc_nulls_first: c.next_check_at, asc: r.local_room_id],
          limit: 25,
          select: r.room_id
      )

    Enum.map(rooms, fn ref ->
      result = reconcile(ref)
      save_check(ref, result)
      result
    end)
  end

  def reconcile(ref) do
    case Graph.room_by_id(ref) do
      nil ->
        {:error, :not_found}

      room ->
        state = RoomAccess.state(room)
        servers = servers(state)
        unless tombstoned?(state), do: Enum.each(servers, &RoomVersions.refresh/1)
        # All network I/O finishes before taking the global event stream lock.
        Policy.transaction(fn ->
          ClientStore.lock!()
          room = Graph.room_by_id(ref) || Repo.rollback(:not_found)
          state = RoomAccess.state(room)

          cond do
            tombstoned?(state) ->
              %{status: "replaced", version: room.version}

            true ->
              target =
                case RoomVersions.common(servers(state)) do
                  {:ok, version} -> version
                  {:error, reason} -> Repo.rollback(reason)
                end

              if target == room.version do
                %{status: "current", version: target}
              else
                migrate(room, state, target)
              end
          end
        end)
    end
  end

  defp migrate(room, state, target) do
    # Never discard a policy-server requirement or silently weaken a join rule
    # while moving to a format that cannot represent it.
    if map_size(get_in(state, [{"m.room.policy", ""}, "content"]) || %{}) > 0 or
         (target == "9" and
            get_in(state, [{"m.room.join_rules", ""}, "content", "join_rule"]) ==
              "knock_restricted"),
       do: Repo.rollback(:unsupported_room_features)

    principal = actor(room, state) || Repo.rollback(:no_authorized_local_member)

    creators =
      Authorization.creators(state) |> Enum.reject(&(&1 == Identity.user_id(principal.username)))

    result =
      case RoomUpgrades.upgrade(principal.id, room.room_id, %{
             "new_version" => target,
             "additional_creators" => creators
           }) do
        {:ok, result} -> result
        {:error, reason} -> Repo.rollback(reason)
      end

    %{status: "upgraded", version: target, replacement_room: result["replacement_room"]}
  end

  defp actor(room, state) do
    creators = Authorization.creators(state)

    state
    |> Enum.filter(fn {{type, _}, event} ->
      type == "m.room.member" and event["content"]["membership"] == "join"
    end)
    |> Enum.map(fn {{_, user}, _} -> user end)
    |> Enum.sort_by(fn user -> {user not in creators, user} end)
    |> Enum.find_value(fn user ->
      with {:ok, name} <- Identity.parse_user_id(user),
           {:ok, %{active: true} = p} <- Accounts.fetch_user(name),
           true <- IAM.can?(p.id, "matrix.room.create", nil),
           event <-
             Graph.template(
               room,
               Graph.load_graph(room.local_room_id),
               user,
               "m.room.tombstone",
               %{},
               ""
             ),
           :ok <- Authorization.check(event, state, room.version),
           do: p,
           else: (_ -> nil)
    end)
  end

  defp servers(state) do
    state
    |> Enum.flat_map(fn
      {{"m.room.member", user}, event} ->
        if event["content"]["membership"] in ~w(join invite knock), do: [user], else: []

      _ ->
        []
    end)
    |> RoomVersions.domains()
  end

  defp tombstoned?(state),
    do: is_binary(get_in(state, [{"m.room.tombstone", ""}, "content", "replacement_room"]))

  defp save_check(ref, result) do
    room = Graph.room_by_id(ref)

    if room do
      {status, target} =
        case result do
          {:ok, info} -> {info.status, info.version}
          {:error, reason} when is_atom(reason) -> {Atom.to_string(reason), nil}
          _ -> {"retry", nil}
        end

      values = %{
        room_id: ClientStore.dump_id(room.local_room_id),
        next_check_at:
          DateTime.add(
            ClientStore.now(),
            Application.get_env(:lakehouse_matrix, :room_version_check_seconds, 300),
            :second
          ),
        status: status,
        target_version: target
      }

      Repo.insert_all("matrix_room_version_checks", [values],
        on_conflict: {:replace, [:next_check_at, :status, :target_version]},
        conflict_target: [:room_id]
      )
    end
  end
end
