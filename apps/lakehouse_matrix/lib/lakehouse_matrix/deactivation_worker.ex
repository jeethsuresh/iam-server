defmodule LakehouseMatrix.DeactivationWorker do
  @moduledoc "Leased, retryable room leaves after credentials have already been revoked."
  use GenServer
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, Identity}
  alias LakehouseMatrix.Events.{Context, Processor}
  alias LakehouseMatrix.Protocol.Graph

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  @impl true
  def init(_) do
    send(self(), :work)
    {:ok, %{}}
  end

  @impl true
  def handle_info(:work, state) do
    result = deliver_once()
    Process.send_after(self(), :work, if(result == :idle, do: 1000, else: 100))
    {:noreply, state}
  end

  def deliver_once(leave \\ &leave/2) do
    case claim() do
      nil ->
        :idle

      job ->
        account = Repo.get!(LakehouseIam.Schema.Principal, job.principal)

        if account.matrix_deactivated do
          cleanup_failed = cleanup_grants(account.id) != :ok

          rooms =
            Repo.all(
              from m in LakehouseMatrix.Schema.RoomMembership,
                where:
                  m.principal_id == ^account.id and
                    fragment("?->>'membership'", m.membership_state) in [
                      "join",
                      "invite",
                      "knock"
                    ],
                select: m.room_id,
                order_by: m.room_id
            )

          after_cursor =
            if job.after_room, do: Enum.filter(rooms, &(&1 > job.after_room)), else: rooms

          batch = Enum.take(if(after_cursor == [], do: rooms, else: after_cursor), 20)

          results =
            Enum.map(batch, fn room ->
              if renew(job), do: leave.(account, room), else: {:error, :lost_lease}
            end)

          failed = cleanup_failed or Enum.any?(results, &(not match?({:ok, _}, &1)))
          remaining = length(rooms) > length(batch) or failed

          if remaining do
            Repo.update_all(
              from(j in "matrix_deactivation_jobs",
                where:
                  j.principal_id == type(^job.principal, :binary_id) and
                    j.lease_token == type(^job.token, :binary_id)
              ),
              set: [
                lease_until: nil,
                lease_token: nil,
                after_room_id:
                  if(batch == [], do: nil, else: ClientStore.dump_id(List.last(batch))),
                available_at:
                  DateTime.add(
                    ClientStore.now(),
                    if(failed, do: min(60, job.attempts * 5), else: 0),
                    :second
                  )
              ]
            )
          else
            Repo.delete_all(
              from j in "matrix_deactivation_jobs",
                where:
                  j.principal_id == type(^job.principal, :binary_id) and
                    j.lease_token == type(^job.token, :binary_id)
            )
          end

          :worked
        else
          Repo.delete_all(
            from j in "matrix_deactivation_jobs",
              where:
                j.principal_id == type(^job.principal, :binary_id) and
                  j.lease_token == type(^job.token, :binary_id)
          )

          :worked
        end
    end
  end

  defp claim do
    {:ok, job} =
      Repo.transaction(fn ->
        now = ClientStore.now()

        row =
          Repo.one(
            from j in "matrix_deactivation_jobs",
              where: j.available_at <= ^now and (is_nil(j.lease_until) or j.lease_until < ^now),
              order_by: j.available_at,
              limit: 1,
              lock: "FOR UPDATE SKIP LOCKED",
              select: %{
                principal: type(j.principal_id, :binary_id),
                attempts: j.attempts,
                after_room: type(j.after_room_id, :binary_id)
              }
          )

        if row do
          lease = DateTime.add(now, 120, :second)
          token = Ecto.UUID.generate()

          Repo.update_all(
            from(j in "matrix_deactivation_jobs",
              where: j.principal_id == type(^row.principal, :binary_id)
            ),
            set: [
              lease_until: lease,
              lease_token: ClientStore.dump_id(token),
              attempts: row.attempts + 1
            ]
          )

          Map.merge(row, %{token: token, attempts: row.attempts + 1})
        end
      end)

    job
  end

  defp renew(job) do
    now = ClientStore.now()

    {count, _} =
      Repo.update_all(
        from(j in "matrix_deactivation_jobs",
          where:
            j.principal_id == type(^job.principal, :binary_id) and
              j.lease_token == type(^job.token, :binary_id) and j.lease_until > ^now
        ),
        set: [lease_until: DateTime.add(now, 120, :second)]
      )

    count == 1
  end

  defp cleanup_grants(principal) do
    Repo.delete_all(from g in LakehouseIam.Schema.AppGrant, where: g.principal_id == ^principal)
    :ok
  rescue
    Postgrex.Error -> {:error, :unavailable}
  end

  defp leave(account, room) do
    metadata = Graph.room(room)
    user = Identity.user_id(account.username)

    if metadata && metadata.extremities == [] do
      LakehouseMatrix.Federation.RemoteMembership.reject_invite(account.id, room)
    else
      Processor.process(%Context{
        room_id: room,
        principal_id: account.id,
        sender: user,
        state_key: user,
        type: "m.room.member",
        content: %{"membership" => "leave"},
        event_id: Identity.new_event_id(),
        origin_server_ts: System.system_time(:millisecond)
      })
    end
  rescue
    _ -> {:error, :unavailable}
  end
end
