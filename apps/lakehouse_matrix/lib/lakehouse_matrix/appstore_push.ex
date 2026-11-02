defmodule LakehouseMatrix.AppstorePush do
  @moduledoc "Receipt-aware Matrix alerts through the pinned Private Store protocol. No message content leaves the homeserver."
  use GenServer
  import Ecto.Query
  alias LakehouseIam.{Changes, Protocols, Repo}
  alias LakehouseIam.Schema.{AppGrant, Principal}
  alias LakehouseMatrix.{ClientStore, Identity, Notifications, ReadSnapshot}
  alias LakehouseMatrix.Schema.{Pdu, RoomEvent}

  @permissions ~w(protocols.read appstore.push appstore.push.broadcast)

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(_) do
    :ok = Changes.subscribe(nil, "matrix_appstore_push")
    {:ok, %{timer: :erlang.start_timer(0, self(), :deliver)}}
  end

  @impl true
  def handle_info({:timeout, timer, :deliver}, %{timer: timer} = state) do
    result = deliver_once()

    {:noreply,
     %{
       state
       | timer: :erlang.start_timer(if(result == :idle, do: 1000, else: 0), self(), :deliver)
     }}
  end

  def handle_info({:gravitas_change, %{"matrix_appstore_push" => true}}, state) do
    Process.cancel_timer(state.timer)
    {:noreply, %{state | timer: :erlang.start_timer(0, self(), :deliver)}}
  end

  def handle_info(_, state), do: {:noreply, state}

  defp sender do
    origin = Application.get_env(:lakehouse_matrix, :appstore_push_origin)
    service = Protocols.services()[origin]

    if is_binary(origin) and is_map(service) and
         Enum.all?(@permissions, &(&1 in (service["permissions"] || []))),
       do: %{origin: origin, permissions: @permissions}
  end

  defp subscribed?(principal, sender) do
    Repo.exists?(
      from g in AppGrant, where: g.principal_id == ^principal and g.app_origin == ^sender.origin
    ) and
      Enum.any?(Protocols.subscribed(principal, sender), fn spec ->
        spec["protocol"] == "appstore" and spec["version"] == "1.0.0" and
          Enum.any?(spec["capabilities"], &(&1["id"] == "push.broadcast"))
      end)
  end

  # Invoked in the event's transaction. Rollback also rolls back queue insertion
  # and the database notification. Private Store alone owns installed devices.
  def queue!(principal, notification) do
    if current = sender() do
      if subscribed?(principal, current) do
        now = ClientStore.now()

        Repo.insert_all(
          "matrix_appstore_outbox",
          [
            %{
              notification_id: notification,
              available_at: now,
              expires_at: DateTime.add(now, 7 * 86400, :second)
            }
          ],
          on_conflict: :nothing
        )

        Changes.notify(%{"matrix_appstore_push" => true})
      end
    end

    :ok
  end

  def deliver_once(invoke \\ &Protocols.invoke/3) do
    if current = sender() do
      case claim() do
        nil ->
          :idle

        item ->
          {:ok, envelope} = ReadSnapshot.transaction(fn -> payload(item, current) end)

          case envelope do
            nil ->
              complete(item)

            {principal, params} ->
              case invoke.(current, principal, params) do
                {:ok, %{"status" => "accepted"}} -> complete(item)
                _ -> retry(item)
              end
          end

          :worked
      end
    else
      :idle
    end
  end

  defp claim do
    {:ok, item} =
      Repo.transaction(fn ->
        now = ClientStore.now()
        # Bound cleanup to the indexed live queue, never the notification archive.
        Repo.delete_all(from o in "matrix_appstore_outbox", where: o.expires_at <= ^now)

        item =
          Repo.one(
            from o in "matrix_appstore_outbox",
              where: o.available_at <= ^now and (is_nil(o.lease_until) or o.lease_until <= ^now),
              order_by: o.notification_id,
              limit: 1,
              lock: "FOR UPDATE SKIP LOCKED",
              select: %{id: o.notification_id, attempts: o.attempts}
          )

        if item do
          lease = DateTime.add(now, 90, :second)

          Repo.update_all(
            from(o in "matrix_appstore_outbox", where: o.notification_id == ^item.id),
            set: [lease_until: lease, attempts: item.attempts + 1]
          )

          Map.merge(item, %{lease: lease, attempts: item.attempts + 1})
        end
      end)

    item
  end

  defp payload(item, current) do
    row =
      Repo.one(
        from n in "matrix_notifications",
          join: u in Principal,
          on: n.principal_id == u.id,
          join: e in RoomEvent,
          on: n.event_id == e.event_id,
          left_join: p in Pdu,
          on: p.event_id == e.event_id,
          where:
            n.id == ^item.id and u.active == true and u.matrix_locked == false and
              u.matrix_deactivated == false and
              is_nil(p.redacted_by),
          select: %{
            principal: u.id,
            event: e,
            room: type(n.local_room_id, :binary_id),
            depth: fragment("(?->>'depth')::bigint", p.pdu)
          }
      )

    if row && subscribed?(row.principal, current) &&
         LakehouseMatrix.Memberships.membership(row.room, row.principal) in ["join", "invite"] &&
         not Notifications.read?(
           row.event,
           row.depth,
           Notifications.read_states(row.principal, row.room, ClientStore.position())
         ) &&
         Notifications.visible_event(row.principal, row.event) do
      # Immutable across retries, including a crash after relay acceptance. Read
      # counts/titles/content could change and would break PCR idempotency.
      payload = %{
        "kind" => "matrix.event",
        "issuer" => LakehouseIam.Discovery.public_url(),
        "subject" => row.principal,
        "room_id" => Identity.room_id(row.room),
        "event_id" => row.event.event_id,
        "sequence" => item.id
      }

      {row.principal,
       %{
         "id" => "matrix:#{item.id}",
         "protocol" => "appstore",
         "version" => "1.0.0",
         "capability" => "push.broadcast",
         "input" => %{"app" => "river", "payload" => payload}
       }}
    end
  end

  defp complete(item),
    do:
      Repo.delete_all(
        from o in "matrix_appstore_outbox",
          where: o.notification_id == ^item.id and o.lease_until == ^item.lease
      )

  defp retry(item) do
    Repo.update_all(
      from(o in "matrix_appstore_outbox",
        where: o.notification_id == ^item.id and o.lease_until == ^item.lease
      ),
      set: [
        lease_until: nil,
        available_at:
          DateTime.add(
            ClientStore.now(),
            min(3600, 5 * Integer.pow(2, min(item.attempts, 10))),
            :second
          )
      ]
    )
  end
end
