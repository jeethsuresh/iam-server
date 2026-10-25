defmodule LakehouseMatrix.Pushers do
  @moduledoc "Device-bound HTTP pushers and leased delivery to DNS-pinned HTTPS push gateways."
  use GenServer
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientStore, Identity, Notifications}
  alias LakehouseMatrix.Federation.Transport
  alias LakehouseMatrix.Schema.{Pdu, RoomEvent}

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  @impl true
  def init(_),
    do:
      (
        send(self(), :deliver)
        {:ok, %{}}
      )

  @impl true
  def handle_info(:deliver, state) do
    result = deliver_once()
    Process.send_after(self(), :deliver, if(result == :idle, do: 1000, else: 10))
    {:noreply, state}
  end

  def list(principal),
    do: %{
      "pushers" =>
        Repo.all(
          from p in "matrix_pushers",
            where: p.principal_id == type(^principal, :binary_id),
            order_by: p.id,
            select: p.config
        )
    }

  def set(principal, device, params) do
    app = params["app_id"]
    key = params["pushkey"]

    if text?(app, 64) and text?(key, 512) and params["append"] in [nil, false, true] and
         Map.has_key?(params, "kind") and (is_nil(params["kind"]) or valid_config?(params)) do
      Repo.transaction(fn ->
        ClientStore.lock!()

        if is_nil(params["kind"]) do
          Repo.delete_all(
            from p in "matrix_pushers",
              where:
                p.principal_id == type(^principal, :binary_id) and p.app_id == ^app and
                  p.pushkey == ^key
          )
        else
          if params["append"] != true,
            do:
              Repo.delete_all(
                from p in "matrix_pushers",
                  where:
                    p.principal_id != type(^principal, :binary_id) and p.app_id == ^app and
                      p.pushkey == ^key
              )

          config =
            Map.take(
              params,
              ~w(pushkey kind app_id app_display_name device_display_name profile_tag lang data)
            )

          created = ClientStore.now()

          Repo.insert_all(
            "matrix_pushers",
            [
              %{
                principal_id: ClientStore.dump_id(principal),
                device_id: device,
                app_id: app,
                pushkey: key,
                config: config,
                created_at: created
              }
            ],
            conflict_target: [:principal_id, :app_id, :pushkey],
            on_conflict: [set: [config: config, device_id: device]]
          )

          if Repo.aggregate(
               from(p in "matrix_pushers", where: p.principal_id == type(^principal, :binary_id)),
               :count
             ) > 100,
             do: Repo.rollback(:limit_exceeded)
        end

        %{}
      end)
    else
      {:error, :invalid_param}
    end
  end

  defp valid_config?(params) do
    data = params["data"]

    params["kind"] == "http" and is_map(data) and valid_url?(data["url"]) and
      data["format"] in [nil, "event_id_only"] and text?(params["app_display_name"], 1024) and
      text?(params["device_display_name"], 1024) and text?(params["lang"], 128) and
      (is_nil(params["profile_tag"]) or text?(params["profile_tag"], 128)) and
      byte_size(Jason.encode!(params)) <= 65_536
  end

  defp text?(value, max), do: is_binary(value) and byte_size(value) in 1..max

  defp valid_url?(url) when is_binary(url) and byte_size(url) <= 2048 do
    uri = URI.parse(url)

    uri.scheme == "https" and is_binary(uri.host) and uri.host != "" and is_nil(uri.userinfo) and
      is_nil(uri.fragment) and
      uri.port in 1..65535 and not Regex.match?(~r/[\x00-\x20\x7f\\]/, url)
  rescue
    ArgumentError -> false
  end

  defp valid_url?(_), do: false

  def queue!(principal, notification \\ nil) do
    ids =
      Repo.all(
        from p in "matrix_pushers",
          where: p.principal_id == type(^principal, :binary_id),
          select: p.id
      )

    if ids != [],
      do:
        Repo.insert_all(
          "matrix_push_outbox",
          Enum.map(
            ids,
            &%{pusher_id: &1, notification_id: notification, available_at: ClientStore.now()}
          )
        )

    :ok
  end

  def deliver_once(request \\ &request/2) do
    case claim() do
      nil ->
        :idle

      item ->
        # Revocation/read/visibility checks and payload preparation complete in a
        # short transaction; outbound I/O never owns a database transaction.
        payload = payload(item)

        case payload do
          nil ->
            complete(item)

          {config, body} ->
            case request.(config["data"]["url"], %{"notification" => body}) do
              {:ok, %{"rejected" => rejected}} when is_list(rejected) ->
                if config["pushkey"] in rejected do
                  Repo.delete_all(
                    from p in "matrix_pushers",
                      join: o in "matrix_push_outbox",
                      on: o.pusher_id == p.id,
                      where:
                        p.id == ^item.pusher and p.config == ^config and o.id == ^item.id and
                          o.lease_until == ^item.lease
                  )
                else
                  complete(item)
                end

              _ ->
                retry(item)
            end
        end

        :delivered
    end
  end

  def request(url, body) do
    with true <- valid_url?(url) do
      uri = URI.parse(url)
      authority = if String.contains?(uri.host, ":"), do: "[" <> uri.host <> "]", else: uri.host
      authority = authority <> if(uri.port == 443, do: "", else: ":" <> to_string(uri.port))

      path =
        if(uri.path in [nil, ""], do: "/", else: uri.path) <>
          if(uri.query, do: "?" <> uri.query, else: "")

      Transport.fetch(
        %{host: uri.host, port: uri.port, tls_name: uri.host, authority: authority},
        path,
        method: :post,
        content: body,
        headers: [{"content-type", "application/json"}],
        max_bytes: 65_536
      )
    else
      _ -> {:error, :invalid_param}
    end
  end

  defp claim do
    {:ok, item} =
      Repo.transaction(fn ->
        now = ClientStore.now()

        item =
          Repo.one(
            from o in "matrix_push_outbox",
              where:
                is_nil(o.delivered_at) and o.available_at <= ^now and
                  (is_nil(o.lease_until) or o.lease_until <= ^now),
              order_by: o.id,
              limit: 1,
              lock: "FOR UPDATE SKIP LOCKED",
              select: %{
                id: o.id,
                pusher: o.pusher_id,
                notification: o.notification_id,
                attempts: o.attempts
              }
          )

        if item do
          lease = DateTime.add(now, 90, :second)

          Repo.update_all(from(o in "matrix_push_outbox", where: o.id == ^item.id),
            set: [lease_until: lease, attempts: item.attempts + 1]
          )

          Map.merge(item, %{lease: lease, attempts: item.attempts + 1})
        end
      end)

    item
  end

  defp payload(item) do
    {:ok, body} =
      Repo.transaction(fn ->
        high = ClientStore.lock!()

        pusher =
          Repo.one(
            from p in "matrix_pushers",
              join: u in LakehouseIam.Schema.Principal,
              on: p.principal_id == u.id,
              where: p.id == ^item.pusher and u.active == true and u.matrix_locked == false,
              select: %{
                principal: type(p.principal_id, :binary_id),
                config: p.config,
                created: type(p.created_at, :utc_datetime_usec)
              }
          )

        if pusher do
          total =
            LakehouseMatrix.Memberships.joined_room_ids(pusher.principal)
            |> Enum.reduce(0, fn room, count ->
              count + Notifications.counts(pusher.principal, room, high)["notification_count"]
            end)

          config = pusher.config
          data = config["data"] |> Map.delete("url")

          device = %{
            "app_id" => config["app_id"],
            "pushkey" => config["pushkey"],
            "pushkey_ts" => DateTime.to_unix(pusher.created),
            "data" => data,
            "tweaks" => %{}
          }

          body = %{"counts" => %{"unread" => total, "missed_calls" => 0}, "devices" => [device]}

          if item.notification do
            notification =
              Repo.one(
                from n in "matrix_notifications",
                  join: e in RoomEvent,
                  on: n.event_id == e.event_id,
                  left_join: p in Pdu,
                  on: p.event_id == e.event_id,
                  where:
                    n.id == ^item.notification and
                      n.principal_id == type(^pusher.principal, :binary_id) and
                      is_nil(p.redacted_by),
                  select: %{
                    event: e,
                    actions: n.actions,
                    room: type(n.local_room_id, :binary_id),
                    depth: fragment("(?->>'depth')::bigint", p.pdu)
                  }
              )

            if notification &&
                 !Notifications.read?(
                   notification.event,
                   notification.depth,
                   Notifications.read_states(pusher.principal, notification.room, high)
                 ) do
              if event = Notifications.visible_event(pusher.principal, notification.event) do
                body =
                  Map.merge(body, %{
                    "event_id" => event["event_id"],
                    "room_id" => Identity.room_id(notification.room),
                    "prio" =>
                      if(
                        event["type"] == "m.room.encrypted" or
                          Notifications.highlight?(notification.actions),
                        do: "high",
                        else: "low"
                      )
                  })

                body =
                  if config["data"]["format"] == "event_id_only",
                    do: body,
                    else:
                      body
                      |> Map.merge(Map.take(event, ~w(type sender content)))
                      |> Map.put(
                        "user_is_target",
                        event["state_key"] ==
                          Identity.user_id(
                            Repo.get!(LakehouseIam.Schema.Principal, pusher.principal).username
                          )
                      )

                tweaks =
                  notification.actions
                  |> Enum.filter(&is_map/1)
                  |> Enum.filter(&is_binary(&1["set_tweak"]))
                  |> Map.new(&{&1["set_tweak"], Map.get(&1, "value", true)})

                {config, Map.put(body, "devices", [Map.put(device, "tweaks", tweaks)])}
              end
            end
          else
            {config, body}
          end
        end
      end)

    body
  end

  defp complete(item),
    do:
      Repo.update_all(
        from(o in "matrix_push_outbox", where: o.id == ^item.id and o.lease_until == ^item.lease),
        set: [delivered_at: ClientStore.now(), lease_until: nil]
      )

  defp retry(item),
    do:
      Repo.update_all(
        from(o in "matrix_push_outbox", where: o.id == ^item.id and o.lease_until == ^item.lease),
        set: [
          available_at:
            DateTime.add(
              ClientStore.now(),
              min(3600, 5 * Integer.pow(2, min(item.attempts, 10))),
              :second
            ),
          lease_until: nil
        ]
      )
end
