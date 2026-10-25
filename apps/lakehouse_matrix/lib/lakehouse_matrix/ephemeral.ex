defmodule LakehouseMatrix.Ephemeral do
  @moduledoc "Scoped typing and presence delivery, including durable expiry transitions."
  use GenServer
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseMatrix.{ClientRooms, ClientStore, ClientSync, Identity, Memberships}
  alias LakehouseMatrix.Federation.{Edus, RoomAccess}
  alias LakehouseMatrix.Protocol.Graph

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  @impl true
  def init(_),
    do:
      (
        Process.send_after(self(), :expire, 1000)
        {:ok, %{}}
      )

  @impl true
  def handle_info(:expire, state) do
    expire()
    Process.send_after(self(), :expire, 1000)
    {:noreply, state}
  end

  def typing(principal, ref, user, params) do
    with true <- user == mxid(principal) and is_boolean(params["typing"]),
         {:ok, timeout} <- ClientSync.integer(params["timeout"], 30_000, 1, 120_000),
         {:ok, room} <- ClientRooms.readable(principal, ref) do
      Repo.transaction(fn ->
        ClientStore.lock!()

        put!(
          room.id,
          user,
          "m.typing",
          %{"typing" => params["typing"]},
          DateTime.add(ClientStore.now(), timeout, :millisecond)
        )

        if metadata = Graph.room(room.id),
          do:
            Edus.broadcast!(metadata, "m.typing", %{
              "room_id" => ref,
              "user_id" => user,
              "typing" => params["typing"]
            })

        %{}
      end)
    else
      _ -> {:error, :invalid_param}
    end
  end

  def set_presence(principal, params, from_sync \\ false) do
    presence = params["presence"] || "online"
    status = params["status_msg"]

    if presence in ~w(online offline unavailable) and
         (is_nil(status) or (is_binary(status) and byte_size(status) <= 4096)) do
      Repo.transaction(fn ->
        ClientStore.lock!()
        now = ClientStore.now()

        current =
          Repo.one(
            from p in "matrix_user_presence",
              where: p.principal_id == type(^principal, :binary_id),
              select: %{content: p.content, updated_at: type(p.updated_at, :utc_datetime_usec)}
          )

        # Ordinary sync keeps an explicitly supplied status message intact.
        status = if from_sync and current, do: current.content["status_msg"], else: status

        content = %{
          "presence" => presence,
          "status_msg" => status,
          "currently_active" => presence == "online",
          "last_active_ago" => 0
        }

        fresh =
          not is_nil(current) and current.content == content and
            DateTime.diff(now, current.updated_at, :second) < 30

        unless fresh do
          Repo.insert_all(
            "matrix_user_presence",
            [%{principal_id: ClientStore.dump_id(principal), content: content, updated_at: now}],
            on_conflict: [set: [content: content, updated_at: now]],
            conflict_target: [:principal_id]
          )

          user = mxid(principal)

          for room <- Memberships.joined_room_ids(principal) do
            put!(
              room,
              user,
              "m.presence",
              content,
              DateTime.add(now, if(presence == "offline", do: 31_536_000, else: 180), :second)
            )
          end

          rooms = Edus.shared_rooms(user)

          servers =
            rooms
            |> Enum.flat_map(fn metadata ->
              for {{"m.room.member", member}, e} <- RoomAccess.state(metadata),
                  e["content"]["membership"] == "join",
                  {:ok, server} <- [LakehouseMatrix.Protocol.Event.user_domain(member)],
                  server != Identity.homeserver_domain() and
                    RoomAccess.allowed?(metadata, server),
                  do: server
            end)
            |> Enum.uniq()

          for server <- servers,
              do:
                Edus.outgoing!(server, "m.presence", %{
                  "push" => [Map.put(content, "user_id", user)]
                })
        end

        %{}
      end)
    else
      {:error, :invalid_param}
    end
  end

  def get_presence(principal, user) do
    own = mxid(principal)
    rooms = Memberships.joined_room_ids(principal)
    shared = Enum.any?(rooms, fn room -> user in joined_users(room, ClientStore.position()) end)

    if user == own or shared do
      content =
        Repo.one(
          from e in "matrix_ephemeral_events",
            where:
              e.user_id == ^user and e.type == "m.presence" and
                e.local_room_id in type(^rooms, {:array, :binary_id}),
            order_by: [desc: e.stream_id],
            limit: 1,
            select: %{content: e.content, expires_at: type(e.expires_at, :utc_datetime_usec)}
        )

      own_content =
        if user == own,
          do:
            Repo.one(
              from p in "matrix_user_presence",
                where: p.principal_id == type(^principal, :binary_id),
                select: %{content: p.content, updated_at: type(p.updated_at, :utc_datetime_usec)}
            )

      data =
        cond do
          content &&
              (content.content["presence"] == "offline" or
                 DateTime.compare(content.expires_at, ClientStore.now()) == :gt) ->
            content.content

          own_content ->
            if DateTime.diff(ClientStore.now(), own_content.updated_at, :second) < 180,
              do: own_content.content,
              else:
                Map.merge(own_content.content, %{
                  "presence" => "offline",
                  "currently_active" => false
                })

          true ->
            %{"presence" => "offline"}
        end

      {:ok, data}
    else
      {:error, :forbidden}
    end
  end

  def typing_events(room, since, high) do
    rows =
      Repo.all(
        from e in "matrix_ephemeral_events",
          where:
            e.local_room_id == type(^room, :binary_id) and e.type == "m.typing" and
              e.stream_id <= ^high,
          select: %{
            user: e.user_id,
            content: e.content,
            stream: e.stream_id,
            expiry: type(e.expires_at, :utc_datetime_usec)
          }
      )

    changed = Enum.any?(rows, &(&1.stream > since))
    users = joined_users(room, high)

    active =
      for row <- rows,
          row.content["typing"] == true and DateTime.compare(row.expiry, ClientStore.now()) == :gt and
            row.user in users,
          do: row.user

    if changed,
      do: [%{"type" => "m.typing", "content" => %{"user_ids" => Enum.sort(active)}}],
      else: []
  end

  def presence_events(principal, since, high) do
    rooms = Memberships.joined_room_ids(principal)

    rows =
      Repo.all(
        from e in "matrix_ephemeral_events",
          where:
            e.local_room_id in type(^rooms, {:array, :binary_id}) and e.type == "m.presence" and
              e.stream_id > ^since and e.stream_id <= ^high,
          order_by: [asc: e.stream_id],
          select: %{user: e.user_id, content: e.content, room: type(e.local_room_id, :binary_id)}
      )

    users = Map.new(rooms, &{&1, joined_users(&1, high)})

    rows
    |> Enum.filter(&(&1.user in users[&1.room]))
    |> Map.new(
      &{&1.user, %{"type" => "m.presence", "sender" => &1.user, "content" => &1.content}}
    )
    |> Map.values()
  end

  def expire(now \\ ClientStore.now()) do
    Repo.transaction(fn ->
      ClientStore.lock!()

      rows =
        Repo.all(
          from e in "matrix_ephemeral_events",
            where:
              e.expires_at <= ^now and
                fragment(
                  "((? = 'm.typing' AND ?->>'typing' = 'true') OR (? = 'm.presence' AND ?->>'presence' <> 'offline'))",
                  e.type,
                  e.content,
                  e.type,
                  e.content
                ),
            select: %{
              id: e.id,
              room: type(e.local_room_id, :binary_id),
              user: e.user_id,
              type: e.type,
              content: e.content
            }
        )

      for row <- rows do
        content =
          if row.type == "m.typing",
            do: %{"typing" => false},
            else: Map.merge(row.content, %{"presence" => "offline", "currently_active" => false})

        Repo.update_all(from(e in "matrix_ephemeral_events", where: e.id == ^row.id),
          set: [content: content]
        )

        if row.type == "m.typing" and match?({:ok, _}, Identity.parse_user_id(row.user)) do
          if metadata = Graph.room(row.room),
            do:
              Edus.broadcast!(metadata, "m.typing", %{
                "room_id" => metadata.room_id,
                "user_id" => row.user,
                "typing" => false
              })
        end
      end

      length(rows)
    end)
  end

  defp joined_users(room, high) do
    for e <- ClientSync.state_at(room, high),
        e["type"] == "m.room.member" and e["content"]["membership"] == "join",
        do: e["state_key"]
  end

  defp mxid(principal),
    do: Repo.get!(LakehouseIam.Schema.Principal, principal).username |> Identity.user_id()

  defp put!(room, user, type, content, expiry) do
    Repo.insert_all(
      "matrix_ephemeral_events",
      [
        %{
          local_room_id: ClientStore.dump_id(room),
          user_id: user,
          type: type,
          content: content,
          expires_at: expiry
        }
      ],
      on_conflict: [set: [content: content, expires_at: expiry]],
      conflict_target: [:local_room_id, :type, :user_id]
    )
  end
end
