defmodule LakehouseMatrix.Memberships do
  @moduledoc """
  Room membership tracking per principal.
  """
  import Ecto.Query

  alias LakehouseIam.Repo
  alias LakehouseMatrix.Schema.{Room, RoomMembership}

  @spec joined_room_ids(Ecto.UUID.t()) :: [Ecto.UUID.t()]
  def joined_room_ids(principal_id),
    do:
      room_ids_with_membership(principal_id, "join")
      |> Enum.filter(
        &(LakehouseMatrix.RiverRtc.chat_allowed?(&1, principal_id) and
            LakehouseMatrix.RiverPublishing.reader_allowed?(&1, principal_id))
      )

  @spec invited_room_ids(Ecto.UUID.t()) :: [Ecto.UUID.t()]
  def invited_room_ids(principal_id), do: room_ids_with_membership(principal_id, "invite")

  @spec left_room_ids(Ecto.UUID.t()) :: [Ecto.UUID.t()]
  def left_room_ids(principal_id),
    do:
      room_ids_with_membership(principal_id, "leave") ++
        room_ids_with_membership(principal_id, "ban")

  @spec list_joined_rooms(Ecto.UUID.t()) :: [Room.t()]
  def list_joined_rooms(principal_id) do
    Repo.all(
      from r in Room,
        join: m in RoomMembership,
        on: m.room_id == r.id,
        where:
          m.principal_id == ^principal_id and
            fragment("?->>'membership' = 'join'", m.membership_state),
        order_by: [desc: m.inserted_at],
        select: r
    )
    |> Enum.filter(
      &(LakehouseMatrix.RiverRtc.chat_allowed?(&1.id, principal_id) and
          LakehouseMatrix.RiverPublishing.reader_allowed?(&1.id, principal_id))
    )
  end

  @spec joined?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def joined?(room_id, principal_id),
    do:
      membership?(room_id, principal_id, "join") and
        LakehouseMatrix.RiverRtc.chat_allowed?(room_id, principal_id) and
        LakehouseMatrix.RiverPublishing.reader_allowed?(room_id, principal_id)

  @spec invited?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def invited?(room_id, principal_id), do: membership?(room_id, principal_id, "invite")

  @spec membership(Ecto.UUID.t(), Ecto.UUID.t()) :: String.t() | nil
  def membership(room_id, principal_id) do
    case Repo.one(
           from m in RoomMembership,
             where: m.room_id == ^room_id and m.principal_id == ^principal_id,
             select: m.membership_state
         ) do
      %{"membership" => membership} -> membership
      _ -> nil
    end
  end

  @spec membership_map(Ecto.UUID.t()) :: %{optional(Ecto.UUID.t()) => String.t()}
  def membership_map(room_id) do
    Repo.all(
      from m in RoomMembership,
        where: m.room_id == ^room_id,
        select: {m.principal_id, m.membership_state}
    )
    |> Map.new(fn {pid, state} -> {pid, Map.get(state, "membership")} end)
  end

  @spec list_members(Ecto.UUID.t()) :: [%{username: String.t(), principal_id: Ecto.UUID.t()}]
  def list_members(room_id) do
    if LakehouseMatrix.Protocol.Graph.room(room_id) do
      members =
        LakehouseMatrix.Federation.RoomAccess.state(LakehouseMatrix.Protocol.Graph.room(room_id))

      for {{"m.room.member", user}, event} <- members, event["content"]["membership"] == "join" do
        local =
          with {:ok, name} <- LakehouseMatrix.Identity.parse_user_id(user),
               {:ok, principal} <- LakehouseIam.Accounts.fetch_user(name),
               do: principal

        %{
          username: if(is_map(local), do: local.username, else: user),
          principal_id: if(is_map(local), do: local.id),
          user_id: user,
          display_name: event["content"]["displayname"],
          avatar_url: event["content"]["avatar_url"]
        }
      end
      |> Enum.sort_by(& &1.username)
    else
      Repo.all(
        from m in RoomMembership,
          join: p in LakehouseIam.Schema.Principal,
          on: p.id == m.principal_id,
          where:
            m.room_id == ^room_id and fragment("?->>'membership' = 'join'", m.membership_state),
          order_by: [asc: p.username],
          select: %{username: p.username, principal_id: p.id}
      )
    end
  end

  @spec apply_membership(
          Ecto.UUID.t(),
          String.t(),
          String.t(),
          LakehouseMatrix.Events.Context.t()
        ) ::
          {:ok, RoomMembership.t()} | {:error, Ecto.Changeset.t() | :unknown_member}
  def apply_membership(room_id, mxid, membership, ctx) do
    case principal_id_for_mxid(mxid) do
      nil ->
        {:error, :unknown_member}

      principal_id ->
        upsert_membership(room_id, principal_id, membership, ctx)
    end
  end

  @spec upsert_membership(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          String.t(),
          LakehouseMatrix.Events.Context.t()
        ) ::
          {:ok, RoomMembership.t()} | {:error, Ecto.Changeset.t()}
  def upsert_membership(
        room_id,
        principal_id,
        membership,
        %LakehouseMatrix.Events.Context{} = ctx
      ) do
    if membership in ~w(join invite knock),
      do: LakehouseMatrix.ClientStore.restore_room!(principal_id, room_id)

    state = %{
      "membership" => membership,
      "displayname" => Map.get(ctx.content, "displayname"),
      "event_id" => ctx.event_id,
      "origin_server_ts" => ctx.origin_server_ts
    }

    existing =
      Repo.one(
        from m in RoomMembership,
          where: m.room_id == ^room_id and m.principal_id == ^principal_id
      )

    result =
      case existing do
        nil ->
          %RoomMembership{}
          |> RoomMembership.changeset(%{
            room_id: room_id,
            principal_id: principal_id,
            membership_state: state
          })
          |> Repo.insert()

        existing ->
          existing
          |> RoomMembership.changeset(%{membership_state: state})
          |> Repo.update()
      end

    if match?({:ok, _}, result) and membership == "join" and
         (is_nil(existing) or existing.membership_state["membership"] != "join"),
       do: LakehouseMatrix.RoomUpgrades.copy_settings!(principal_id, room_id)

    result
  end

  @spec member_count(Ecto.UUID.t()) :: integer()
  def member_count(room_id), do: count_with_membership(room_id, "join")

  @spec invited_count(Ecto.UUID.t()) :: integer()
  def invited_count(room_id), do: count_with_membership(room_id, "invite")

  @doc """
  Room ids whose membership for `principal_id` is `membership` and was
  updated after `since_ts` (milliseconds since epoch).
  """
  @spec room_ids_changed_since(Ecto.UUID.t(), String.t(), integer()) :: [Ecto.UUID.t()]
  def room_ids_changed_since(principal_id, membership, since_ts)
      when is_binary(membership) and is_integer(since_ts) do
    cutoff =
      since_ts
      |> div(1000)
      |> DateTime.from_unix!(:second)

    Repo.all(
      from m in RoomMembership,
        where:
          m.principal_id == ^principal_id and
            fragment("?->>'membership' = ?", m.membership_state, ^membership) and
            m.updated_at > ^cutoff,
        select: m.room_id
    )
  end

  defp room_ids_with_membership(principal_id, membership) do
    Repo.all(
      from m in RoomMembership,
        where:
          m.principal_id == ^principal_id and
            fragment("?->>'membership' = ?", m.membership_state, ^membership),
        select: m.room_id,
        order_by: [desc: m.updated_at]
    )
  end

  defp membership?(room_id, principal_id, membership) do
    Repo.exists?(
      from m in RoomMembership,
        where:
          m.room_id == ^room_id and m.principal_id == ^principal_id and
            fragment("?->>'membership' = ?", m.membership_state, ^membership)
    )
  end

  defp count_with_membership(room_id, membership) do
    if LakehouseMatrix.Protocol.Graph.room(room_id) do
      Repo.aggregate(
        from(s in LakehouseMatrix.Schema.RoomState,
          where:
            s.room_id == ^room_id and s.type == "m.room.member" and
              fragment("?->>'membership' = ?", s.content, ^membership)
        ),
        :count
      )
    else
      Repo.aggregate(
        from(m in RoomMembership,
          where:
            m.room_id == ^room_id and
              fragment("?->>'membership' = ?", m.membership_state, ^membership)
        ),
        :count
      )
    end
  end

  defp principal_id_for_mxid(mxid) when is_binary(mxid) do
    username =
      case LakehouseMatrix.Identity.parse_user_id(mxid) do
        {:ok, user} -> user
        _ -> nil
      end

    if username do
      Repo.one(
        from p in LakehouseIam.Schema.Principal,
          where: p.username == ^username and p.type == :user,
          select: p.id
      )
    end
  end
end
