defmodule LakehouseMatrix.Memberships do
  @moduledoc """
  Room membership tracking per principal.
  """
  import Ecto.Query

  alias LakehouseIam.Repo
  alias LakehouseMatrix.Schema.{Room, RoomMembership}

  @spec joined_room_ids(Ecto.UUID.t()) :: [Ecto.UUID.t()]
  def joined_room_ids(principal_id) do
    Repo.all(
      from m in RoomMembership,
        where:
          m.principal_id == ^principal_id and fragment("?->>'membership' = 'join'", m.membership_state),
        select: m.room_id,
        order_by: [desc: m.updated_at]
    )
  end

  @spec list_joined_rooms(Ecto.UUID.t()) :: [Room.t()]
  def list_joined_rooms(principal_id) do
    Repo.all(
      from r in Room,
        join: m in RoomMembership,
        on: m.room_id == r.id,
        where:
          m.principal_id == ^principal_id and fragment("?->>'membership' = 'join'", m.membership_state),
        order_by: [desc: m.inserted_at],
        select: r
    )
  end

  @spec joined?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def joined?(room_id, principal_id) do
    Repo.exists?(
      from m in RoomMembership,
        where:
          m.room_id == ^room_id and m.principal_id == ^principal_id and
            fragment("?->>'membership' = 'join'", m.membership_state)
    )
  end

  @spec list_members(Ecto.UUID.t()) :: [%{username: String.t(), principal_id: Ecto.UUID.t()}]
  def list_members(room_id) do
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

  @spec apply_membership(Ecto.UUID.t(), String.t(), String.t(), LakehouseMatrix.Events.Context.t()) ::
          {:ok, RoomMembership.t()} | {:error, Ecto.Changeset.t() | :unknown_member}
  def apply_membership(room_id, mxid, membership, ctx) do
    case principal_id_for_mxid(mxid) do
      nil ->
        {:error, :unknown_member}

      principal_id ->
        upsert_membership(room_id, principal_id, membership, ctx)
    end
  end

  @spec upsert_membership(Ecto.UUID.t(), Ecto.UUID.t(), String.t(), LakehouseMatrix.Events.Context.t()) ::
          {:ok, RoomMembership.t()} | {:error, Ecto.Changeset.t()}
  def upsert_membership(room_id, principal_id, membership, %LakehouseMatrix.Events.Context{} = ctx) do
    state = %{
      "membership" => membership,
      "displayname" => Map.get(ctx.content, "displayname"),
      "event_id" => ctx.event_id,
      "origin_server_ts" => ctx.origin_server_ts
    }

    case Repo.one(
           from m in RoomMembership,
             where: m.room_id == ^room_id and m.principal_id == ^principal_id
         ) do
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
  end

  @spec member_count(Ecto.UUID.t()) :: integer()
  def member_count(room_id) do
    Repo.aggregate(
      from(m in RoomMembership,
        where:
          m.room_id == ^room_id and fragment("?->>'membership' = 'join'", m.membership_state)
      ),
      :count
    )
  end

  defp principal_id_for_mxid(mxid) when is_binary(mxid) do
    username =
      case String.split(mxid, ":", parts: 2) do
        ["@" <> user, _domain] -> String.downcase(user)
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
