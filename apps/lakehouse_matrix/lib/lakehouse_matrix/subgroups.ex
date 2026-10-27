defmodule LakehouseMatrix.Subgroups do
  @moduledoc "Projects authoritative joined membership into the Gravitas participant-set registry."
  import Ecto.Query
  alias LakehouseIam.{Accounts, ParticipantSets, Repo}
  alias LakehouseMatrix.{Identity, Memberships}
  alias LakehouseMatrix.Schema.{ProtocolRoom, Room, RoomState}

  def sync!(room, event_id \\ nil) do
    members =
      if Repo.get(ProtocolRoom, room) do
        Repo.all(
          from s in RoomState,
            where:
              s.room_id == ^room and s.type == "m.room.member" and
                fragment("?->>'membership' = 'join'", s.content),
            select: s.state_key
        )
        |> Enum.map(&subject/1)
      else
        for {id, "join"} <- Memberships.membership_map(room), do: ParticipantSets.principal(id)
      end

    ParticipantSets.bind!(room, Enum.sort(Enum.uniq(members)), event_id)
  end

  def backfill! do
    for p <-
          Repo.all(from p in LakehouseIam.Schema.Principal, where: p.type == :user, select: p.id),
        do: ParticipantSets.register!([ParticipantSets.principal(p)])

    for id <- Repo.all(from r in Room, select: r.id), do: sync!(id)
  end

  defp subject(user) do
    with {:ok, name} <- Identity.parse_user_id(user),
         {:ok, person} <- Accounts.fetch_user(name),
         do: ParticipantSets.principal(person.id),
         else: (_ -> "matrix:" <> user)
  end
end
