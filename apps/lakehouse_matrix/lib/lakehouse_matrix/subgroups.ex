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
    # Release.migrate starts only the repository. Loading this application's
    # environment preserves the configured homeserver identity without starting
    # any Matrix workers while the migration owns the database.
    case Application.load(:lakehouse_matrix) do
      :ok -> :ok
      {:error, {:already_loaded, :lakehouse_matrix}} -> :ok
      error -> raise "cannot load Matrix configuration for subgroup backfill: #{inspect(error)}"
    end

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
