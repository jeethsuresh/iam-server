defmodule LakehouseIam.Apps.Grants do
  @moduledoc """
  Persistent per-(principal, app_origin) consent grants.
  """
  import Ecto.Query

  alias LakehouseIam.Apps.Scopes
  alias LakehouseIam.Repo
  alias LakehouseIam.Schema.AppGrant

  @spec get(Ecto.UUID.t(), String.t()) :: AppGrant.t() | nil
  def get(principal_id, app_origin) do
    Repo.get_by(AppGrant, principal_id: principal_id, app_origin: app_origin)
  end

  @spec list_for_principal(Ecto.UUID.t()) :: [AppGrant.t()]
  def list_for_principal(principal_id) do
    from(g in AppGrant, where: g.principal_id == ^principal_id, order_by: [asc: g.app_origin])
    |> Repo.all()
  end

  @doc """
  Upsert grant. `room_mode` is `:all` or `:selected` with `room_ids`.
  """
  def upsert(principal_id, app_origin, scopes, room_mode, room_ids \\ []) do
    attrs = %{
      principal_id: principal_id,
      app_origin: app_origin,
      scopes: Enum.uniq(scopes),
      room_mode: room_mode,
      room_ids: if(room_mode == :all, do: [], else: Enum.uniq(room_ids))
    }

    case get(principal_id, app_origin) do
      nil ->
        %AppGrant{}
        |> AppGrant.changeset(attrs)
        |> Repo.insert()

      existing ->
        merged_scopes = Enum.uniq(existing.scopes ++ scopes)

        {mode, ids} =
          merge_rooms(existing.room_mode, existing.room_ids, room_mode, room_ids)

        existing
        |> AppGrant.changeset(%{
          scopes: merged_scopes,
          room_mode: mode,
          room_ids: ids
        })
        |> Repo.update()
    end
  end

  defp merge_rooms(:all, _, _, _), do: {:all, []}
  defp merge_rooms(_, _, :all, _), do: {:all, []}

  defp merge_rooms(:selected, old_ids, :selected, new_ids) do
    {:selected, Enum.uniq(old_ids ++ new_ids)}
  end

  @doc """
  Whether an existing grant covers the requested scopes and room selection.
  """
  def covers?(%AppGrant{} = grant, requested_scopes, requested_mode, requested_room_ids) do
    Scopes.covers?(grant.scopes, requested_scopes) and
      rooms_cover?(grant, requested_mode, requested_room_ids)
  end

  def covers?(nil, _, _, _), do: false

  defp rooms_cover?(%{room_mode: :all}, _, _), do: true

  defp rooms_cover?(%{room_mode: :selected}, :all, _), do: false

  defp rooms_cover?(%{room_mode: :selected, room_ids: have}, :selected, need) do
    MapSet.subset?(MapSet.new(need), MapSet.new(have))
  end

  @spec room_allowed?(AppGrant.t(), Ecto.UUID.t()) :: boolean()
  def room_allowed?(%AppGrant{room_mode: :all}, _room_id), do: true

  def room_allowed?(%AppGrant{room_mode: :selected, room_ids: ids}, room_id) do
    room_id in ids
  end

  @spec revoke(Ecto.UUID.t()) :: :ok | {:error, :not_found}
  def revoke(grant_id) do
    case Repo.get(AppGrant, grant_id) do
      nil ->
        {:error, :not_found}

      grant ->
        {:ok, _} = Repo.delete(grant)
        LakehouseIam.Changes.notify(%{"principal_id" => grant.principal_id})
        :ok
    end
  end

  @spec revoke_for(Ecto.UUID.t(), String.t()) :: :ok | {:error, :not_found}
  def revoke_for(principal_id, app_origin) do
    case get(principal_id, app_origin) do
      nil -> {:error, :not_found}
      grant -> revoke(grant.id)
    end
  end
end
