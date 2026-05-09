defmodule LakehouseIam.Authorization do
  @moduledoc """
  RBAC checks: principals receive grants (role + optional resource ARN).
  """
  import Ecto.Query

  alias LakehouseIam.Repo
  alias LakehouseIam.Schema.{Grant, Permission, Principal, Resource, Role, RolePermission}

  @spec can?(Ecto.UUID.t(), String.t(), String.t() | nil) :: boolean()
  def can?(principal_id, action, resource_arn) when is_binary(action) do
    rid =
      if resource_arn && resource_arn != "" do
        case Repo.one(from r in Resource, where: r.arn == ^resource_arn, select: r.id) do
          nil -> :missing
          id -> id
        end
      else
        nil
      end

    if rid == :missing do
      false
    else
      permission_ids =
        from(p in Permission,
          where: p.name == ^action,
          select: p.id
        )
        |> Repo.all()

      if permission_ids == [] do
        false
      else
        roles_with_perm =
          from(rp in RolePermission,
            where: rp.permission_id in ^permission_ids,
            select: rp.role_id
          )
          |> Repo.all()
          |> MapSet.new()

        grants =
          from(g in Grant,
            where: g.principal_id == ^principal_id,
            select: {g.role_id, g.resource_id}
          )
          |> Repo.all()

        Enum.any?(grants, fn {role_id, res_id} ->
          if MapSet.member?(roles_with_perm, role_id) do
            cond do
              res_id == nil -> true
              rid != nil and res_id == rid -> true
              true -> false
            end
          else
            false
          end
        end)
      end
    end
  end

  @spec assign_role(Ecto.UUID.t(), String.t(), String.t() | nil) ::
          {:ok, Grant.t()} | {:error, Ecto.Changeset.t() | :not_found}
  def assign_role(principal_id, role_name, resource_arn \\ nil) do
    case Repo.get(Principal, principal_id) do
      nil ->
        {:error, :not_found}

      %Principal{} ->
        case Repo.get_by(Role, name: role_name) do
          nil ->
            {:error, :not_found}

          %Role{id: role_id} ->
            case resolve_resource_id(resource_arn) do
              {:error, _} = err ->
                err

              {:ok, resource_id} ->
                cs =
                  Grant.changeset(%Grant{}, %{
                    principal_id: principal_id,
                    role_id: role_id,
                    resource_id: resource_id
                  })

                existing_q =
                  from g in Grant,
                    where:
                      g.principal_id == ^principal_id and g.role_id == ^role_id and
                        fragment("? IS NOT DISTINCT FROM ?", g.resource_id, ^resource_id)

                case Repo.one(existing_q) do
                  %Grant{} = g ->
                    {:ok, g}

                  nil ->
                    Repo.insert(cs)
                end
            end
        end
    end
  end

  defp resolve_resource_id(nil), do: {:ok, nil}
  defp resolve_resource_id(""), do: {:ok, nil}

  defp resolve_resource_id(arn) when is_binary(arn) do
    case Repo.get_by(Resource, arn: arn) do
      nil ->
        case %Resource{} |> Resource.changeset(%{arn: arn}) |> Repo.insert() do
          {:ok, r} -> {:ok, r.id}
          {:error, cs} -> {:error, cs}
        end

      r ->
        {:ok, r.id}
    end
  end

  @spec revoke_role(Ecto.UUID.t(), String.t(), String.t() | nil) :: :ok | {:error, :not_found}
  def revoke_role(principal_id, role_name, resource_arn \\ nil) do
    role_id = Repo.one(from r in Role, where: r.name == ^role_name, select: r.id)
    rid = if resource_arn && resource_arn != "", do: Repo.one(from r in Resource, where: r.arn == ^resource_arn, select: r.id), else: nil

    if role_id == nil do
      {:error, :not_found}
    else
      q =
        from g in Grant,
          where: g.principal_id == ^principal_id and g.role_id == ^role_id

      q =
        if rid do
          where(q, [g], g.resource_id == ^rid)
        else
          where(q, [g], is_nil(g.resource_id))
        end

      case Repo.delete_all(q) do
        {0, _} -> {:error, :not_found}
        {_, _} -> :ok
      end
    end
  end

  def permissions_for(principal_id) do
    from(p in Permission,
      join: rp in RolePermission,
      on: rp.permission_id == p.id,
      join: g in Grant,
      on: g.role_id == rp.role_id,
      where: g.principal_id == ^principal_id,
      distinct: true,
      select: p.name
    )
    |> Repo.all()
  end

  def roles_for(principal_id) do
    from(r in Role,
      join: g in Grant,
      on: g.role_id == r.id,
      where: g.principal_id == ^principal_id,
      distinct: true,
      select: r.name
    )
    |> Repo.all()
  end

  def resources_for(principal_id) do
    from(res in Resource,
      join: g in Grant,
      on: g.resource_id == res.id,
      where: g.principal_id == ^principal_id,
      distinct: true,
      select: res.arn
    )
    |> Repo.all()
  end
end
