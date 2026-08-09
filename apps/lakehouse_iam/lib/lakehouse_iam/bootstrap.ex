defmodule LakehouseIam.Bootstrap do
  @moduledoc """
  Ensures the bootstrap admin account exists when `IAM_ADMIN_PASSWORD` is set,
  matching iam-server `EnsureBootstrapAdmin` behaviour.
  """
  import Ecto.Query

  alias LakehouseIam.Accounts
  alias LakehouseIam.Repo
  alias LakehouseIam.Schema.Principal

  @spec run() :: :ok
  def run do
    username = Application.fetch_env!(:lakehouse_iam, :admin_username) |> String.trim()
    password = Application.fetch_env!(:lakehouse_iam, :admin_password) |> String.trim()

    if username == "" or password == "" do
      :ok
    else
      canonical = Accounts.normalize_username(username)

      case Repo.one(from p in Principal, where: p.username == ^canonical, select: p.id) do
        nil ->
          case Accounts.register_user(canonical, password, approve: true) do
            {:ok, _} -> :ok
            {:error, _} -> :ok
          end

        id ->
          _ = Accounts.set_password(id, password)
          _ = Accounts.set_active(id, true)
          _ = LakehouseIam.IAM.assign_role(id, "member")
          :ok
      end
    end

    ensure_member_roles()
  end

  @doc """
  Grants the global `member` role to active users who lack any role grant.
  Covers accounts approved before role assignment was wired up.
  """
  @spec ensure_member_roles() :: :ok
  def ensure_member_roles do
    active_ids =
      Repo.all(
        from p in Principal,
          where: p.type == :user and p.active == true,
          select: p.id
      )

    for principal_id <- active_ids do
      if LakehouseIam.IAM.roles_for(principal_id) == [] do
        _ = LakehouseIam.IAM.assign_role(principal_id, "member")
      end
    end

    :ok
  end
end
