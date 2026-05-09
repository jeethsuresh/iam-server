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
          :ok
      end
    end
  end
end
