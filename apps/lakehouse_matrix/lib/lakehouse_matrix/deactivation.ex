defmodule LakehouseMatrix.Deactivation do
  @moduledoc "Authenticated, permanent closure of the shared Gravitas identity and durable room departure."
  import Ecto.Query
  alias LakehouseIam.{Repo, Accounts}
  alias LakehouseIam.Schema.{Credential, Grant, Principal, AppGrant}
  alias LakehouseMatrix.{AccountModeration, ClientStore, ClientUia, Erasure}

  def deactivate(principal, device, params) do
    if params["erase"] in [nil, true, false] and
         (is_nil(params["id_server"]) or is_binary(params["id_server"])) do
      ClientUia.perform(principal, device, "deactivate", params, fn ->
        close(principal, params["erase"] == true)
      end)
    else
      {:error, :invalid_param}
    end
  end

  defp close(principal, erase) do
    ClientStore.lock!()
    AccountModeration.require!(principal, :read)
    account = Repo.one!(from p in Principal, where: p.id == ^principal, lock: "FOR NO KEY UPDATE")
    unless Accounts.active?(account), do: Repo.rollback(:user_deactivated)
    if erase, do: Erasure.erase!(principal)

    for devices <-
          ClientStore.devices(principal) |> Enum.map(& &1.device_id) |> Enum.chunk_every(100) do
      case ClientStore.delete_devices(principal, devices) do
        {:ok, _} -> :ok
        {:error, reason} -> Repo.rollback(reason)
      end
    end

    # Token refresh locks its token/session family before inserting replacements.
    # Revoke authority now, without taking the conflicting grant-deletion lock;
    # the durable worker removes these rows after the account closure commits.
    Repo.update_all(from(g in AppGrant, where: g.principal_id == ^principal),
      set: [scopes: [], room_ids: [], room_mode: :selected]
    )

    Repo.delete_all(from c in Credential, where: c.principal_id == ^principal)
    Repo.delete_all(from g in Grant, where: g.principal_id == ^principal)
    LakehouseIam.Auth.Sessions.revoke_for_principal(principal)

    for table <-
          ~w(matrix_sessions matrix_login_tokens matrix_uia_sessions matrix_openid_tokens matrix_filters matrix_account_data matrix_cross_signing matrix_key_signatures matrix_key_backups matrix_notifications matrix_pushers matrix_preview_requests matrix_media_reservations matrix_hierarchy_cursors matrix_sync_connections matrix_transactions) do
      Repo.delete_all(from row in table, where: row.principal_id == type(^principal, :binary_id))
    end

    if erase do
      Repo.delete_all(
        from r in "matrix_reports", where: r.principal_id == type(^principal, :binary_id)
      )

      Repo.delete_all(
        from r in "river_friend_blocks", where: r.owner_id == type(^principal, :binary_id)
      )

      Repo.delete_all(
        from r in "river_friendships",
          where:
            r.low_id == type(^principal, :binary_id) or r.high_id == type(^principal, :binary_id)
      )

      Repo.delete_all(
        from r in "river_social_events", where: r.actor_id == type(^principal, :binary_id)
      )
    end

    account
    |> Ecto.Changeset.change(
      active: false,
      matrix_deactivated: true,
      meta: %{"matrix_profile" => %{}}
    )
    |> Repo.update!()

    LakehouseMatrix.Ephemeral.deactivate_presence!(principal)

    Repo.insert_all(
      "matrix_deactivation_jobs",
      [
        %{
          principal_id: ClientStore.dump_id(principal),
          available_at: ClientStore.now(),
          attempts: 0
        }
      ],
      on_conflict: :nothing
    )

    LakehouseIam.Changes.notify(%{"principal_id" => principal})
    # This homeserver never binds 3PIDs to an identity service.
    {:ok, %{"id_server_unbind_result" => "success"}}
  end
end
