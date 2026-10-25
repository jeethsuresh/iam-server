defmodule LakehouseMatrix.RoomReset do
  @moduledoc "Explicit maintenance-only room reset. Never called by a migration or application startup."
  import Ecto.Query
  alias LakehouseIam.Repo
  alias LakehouseIam.Schema.{AppGrant, Resource}
  alias LakehouseMatrix.{ClientStore, Identity}
  alias LakehouseMatrix.Schema.Room

  def plan do
    %{
      "server_name" => Identity.homeserver_domain(),
      "rooms" => Repo.aggregate(Room, :count),
      "events" => Repo.aggregate(LakehouseMatrix.Schema.RoomEvent, :count),
      "matrix_sessions_to_revoke" => Repo.aggregate(from(s in "matrix_sessions"), :count),
      "preserve" =>
        ~w(accounts identity_credentials iam_sessions app_tokens uploads device_keys cross_signing encrypted_backups global_account_data)
    }
  end

  # Quiesce all application writers and verify a fresh database backup before
  # calling this release task. The domain check prevents a command prepared for
  # another homeserver from silently resetting this database.
  def run(expected_server) do
    if expected_server != Identity.homeserver_domain() do
      {:error, :wrong_server}
    else
      Repo.transaction(fn ->
        ClientStore.lock!()
        before = plan()
        rooms = Repo.all(from r in Room, select: r.id)

        for batch <- Enum.chunk_every(rooms, 500) do
          arns = Enum.map(batch, &Identity.resource_arn/1)
          # The resource FK deletes scoped role grants; it must never be
          # nullified into a global grant.
          Repo.delete_all(from r in Resource, where: r.arn in ^arns)
          scopes = Enum.flat_map(batch, &["send:" <> &1, "redact:" <> &1])
          Repo.delete_all(from t in "matrix_transactions", where: t.scope in ^scopes)
        end

        Repo.update_all(AppGrant, set: [room_ids: []])
        Repo.delete_all(from d in "matrix_account_data", where: d.room_id != "")

        Repo.update_all(
          from(d in "matrix_account_data", where: d.room_id == "" and d.type == "m.direct"),
          set: [content: %{}]
        )

        clear_room_rules!()

        for table <-
              ~w(matrix_sync_connections matrix_hierarchy_cursors matrix_hierarchy_cache matrix_sessions matrix_login_tokens matrix_sso_requests matrix_uia_sessions) do
          Repo.delete_all(from(row in table))
        end

        Repo.delete_all(
          from o in "matrix_federation_outbox",
            where:
              o.kind != "edu" or
                fragment(
                  "EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(?->'edus', '[]'::jsonb)) edu WHERE edu->>'edu_type' IN ('m.typing','m.presence','m.receipt'))",
                  o.payload
                )
        )

        # DELETE honors FK actions. TRUNCATE CASCADE could erase unrelated
        # data in referencing tables and must never be used here.
        Repo.delete_all(Room)
        epoch = Ecto.UUID.generate()

        Repo.update_all(from(s in "matrix_stream", where: s.id == 1),
          set: [epoch: ClientStore.dump_id(epoch)],
          inc: [position: 1]
        )

        Map.merge(before, %{"rooms_after" => Repo.aggregate(Room, :count), "epoch" => epoch})
      end)
    end
  end

  defp clear_room_rules! do
    rows =
      Repo.all(
        from d in "matrix_account_data",
          where: d.room_id == "" and d.type == "m.push_rules",
          select: %{id: d.id, content: d.content}
      )

    for %{id: id, content: %{"global" => global} = content} <- rows, is_map(global) do
      value = Map.put(content, "global", Map.put(global, "room", []))
      Repo.update_all(from(d in "matrix_account_data", where: d.id == ^id), set: [content: value])
    end
  end
end
