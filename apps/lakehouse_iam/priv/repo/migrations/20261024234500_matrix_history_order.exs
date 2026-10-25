defmodule LakehouseIam.Repo.Migrations.MatrixHistoryOrder do
  use Ecto.Migration

  def up do
    execute(
      "CREATE INDEX matrix_pdus_history_order ON matrix_pdus (local_room_id, ((pdu->>'depth')::bigint), event_id) WHERE NOT outlier AND NOT auth_rejected AND NOT state_rejected AND NOT soft_failed"
    )
  end

  def down do
    execute("DROP INDEX matrix_pdus_history_order")
  end
end
