defmodule LakehouseIam.Repo.Migrations.MatrixTimestampIndex do
  use Ecto.Migration

  def change do
    execute(
      "CREATE INDEX matrix_pdus_timestamp ON matrix_pdus (local_room_id, ((pdu->>'origin_server_ts')::bigint), event_id) WHERE NOT outlier AND NOT auth_rejected AND NOT state_rejected AND NOT soft_failed",
      "DROP INDEX matrix_pdus_timestamp"
    )
  end
end
