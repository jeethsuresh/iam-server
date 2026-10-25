defmodule LakehouseIam.Repo.Migrations.MatrixRelationsIndexes do
  use Ecto.Migration

  def change do
    execute(
      "CREATE INDEX matrix_pdus_relation_parent ON matrix_pdus (local_room_id, (pdu->'content'->'m.relates_to'->>'event_id'), event_id) WHERE NOT outlier AND NOT auth_rejected AND NOT state_rejected AND NOT soft_failed",
      "DROP INDEX matrix_pdus_relation_parent"
    )

    execute(
      "CREATE INDEX matrix_pdus_relation_type ON matrix_pdus (local_room_id, (pdu->'content'->'m.relates_to'->>'rel_type'), event_id) WHERE NOT outlier AND NOT auth_rejected AND NOT state_rejected AND NOT soft_failed",
      "DROP INDEX matrix_pdus_relation_type"
    )
  end
end
