defmodule LakehouseIam.Repo.Migrations.MatrixAccountErasure do
  use Ecto.Migration

  def up do
    alter table(:principals) do
      add(:matrix_deactivated, :boolean, null: false, default: false)
    end

    create table(:matrix_erased_users, primary_key: false) do
      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        primary_key: true
      )

      add(:user_id, :text, null: false)
      add(:stream_id, :bigint, null: false)
    end

    create(unique_index(:matrix_erased_users, [:user_id]))

    create table(:matrix_erased_events, primary_key: false) do
      add(:event_id, :text, primary_key: true)

      add(:local_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:original_content, :map, null: false)
      add(:event_type, :text, null: false, default: "")
      add(:original_pdu, :map)
      add(:pruned_pdu, :map)
    end

    create(index(:matrix_erased_events, [:principal_id, :local_room_id]))

    create table(:matrix_deactivation_jobs, primary_key: false) do
      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        primary_key: true
      )

      add(:available_at, :utc_datetime_usec, null: false)
      add(:lease_until, :utc_datetime_usec)
      add(:attempts, :integer, default: 0, null: false)
    end

    execute("""
    CREATE INDEX matrix_erasure_prior_join ON room_events(room_id, state_key, stream_id)
      WHERE type = 'm.room.member' AND content->>'membership' = 'join'
    """)

    execute("""
    CREATE FUNCTION matrix_erasure_access(event text, viewer_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
      SELECT EXISTS (
        SELECT 1 FROM matrix_erased_events a
        JOIN matrix_erased_users erased ON erased.principal_id = a.principal_id
        JOIN principals viewer ON viewer.id = viewer_id
        JOIN room_events member ON member.room_id = a.local_room_id
        WHERE a.event_id = event AND member.type = 'm.room.member'
          AND member.state_key = '@' || viewer.username || ':' ||
            substring(erased.user_id FROM position(':' IN erased.user_id) + 1)
          AND member.content->>'membership' = 'join' AND member.stream_id <= erased.stream_id
          AND NOT EXISTS (SELECT 1 FROM matrix_pdus p WHERE p.event_id = event AND p.redacted_by IS NOT NULL)
          AND NOT EXISTS (SELECT 1 FROM room_events r WHERE r.room_id = a.local_room_id
            AND r.type = 'm.room.redaction' AND r.content->>'redacts' = event)
      )
    $$
    """)

    execute("""
    CREATE FUNCTION matrix_view_content(event text, viewer_id uuid) RETURNS jsonb
    LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
      SELECT COALESCE(
        (SELECT original_content FROM matrix_erased_events WHERE event_id = event AND matrix_erasure_access(event, viewer_id)),
        (SELECT content FROM room_events WHERE event_id = event)
      )
    $$
    """)

    execute("""
    CREATE FUNCTION matrix_view_pdu(event text, viewer_id uuid) RETURNS jsonb
    LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
      SELECT COALESCE(
        (SELECT original_pdu FROM matrix_erased_events WHERE event_id = event AND matrix_erasure_access(event, viewer_id)),
        (SELECT a.pruned_pdu FROM matrix_erased_events a JOIN matrix_pdus p ON p.event_id = a.event_id WHERE a.event_id = event AND p.redacted_by IS NULL),
        (SELECT pdu FROM matrix_pdus WHERE event_id = event)
      )
    $$
    """)

    execute("""
    CREATE INDEX matrix_erased_search ON matrix_erased_events USING gin
      (to_tsvector('english', matrix_search_text(event_type, original_content)))
    """)
  end

  def down do
    execute("DROP FUNCTION matrix_view_pdu(text, uuid)")
    execute("DROP FUNCTION matrix_view_content(text, uuid)")
    execute("DROP FUNCTION matrix_erasure_access(text, uuid)")
    execute("DROP INDEX matrix_erasure_prior_join")
    drop(table(:matrix_deactivation_jobs))
    drop(table(:matrix_erased_events))
    drop(table(:matrix_erased_users))

    alter table(:principals) do
      remove(:matrix_deactivated)
    end
  end
end
