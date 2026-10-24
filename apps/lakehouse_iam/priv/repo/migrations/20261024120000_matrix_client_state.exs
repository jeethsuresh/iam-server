defmodule LakehouseIam.Repo.Migrations.MatrixClientState do
  use Ecto.Migration

  def up do
    # A sequence alone is unsafe for sync: a later transaction can commit first.
    # This row is locked until commit, so a returned cursor never skips a writer.
    execute(
      "CREATE TABLE matrix_stream (id integer PRIMARY KEY CHECK (id = 1), position bigint NOT NULL)"
    )

    execute("INSERT INTO matrix_stream VALUES (1, 0)")

    execute("""
    CREATE FUNCTION matrix_stream_position() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      UPDATE matrix_stream SET position = position + 1 WHERE id = 1 RETURNING position INTO NEW.stream_id;
      RETURN NEW;
    END $$
    """)

    alter table(:room_events) do
      add(:stream_id, :bigint)
    end

    execute("""
    WITH ordered AS (SELECT id, row_number() OVER (ORDER BY inserted_at, id) AS n FROM room_events)
    UPDATE room_events e SET stream_id = ordered.n FROM ordered WHERE ordered.id = e.id
    """)

    execute(
      "UPDATE matrix_stream SET position = COALESCE((SELECT max(stream_id) FROM room_events), 0)"
    )

    execute("ALTER TABLE room_events ALTER COLUMN stream_id SET NOT NULL")
    create(unique_index(:room_events, [:stream_id]))
    create(index(:room_events, [:room_id, :stream_id]))
    stream_trigger("room_events", "INSERT")

    create table(:matrix_devices, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:device_id, :text, null: false)
      add(:display_name, :text)
      add(:keys, :map, null: false, default: %{})
      add(:stream_id, :bigint, null: false)
      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:matrix_devices, [:principal_id, :device_id]))
    stream_trigger("matrix_devices")

    create table(:matrix_sessions, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:device_id, :text, null: false)
      add(:token_hash, :binary, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create(unique_index(:matrix_sessions, [:token_hash]))
    create(index(:matrix_sessions, [:principal_id, :device_id]))

    create table(:matrix_account_data, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:room_id, :text, null: false, default: "")
      add(:type, :text, null: false)
      add(:content, :map, null: false, default: %{})
      add(:stream_id, :bigint, null: false)
    end

    create(unique_index(:matrix_account_data, [:principal_id, :room_id, :type]))
    stream_trigger("matrix_account_data")

    create table(:matrix_filters, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:content, :map, null: false)
    end

    create table(:matrix_to_device, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:device_id, :text, null: false)
      add(:type, :text, null: false)
      add(:sender, :text, null: false)
      add(:content, :map, null: false)
      add(:stream_id, :bigint, null: false)
    end

    create(index(:matrix_to_device, [:principal_id, :device_id, :stream_id]))
    stream_trigger("matrix_to_device", "INSERT")

    create table(:matrix_transactions, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:device_id, :text, null: false)
      add(:txn_id, :text, null: false)
      add(:scope, :text, null: false)
      add(:response, :map, null: false)
    end

    create(unique_index(:matrix_transactions, [:principal_id, :device_id, :scope, :txn_id]))

    create table(:matrix_one_time_keys, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:device_id, :text, null: false)
      add(:key_id, :text, null: false)
      add(:key, :map, null: false)
      add(:fallback, :boolean, null: false, default: false)
      add(:used, :boolean, null: false, default: false)
    end

    create(unique_index(:matrix_one_time_keys, [:principal_id, :device_id, :key_id]))

    create table(:matrix_sync_connections, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:device_id, :text, null: false)
      add(:conn_id, :text, null: false)
      add(:token, :text, null: false)
      add(:position, :bigint, null: false)
      add(:state, :map, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
    end

    create(index(:matrix_sync_connections, [:principal_id, :device_id, :conn_id]))
    create(unique_index(:matrix_sync_connections, [:token]))

    create table(:matrix_receipts, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:room_id, references(:rooms, type: :binary_id, on_delete: :delete_all), null: false)
      add(:type, :text, null: false)
      add(:thread_id, :text, null: false, default: "")
      add(:event_id, :text, null: false)
      add(:data, :map, null: false)
      add(:stream_id, :bigint, null: false)
    end

    create(unique_index(:matrix_receipts, [:principal_id, :room_id, :type, :thread_id]))
    stream_trigger("matrix_receipts")

    execute(fn ->
      domain = Application.fetch_env!(:lakehouse_matrix, :homeserver_domain)

      Ecto.Adapters.SQL.query!(
        repo(),
        """
        INSERT INTO matrix_account_data (principal_id, room_id, type, content)
        SELECT owner, '', 'm.direct', jsonb_object_agg('@' || p.username || ':' || $1,
          jsonb_build_array('!' || pairs.id::text || ':' || $1))
        FROM (
          SELECT id, low_id AS owner, high_id AS peer FROM river_directs
          UNION ALL SELECT id, high_id AS owner, low_id AS peer FROM river_directs
        ) pairs JOIN principals p ON p.id = pairs.peer GROUP BY owner
        """,
        [domain]
      )
    end)
  end

  def down do
    for table <-
          ~w(matrix_receipts matrix_sync_connections matrix_one_time_keys matrix_transactions matrix_to_device matrix_filters matrix_account_data matrix_sessions matrix_devices) do
      execute("DROP TABLE #{table}")
    end

    execute("DROP TRIGGER matrix_stream_trigger ON room_events")
    alter(table(:room_events), do: remove(:stream_id))
    execute("DROP FUNCTION matrix_stream_position()")
    execute("DROP TABLE matrix_stream")
  end

  defp stream_trigger(table, operations \\ "INSERT OR UPDATE") do
    execute(
      "CREATE TRIGGER matrix_stream_trigger BEFORE #{operations} ON #{table} FOR EACH ROW EXECUTE FUNCTION matrix_stream_position()"
    )
  end
end
