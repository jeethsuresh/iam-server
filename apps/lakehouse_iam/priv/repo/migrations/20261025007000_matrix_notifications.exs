defmodule LakehouseIam.Repo.Migrations.MatrixNotifications do
  use Ecto.Migration

  def up do
    create table(:matrix_notifications, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:local_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :event_id,
        references(:room_events, column: :event_id, type: :text, on_delete: :delete_all),
        null: false
      )

      add(:actions, :map, null: false)
      add(:highlight, :boolean, null: false, default: false)
      add(:stream_id, :bigint, null: false)
      add(:ts, :bigint, null: false)
    end

    create(unique_index(:matrix_notifications, [:principal_id, :event_id]))
    create(index(:matrix_notifications, [:principal_id, :local_room_id, :stream_id]))
    create(index(:matrix_notifications, [:principal_id, :id]))

    execute("CREATE TABLE matrix_receipt_history (LIKE matrix_receipts INCLUDING DEFAULTS)")
    execute("ALTER TABLE matrix_receipt_history DROP COLUMN id")
    execute("ALTER TABLE matrix_receipt_history ADD PRIMARY KEY (stream_id)")

    execute(
      "ALTER TABLE matrix_receipt_history ADD FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE"
    )

    execute(
      "ALTER TABLE matrix_receipt_history ADD FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE"
    )

    execute(
      "INSERT INTO matrix_receipt_history (principal_id, room_id, type, thread_id, event_id, data, stream_id) SELECT principal_id, room_id, type, thread_id, event_id, data, stream_id FROM matrix_receipts"
    )

    create(index(:matrix_receipt_history, [:principal_id, :room_id, :stream_id]))

    execute("""
    CREATE FUNCTION matrix_record_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      INSERT INTO matrix_receipt_history (principal_id, room_id, type, thread_id, event_id, data, stream_id)
      VALUES (NEW.principal_id, NEW.room_id, NEW.type, NEW.thread_id, NEW.event_id, NEW.data, NEW.stream_id);
      RETURN NEW;
    END $$
    """)

    execute(
      "CREATE TRIGGER matrix_receipt_audit AFTER INSERT OR UPDATE ON matrix_receipts FOR EACH ROW EXECUTE FUNCTION matrix_record_receipt()"
    )

    create table(:matrix_pushers, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:principal_id, references(:principals, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:device_id, :text, null: false)
      add(:app_id, :text, null: false)
      add(:pushkey, :text, null: false)
      add(:config, :map, null: false)
      add(:created_at, :utc_datetime_usec, null: false)
    end

    create(unique_index(:matrix_pushers, [:principal_id, :app_id, :pushkey]))
    create(index(:matrix_pushers, [:app_id, :pushkey]))

    create table(:matrix_push_outbox, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:pusher_id, references(:matrix_pushers, type: :bigint, on_delete: :delete_all),
        null: false
      )

      add(
        :notification_id,
        references(:matrix_notifications, type: :bigint, on_delete: :delete_all)
      )

      add(:attempts, :integer, null: false, default: 0)
      add(:available_at, :utc_datetime_usec, null: false)
      add(:lease_until, :utc_datetime_usec)
      add(:delivered_at, :utc_datetime_usec)
    end

    create(index(:matrix_push_outbox, [:available_at], where: "delivered_at IS NULL"))
  end

  def down do
    drop(table(:matrix_push_outbox))
    drop(table(:matrix_pushers))
    execute("DROP TRIGGER matrix_receipt_audit ON matrix_receipts")
    execute("DROP FUNCTION matrix_record_receipt()")
    drop(table(:matrix_receipt_history))
    drop(table(:matrix_notifications))
  end
end
