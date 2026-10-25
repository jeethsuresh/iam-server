defmodule LakehouseIam.Repo.Migrations.MatrixFederationDelivery do
  use Ecto.Migration

  def change do
    alter table(:matrix_federation_outbox) do
      modify(:event_id, :text, null: true, from: {:text, null: false})
      add(:kind, :text, null: false, default: "pdu")
      add(:payload, :map, null: false, default: %{})
      add(:delivered_at, :utc_datetime_usec)
      add(:failed_at, :utc_datetime_usec)
    end

    create table(:matrix_federation_inbox, primary_key: false) do
      add(:event_id, :text, primary_key: true)
      add(:origin, :text, null: false)

      add(:local_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:pdu, :map, null: false)
      add(:attempts, :integer, null: false, default: 0)
      add(:available_at, :utc_datetime_usec, null: false)
      add(:last_error, :text)
    end

    create(index(:matrix_federation_inbox, [:available_at]))

    create table(:matrix_federation_edus, primary_key: false) do
      add(:id, :bigserial, primary_key: true)
      add(:origin, :text, null: false)
      add(:message_id, :text, null: false)
      add(:received_at, :utc_datetime_usec, null: false)
    end

    create(unique_index(:matrix_federation_edus, [:origin, :message_id]))

    create table(:matrix_pending_invites, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:local_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:user_id, :text, null: false)
      add(:origin, :text, null: false)
      add(:event_id, :text, null: false)
      add(:stripped_state, :map, null: false)
    end

    create(unique_index(:matrix_pending_invites, [:local_room_id, :user_id]))

    create table(:matrix_remote_users, primary_key: false) do
      add(:user_id, :text, primary_key: true)
      add(:device_stream_id, :bigint)
      add(:valid, :boolean, null: false, default: false)
      add(:master_key, :map)
      add(:self_signing_key, :map)
      add(:stream_id, :bigint, null: false)
    end

    create table(:matrix_remote_devices, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(
        :user_id,
        references(:matrix_remote_users, column: :user_id, type: :text, on_delete: :delete_all),
        null: false
      )

      add(:device_id, :text, null: false)
      add(:keys, :map, null: false, default: %{})
      add(:display_name, :text)
    end

    create(unique_index(:matrix_remote_devices, [:user_id, :device_id]))

    create table(:matrix_remote_receipts, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:local_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:user_id, :text, null: false)
      add(:type, :text, null: false)
      add(:thread_id, :text, null: false, default: "")
      add(:event_id, :text, null: false)
      add(:data, :map, null: false)
      add(:stream_id, :bigint, null: false)
    end

    create(unique_index(:matrix_remote_receipts, [:local_room_id, :user_id, :type, :thread_id]))

    create table(:matrix_ephemeral_events, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:local_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:user_id, :text, null: false)
      add(:type, :text, null: false)
      add(:content, :map, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)
      add(:stream_id, :bigint, null: false)
    end

    create(unique_index(:matrix_ephemeral_events, [:local_room_id, :type, :user_id]))

    create table(:matrix_device_changes, primary_key: false) do
      add(:id, :bigserial, primary_key: true)
      add(:user_id, :text, null: false)
      add(:stream_id, :bigint, null: false)
    end

    for table <- ~w(matrix_remote_users matrix_remote_receipts matrix_ephemeral_events) do
      execute(
        "CREATE TRIGGER matrix_stream_trigger BEFORE INSERT OR UPDATE ON #{table} FOR EACH ROW EXECUTE FUNCTION matrix_stream_position()",
        "DROP TRIGGER matrix_stream_trigger ON #{table}"
      )
    end

    execute(
      "CREATE TRIGGER matrix_stream_trigger BEFORE INSERT ON matrix_device_changes FOR EACH ROW EXECUTE FUNCTION matrix_stream_position()",
      "DROP TRIGGER matrix_stream_trigger ON matrix_device_changes"
    )
  end
end
