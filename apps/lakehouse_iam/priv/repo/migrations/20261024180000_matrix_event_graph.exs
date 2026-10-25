defmodule LakehouseIam.Repo.Migrations.MatrixEventGraph do
  use Ecto.Migration

  def change do
    create table(:matrix_protocol_rooms, primary_key: false) do
      add(:local_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        primary_key: true
      )

      add(:room_id, :text, null: false)
      add(:version, :string, null: false)
      add(:create_id, :text, null: false)
      add(:current_state, :map, null: false, default: %{})
      add(:extremities, {:array, :text}, null: false, default: [])
    end

    create(unique_index(:matrix_protocol_rooms, [:room_id]))

    create table(:matrix_pdus, primary_key: false) do
      add(:event_id, :text, primary_key: true)

      add(:local_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:pdu, :map, null: false)
      add(:state_before, :map, null: false, default: %{})
      add(:state_after, :map, null: false, default: %{})
      add(:auth_rejected, :boolean, null: false, default: false)
      add(:state_rejected, :boolean, null: false, default: false)
      add(:soft_failed, :boolean, null: false, default: false)
      add(:outlier, :boolean, null: false, default: false)
      add(:received_at, :utc_datetime_usec, null: false)
    end

    create(index(:matrix_pdus, [:local_room_id]))

    create table(:matrix_state_changes, primary_key: false) do
      add(:id, :bigserial, primary_key: true)

      add(:local_room_id, references(:rooms, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:type, :text, null: false)
      add(:state_key, :text, null: false)

      add(
        :event_id,
        references(:matrix_pdus, column: :event_id, type: :text, on_delete: :delete_all)
      )

      add(:stream_id, :bigint, null: false)
    end

    create(index(:matrix_state_changes, [:local_room_id, :stream_id]))

    execute(
      "CREATE TRIGGER matrix_stream_trigger BEFORE INSERT ON matrix_state_changes FOR EACH ROW EXECUTE FUNCTION matrix_stream_position()",
      "DROP TRIGGER matrix_stream_trigger ON matrix_state_changes"
    )

    create table(:matrix_federation_transactions, primary_key: false) do
      add(:id, :bigserial, primary_key: true)
      add(:origin, :text, null: false)
      add(:transaction_id, :text, null: false)
      add(:request_hash, :binary, null: false)
      add(:response, :map, null: false)
      add(:received_at, :utc_datetime_usec, null: false)
    end

    create(unique_index(:matrix_federation_transactions, [:origin, :transaction_id]))

    create table(:matrix_federation_outbox, primary_key: false) do
      add(:id, :bigserial, primary_key: true)
      add(:destination, :text, null: false)

      add(
        :event_id,
        references(:matrix_pdus, column: :event_id, type: :text, on_delete: :delete_all),
        null: false
      )

      add(:attempts, :integer, null: false, default: 0)
      add(:available_at, :utc_datetime_usec, null: false)
      add(:lease_until, :utc_datetime_usec)
      add(:transaction_id, :text, null: false)
      add(:last_error, :text)
    end

    create(unique_index(:matrix_federation_outbox, [:destination, :event_id]))
    create(index(:matrix_federation_outbox, [:available_at]))

    create table(:matrix_server_keys, primary_key: false) do
      add(:id, :bigserial, primary_key: true)
      add(:server_name, :text, null: false)
      add(:key_id, :text, null: false)
      add(:public_key, :binary, null: false)
      add(:valid_until_ts, :bigint, null: false)
      add(:fetched_at, :utc_datetime_usec, null: false)
    end

    create(unique_index(:matrix_server_keys, [:server_name, :key_id]))
  end
end
