defmodule LakehouseIam.Repo.Migrations.MatrixEventFields do
  use Ecto.Migration

  def change do
    alter table(:room_events) do
      add :sender, :string
      add :principal_id, references(:principals, type: :binary_id, on_delete: :nilify_all)
      add :origin_server_ts, :bigint
      add :state_key, :string
    end

    create index(:room_events, [:principal_id])
    create index(:room_events, [:room_id, :origin_server_ts])
    create unique_index(:room_events, [:event_id])
  end
end
