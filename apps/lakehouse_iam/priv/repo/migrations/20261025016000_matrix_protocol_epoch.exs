defmodule LakehouseIam.Repo.Migrations.MatrixProtocolEpoch do
  use Ecto.Migration

  def change do
    alter table(:matrix_stream) do
      add(:epoch, :uuid, null: false, default: fragment("gen_random_uuid()"))
    end
  end
end
