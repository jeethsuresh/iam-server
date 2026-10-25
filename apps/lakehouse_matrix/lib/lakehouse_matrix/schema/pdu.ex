defmodule LakehouseMatrix.Schema.Pdu do
  use Ecto.Schema
  @primary_key {:event_id, :string, autogenerate: false}
  schema "matrix_pdus" do
    field :local_room_id, :binary_id
    field :pdu, :map
    field :state_before, :map, default: %{}
    field :state_after, :map, default: %{}
    field :auth_rejected, :boolean, default: false
    field :state_rejected, :boolean, default: false
    field :soft_failed, :boolean, default: false
    field :policy_rejected, :boolean, default: false
    field :outlier, :boolean, default: false
    field :redacted_by, :string
    field :redaction_applied, :boolean, default: false
    field :received_at, :utc_datetime_usec
  end
end
