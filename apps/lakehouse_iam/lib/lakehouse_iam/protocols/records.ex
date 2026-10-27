defmodule LakehouseIam.Protocols.Spec do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "protocol_specs" do
    field :protocol, :string
    field :version, :string
    field :owner, :string
    field :specification, :map
  end
end

defmodule LakehouseIam.Protocols.Registration do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "protocol_registrations" do
    field :grant_id, :binary_id
    field :spec_id, :binary_id
  end
end

defmodule LakehouseIam.Protocols.Invocation do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "protocol_invocations" do
    field :sender, :string
    field :request_id, :string
    field :digest, :string
    field :created_at, :utc_datetime_usec
  end
end

defmodule LakehouseIam.Protocols.Delivery do
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "protocol_deliveries" do
    field :invocation_id, :binary_id
    field :registration_id, :binary_id
    field :envelope, :map
    field :attempts, :integer, default: 0
    field :available_at, :utc_datetime_usec
    field :lease, :binary_id
  end
end
