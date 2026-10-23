defmodule LakehouseIam.Schema.FederatedEntry do
  use Ecto.Schema
  @primary_key {:key, :string, autogenerate: false}
  schema "iam_federated_entries" do
    field :kind, Ecto.Enum, values: [:session, :code]
    field :data, :map
    field :expires_at, :integer
  end
end
