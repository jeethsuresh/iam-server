defmodule LakehouseIam.Repo do
  use Ecto.Repo,
    otp_app: :lakehouse_iam,
    adapter: Ecto.Adapters.Postgres
end
