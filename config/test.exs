import Config

config :lakehouse_iam, LakehouseIam.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "lakehouse_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

config :lakehouse_web, LakehouseWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "testsecret_testsecret_testsecret_testsecret_testsecret_test_sec",
  server: false

config :logger, level: :warning
