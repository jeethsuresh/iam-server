import Config

config :lakehouse_iam, LakehouseIam.Repo,
  username: System.get_env("POSTGRES_USER") || "postgres",
  password: System.get_env("POSTGRES_PASSWORD") || "postgres",
  hostname: System.get_env("POSTGRES_HOST") || "localhost",
  port: String.to_integer(System.get_env("POSTGRES_PORT") || "5432"),
  database: "lakehouse_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

test_port = String.to_integer(System.get_env("PORT") || "4002")

config :lakehouse_web, LakehouseWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: test_port],
  url: [host: "127.0.0.1", port: test_port],
  secret_key_base: "testsecret_testsecret_testsecret_testsecret_testsecret_testsecret_64b",
  server: true,
  check_origin: false

config :logger, level: :warning

config :lakehouse_iam,
  admin_username: "admin",
  admin_password: "adminpass"

demo_port = String.to_integer(System.get_env("DEMO_PORT") || "4102")

config :lakehouse_app_demo,
  enabled: true,
  iam_base: System.get_env("LAKEHOUSE_IAM_BASE") || "http://127.0.0.1:#{test_port}"

config :lakehouse_app_demo, LakehouseAppDemo.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: demo_port],
  url: [host: "127.0.0.1", port: demo_port, scheme: "http"],
  secret_key_base: "demodemo_demodemo_demodemo_demodemo_demodemo_demodemo_demodemo_demodemo",
  server: true,
  check_origin: false

config :wallaby,
  otp_app: :lakehouse_web,
  base_url: "http://127.0.0.1:#{test_port}",
  driver: Wallaby.Chrome,
  chrome: [headless: true]
