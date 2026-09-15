import Config

pg_host = System.get_env("POSTGRES_HOST", "localhost")

pg_user = System.get_env("POSTGRES_USER", "postgres")
pg_pass = System.get_env("POSTGRES_PASSWORD", "postgres")
pg_db = System.get_env("POSTGRES_DB", "lakehouse_dev")

config :lakehouse_iam, LakehouseIam.Repo,
  username: pg_user,
  password: pg_pass,
  hostname: pg_host,
  database: pg_db,
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

phx_ip =
  case System.get_env("PHX_LISTEN_ADDRESS", "127.0.0.1") do
    "0.0.0.0" -> {0, 0, 0, 0}
    _ -> {127, 0, 0, 1}
  end

phx_port = String.to_integer(System.get_env("PORT") || "4000")

config :lakehouse_web, LakehouseWeb.Endpoint,
  http: [ip: phx_ip, port: phx_port],
  check_origin: false,
  code_reloader: true,
  debug_errors: true,
  secret_key_base:
    System.get_env("SECRET_KEY_BASE") ||
      "dEVONLYdEVONLYdEVONLYdEVONLYdEVONLYdEVONLYdEVONLYdEVONLYdEVONLYdEVONLY",
  watchers: []

config :logger, level: :debug

# Test-only style local demo: enable with LAKEHOUSE_DEMO=1 (not used by deploy.sh)
if System.get_env("LAKEHOUSE_DEMO") not in [nil, ""] do
  demo_port = String.to_integer(System.get_env("DEMO_PORT") || "4100")
  # Browser-facing origin (caller/redirect URLs). Inside Docker the IAM base may be
  # 127.0.0.1:4000 on the same container while public URLs stay on the host port.
  demo_public_host = System.get_env("DEMO_PUBLIC_HOST") || "127.0.0.1"

  config :lakehouse_app_demo,
    enabled: true,
    iam_base: System.get_env("LAKEHOUSE_IAM_BASE") || "http://127.0.0.1:#{phx_port}"

  config :lakehouse_app_demo, LakehouseAppDemo.Endpoint,
    http: [ip: phx_ip, port: demo_port],
    url: [host: demo_public_host, port: demo_port, scheme: "http"],
    secret_key_base:
      "dEVONLYdEVONLYdEVONLYdEVONLYdEVONLYdEVONLYdEVONLYdEVONLYdEVONLYdEVONLY",
    server: true,
    check_origin: false
end
