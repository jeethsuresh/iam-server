import Config

config :lakehouse_web, :secure_auth_cookies, true

config :lakehouse_web, LakehouseWeb.Endpoint,
  server: true,
  code_reloader: false,
  debug_errors: false,
  force_ssl: [rewrite_on: [:x_forwarded_proto], exclude: ["localhost", "127.0.0.1"]]

config :lakehouse_web, :session_options,
  store: :cookie,
  key: "__Host-lakehouse",
  signing_salt: "lakehouse sess sign",
  same_site: "Lax",
  secure: true,
  http_only: true

config :logger, level: :info
