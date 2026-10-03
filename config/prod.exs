import Config

config :lakehouse_web, LakehouseWeb.Endpoint,
  code_reloader: false,
  debug_errors: false,
  force_ssl: [rewrite_on: [:x_forwarded_proto]]

config :lakehouse_web, :session_options,
  store: :cookie,
  key: "_lakehouse_web_key",
  signing_salt: "lakehouse sess sign",
  same_site: "Lax",
  secure: true,
  http_only: true

config :logger, level: :info
