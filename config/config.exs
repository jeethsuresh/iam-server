import Config

config :lakehouse_iam, LakehouseIam.Repo,
  migration_primary_key: [name: :id, type: :binary_id],
  migration_foreign_key: [column: :id, type: :binary_id]

config :lakehouse_iam, ecto_repos: [LakehouseIam.Repo]

config :lakehouse_iam,
  jwt_secret: System.get_env("JWT_SECRET", "dev-only-change-me-use-long-secret"),
  token_ttl_seconds: 3600,
  admin_username: System.get_env("IAM_ADMIN_USERNAME", "admin"),
  admin_password: System.get_env("IAM_ADMIN_PASSWORD", ""),
  relaxed_callback_urls: System.get_env("IAM_RELAXED_CALLBACK_URLS") not in [nil, ""]

config :lakehouse_web, :session_options,
  store: :cookie,
  key: "_lakehouse_web_key",
  signing_salt: "lakehouse sess sign",
  same_site: "Lax"

config :lakehouse_web, LakehouseWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  live_view: [signing_salt: "lakehouse_lv_sign"],
  render_errors: [
    formats: [html: LakehouseWeb.ErrorHTML, json: LakehouseWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: LakehouseWeb.PubSub

config :lakehouse_web, LakehouseWeb.Presence, otp_app: :lakehouse_web

config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

config :phoenix, :json_library, Jason

config :lakehouse_matrix, :pubsub, LakehouseWeb.PubSub

config :lakehouse_matrix, :homeserver_domain, "localhost"

config :lakehouse_matrix,
  media_store: LakehouseMatrix.Media.Store.Local,
  media_root: System.get_env("LAKEHOUSE_MEDIA_ROOT") || "tmp/media"

config :lakehouse_app_demo,
  enabled: false,
  iam_base: System.get_env("LAKEHOUSE_IAM_BASE")

config :lakehouse_app_demo, LakehouseAppDemo.Endpoint,
  url: [host: "127.0.0.1"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [formats: [html: LakehouseAppDemo.ErrorHTML], layout: false],
  pubsub_server: nil

import_config "#{config_env()}.exs"
