import Config

if config_env() == :prod do
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      """

  maybe_ipv6 = if System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []

  config :lakehouse_iam, LakehouseIam.Repo,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    socket_options: maybe_ipv6

  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      """

  host = System.get_env("PHX_HOST") || "example.com"
  port = String.to_integer(System.get_env("PORT") || "4000")

  config :lakehouse_web, LakehouseWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      ip: {0, 0, 0, 0},
      port: port
    ],
    secret_key_base: secret_key_base

  config :lakehouse_iam,
    jwt_secret: System.fetch_env!("JWT_SECRET"),
    admin_username: System.get_env("IAM_ADMIN_USERNAME", "admin"),
    admin_password: System.get_env("IAM_ADMIN_PASSWORD", ""),
    relaxed_callback_urls: System.get_env("IAM_RELAXED_CALLBACK_URLS") not in [nil, ""]
end

if media_root = System.get_env("LAKEHOUSE_MEDIA_ROOT") do
  config :lakehouse_matrix, :media_root, media_root
end
