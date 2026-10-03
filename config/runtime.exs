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

  require_secret = fn name, minimum ->
    value = System.fetch_env!(name)
    if byte_size(value) < minimum or
         value in ["docker-dev-jwt-secret-change-me-in-production",
                   "dEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKER"] do
      raise "#{name} must be a fresh production secret (at least #{minimum} bytes)"
    end
    value
  end

  secret_key_base = require_secret.("SECRET_KEY_BASE", 64)
  jwt_secret = require_secret.("JWT_SECRET", 32)
  admin_password = require_secret.("IAM_ADMIN_PASSWORD", 12)

  host = System.fetch_env!("PHX_HOST")
  if host == "" or host == "example.com", do: raise("PHX_HOST must be the public hostname")
  port = String.to_integer(System.get_env("PORT") || "4000")

  config :lakehouse_web, LakehouseWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    check_origin: ["https://#{host}"],
    http: [
      ip: {0, 0, 0, 0},
      port: port
    ],
    secret_key_base: secret_key_base

  config :lakehouse_iam,
    jwt_secret: jwt_secret,
    admin_username: System.get_env("IAM_ADMIN_USERNAME", "admin"),
    admin_password: admin_password,
    relaxed_callback_urls: System.get_env("IAM_RELAXED_CALLBACK_URLS") in ~w(true 1)
end

if media_root = System.get_env("LAKEHOUSE_MEDIA_ROOT") do
  config :lakehouse_matrix, :media_root, media_root
end
