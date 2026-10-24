import Config

if config_env() == :prod do
  public_url =
    (System.get_env("IAM_PUBLIC_URL") || "https://" <> System.fetch_env!("PHX_HOST"))
    |> String.trim_trailing("/")

  public_uri = URI.parse(public_url)
  identity_domain = (System.get_env("IAM_DOMAIN") || public_uri.host || "") |> String.downcase()

  unless public_uri.scheme == "https" and is_binary(public_uri.host) and
           public_uri.path in [nil, ""] and is_nil(public_uri.query) and
           is_nil(public_uri.fragment) and is_nil(public_uri.userinfo) do
    raise "IAM_PUBLIC_URL must be an HTTPS origin"
  end

  unless Regex.match?(~r/\A[a-z0-9]+(?:[.-][a-z0-9]+)*\z/, identity_domain) do
    raise "IAM_DOMAIN must be a DNS name"
  end

  cookie_domain =
    (System.get_env("IAM_SSO_COOKIE_DOMAIN") || identity_domain) |> String.downcase()

  unless String.contains?(cookie_domain, ".") and
           Regex.match?(~r/\A[a-z0-9]+(?:[.-][a-z0-9]+)*\z/, cookie_domain) and
           (public_uri.host == cookie_domain or
              String.ends_with?(public_uri.host, "." <> cookie_domain)) do
    raise "IAM_SSO_COOKIE_DOMAIN must be the IAM hostname or its parent DNS domain"
  end

  config :lakehouse_web, :sso_cookie_domain, cookie_domain

  database_url = System.fetch_env!("DATABASE_URL")

  db_ssl =
    if System.get_env("DATABASE_SSL") == "disable",
      do: false,
      else: [
        verify: :verify_peer,
        cacertfile: System.get_env("DATABASE_CA_FILE", "/etc/ssl/certs/ca-certificates.crt"),
        server_name_indication: String.to_charlist(URI.parse(database_url).host),
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
      ]

  config :lakehouse_iam, LakehouseIam.Repo,
    url: database_url,
    ssl: db_ssl,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    socket_options: if(System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: [])

  require_secret = fn name, minimum ->
    value = System.fetch_env!(name)

    if byte_size(value) < minimum or
         value in [
           "docker-dev-jwt-secret-change-me-in-production",
           "dEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKER"
         ],
       do: raise("#{name} must be a fresh production secret (at least #{minimum} bytes)")

    value
  end

  secret_key_base = require_secret.("SECRET_KEY_BASE", 64)
  jwt_secret = require_secret.("JWT_SECRET", 32)
  admin_password = require_secret.("IAM_ADMIN_PASSWORD", 12)
  registration_key = require_secret.("IAM_REGISTRATION_KEY", 1)
  broker_origin = System.get_env("IAM_NATIVE_BROKER_ORIGIN")

  if broker_origin do
    broker_uri = URI.parse(broker_origin)

    unless broker_uri.scheme == "https" and is_binary(broker_uri.host) and
             broker_uri.path in [nil, ""] and is_nil(broker_uri.query) and
             is_nil(broker_uri.fragment) and is_nil(broker_uri.userinfo) and
             broker_uri.port == 443 and broker_origin == "https://" <> broker_uri.host and
             String.downcase(broker_origin) == broker_origin do
      raise "IAM_NATIVE_BROKER_ORIGIN must be a canonical HTTPS origin"
    end
  end
  host = System.get_env("PHX_HOST") || public_uri.host

  if host == "" or host == "example.com" or host != public_uri.host,
    do: raise("PHX_HOST must match the public IAM hostname")

  config :lakehouse_web, LakehouseWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    check_origin: ["https://#{host}"],
    http: [ip: {0, 0, 0, 0}, port: String.to_integer(System.get_env("PORT") || "4000")],
    server: true,
    secret_key_base: secret_key_base

  config :lakehouse_iam,
    identity_domain: identity_domain,
    public_url: public_url,
    jwt_secret: jwt_secret,
    admin_username: System.get_env("IAM_ADMIN_USERNAME", "admin"),
    admin_password: admin_password,
    registration_key: registration_key,
    native_broker_origin: broker_origin,
    relaxed_callback_urls: false,
    bootstrap_on_start: false

  # Existing Matrix event IDs embed the original domain. Preserve it explicitly
  # when moving an existing database; IAM discovery can use its own domain.
  config :lakehouse_matrix, :homeserver_domain, System.get_env("MATRIX_DOMAIN") || identity_domain

  if endpoint = System.get_env("S3_ENDPOINT") || System.get_env("R2_ENDPOINT") do
    unless String.starts_with?(endpoint, "https://"), do: raise("S3_ENDPOINT must use HTTPS")

    config :lakehouse_matrix,
      media_store: LakehouseMatrix.Media.Store.S3,
      s3: [
        endpoint: endpoint,
        bucket: System.get_env("S3_BUCKET") || System.fetch_env!("R2_BUCKET"),
        region: System.get_env("S3_REGION", "auto"),
        access_key_id:
          System.get_env("S3_ACCESS_KEY_ID") || System.fetch_env!("R2_ACCESS_KEY_ID"),
        secret_access_key:
          System.get_env("S3_SECRET_ACCESS_KEY") || System.fetch_env!("R2_SECRET_ACCESS_KEY")
      ]
  else
    if System.get_env("IAM_EPHEMERAL_DISK") == "true" do
      config :lakehouse_matrix, :media_store, LakehouseMatrix.Media.Store.Unavailable
    end
  end
end

if media_root = System.get_env("LAKEHOUSE_MEDIA_ROOT") do
  config :lakehouse_matrix, :media_root, media_root
end

if rtc_url = System.get_env("MATRIX_RTC_URL") do
  uri = URI.parse(rtc_url)
  unless uri.scheme == "wss" and is_binary(uri.host) and is_nil(uri.userinfo), do: raise("MATRIX_RTC_URL must be a trusted WSS URL")
  config :lakehouse_matrix, :rtc_url, rtc_url
end

# Persistent, dedicated Ed25519 seed; never reuse the IAM JWT signing secret.
if matrix_key = System.get_env("MATRIX_SIGNING_KEY") do
  case Base.decode64(String.trim_trailing(matrix_key, "="), padding: false) do
    {:ok, seed} when byte_size(seed) == 32 -> :ok
    _ -> raise "MATRIX_SIGNING_KEY must encode a 32-byte Ed25519 seed"
  end
  config :lakehouse_matrix, signing_key: String.trim_trailing(matrix_key, "="),
    signing_key_id: System.get_env("MATRIX_SIGNING_KEY_ID", "ed25519:gravitas1")
end
