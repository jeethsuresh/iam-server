defmodule LakehouseIam.ProductionConfigTest do
  use ExUnit.Case, async: false

  @root Path.expand("../../../..", __DIR__)
  @values %{
    "DATABASE_URL" => "ecto://postgres:postgres@postgres/lakehouse_dev",
    "SECRET_KEY_BASE" => String.duplicate("s", 64),
    "JWT_SECRET" => String.duplicate("j", 48),
    "IAM_ADMIN_PASSWORD" => "a-fresh-admin-password-for-tests",
    "IAM_REGISTRATION_KEY" => "test-invitation-key",
    "PHX_HOST" => "iam.jeeth.dev",
    "IAM_PUBLIC_URL" => "https://iam.jeeth.dev",
    "IAM_DOMAIN" => "jeeth.dev",
    "IAM_SSO_COOKIE_DOMAIN" => "jeeth.dev",
    "IAM_RELAXED_CALLBACK_URLS" => "false"
  }

  setup do
    old = Map.new(@values, fn {key, _} -> {key, System.get_env(key)} end)
    System.put_env(@values)

    on_exit(fn ->
      for {key, value} <- old do
        if value, do: System.put_env(key, value), else: System.delete_env(key)
      end
    end)

    :ok
  end

  defp runtime, do: Config.Reader.read!(Path.join(@root, "config/runtime.exs"), env: :prod)

  test "production uses secure sessions and the expected HTTPS websocket origin" do
    prod = Config.Reader.read!(Path.join(@root, "config/prod.exs"), env: :prod)
    assert prod[:lakehouse_web][:session_options][:secure]
    assert prod[:lakehouse_web][:session_options][:http_only]
    endpoint = prod[:lakehouse_web][LakehouseWeb.Endpoint]
    refute endpoint[:debug_errors]
    refute endpoint[:code_reloader]

    assert runtime()[:lakehouse_web][LakehouseWeb.Endpoint][:check_origin] == [
             "https://iam.jeeth.dev"
           ]
  end

  test "false callback flags do not enable relaxed validation" do
    for value <- ["false", "0", ""] do
      System.put_env("IAM_RELAXED_CALLBACK_URLS", value)
      refute runtime()[:lakehouse_iam][:relaxed_callback_urls]
    end
  end

  test "default and missing production secrets fail closed" do
    System.put_env("JWT_SECRET", "docker-dev-jwt-secret-change-me-in-production")
    assert_raise RuntimeError, ~r/JWT_SECRET must be/, &runtime/0
    System.put_env("JWT_SECRET", @values["JWT_SECRET"])
    System.put_env("IAM_ADMIN_PASSWORD", "changeme")
    assert_raise RuntimeError, ~r/IAM_ADMIN_PASSWORD must be/, &runtime/0
    System.put_env("IAM_ADMIN_PASSWORD", @values["IAM_ADMIN_PASSWORD"])
    System.delete_env("SECRET_KEY_BASE")
    assert_raise System.EnvError, &runtime/0
  end

  test "placeholder public hostname is rejected" do
    System.put_env("PHX_HOST", "example.com")
    assert_raise RuntimeError, ~r/PHX_HOST/, &runtime/0
  end

  test "identity domain is separate from the public host and production database TLS is verified" do
    config = runtime()
    assert config[:lakehouse_iam][:identity_domain] == "jeeth.dev"
    assert config[:lakehouse_iam][:public_url] == "https://iam.jeeth.dev"
    assert config[:lakehouse_iam][LakehouseIam.Repo][:ssl][:verify] == :verify_peer
    refute config[:lakehouse_iam][:bootstrap_on_start]
    assert config[:lakehouse_iam][:registration_key] == "test-invitation-key"
  end

  test "production requires a nonempty registration key" do
    System.put_env("IAM_REGISTRATION_KEY", "")
    assert_raise RuntimeError, ~r/IAM_REGISTRATION_KEY must be/, &runtime/0
    System.delete_env("IAM_REGISTRATION_KEY")
    assert_raise System.EnvError, &runtime/0
  end

  test "refresh cookies are secure and a shared hint is scoped to the configured parent" do
    prod = Config.Reader.read!(Path.join(@root, "config/prod.exs"), env: :prod)
    assert prod[:lakehouse_web][:secure_auth_cookies]
    assert runtime()[:lakehouse_web][:sso_cookie_domain] == "jeeth.dev"

    for domain <- ["evil.example", ".jeeth.dev", "*.jeeth.dev", "https://jeeth.dev", "dev"] do
      System.put_env("IAM_SSO_COOKIE_DOMAIN", domain)
      assert_raise RuntimeError, ~r/IAM_SSO_COOKIE_DOMAIN/, &runtime/0
    end
  end

  test "an existing Matrix namespace can be retained when moving its database" do
    previous = System.get_env("MATRIX_DOMAIN")

    on_exit(fn ->
      if previous,
        do: System.put_env("MATRIX_DOMAIN", previous),
        else: System.delete_env("MATRIX_DOMAIN")
    end)

    System.put_env("MATRIX_DOMAIN", "legacy.example")
    config = runtime()
    assert config[:lakehouse_iam][:identity_domain] == "jeeth.dev"
    assert config[:lakehouse_matrix][:homeserver_domain] == "legacy.example"
  end

  test "Matrix runtime flags require an explicit signing identity and reject ambiguous booleans" do
    keys =
      ~w(MATRIX_NATIVE_EVENT_GRAPH MATRIX_FEDERATION_ENABLED MATRIX_SIGNING_KEY MATRIX_SIGNING_KEY_ID)

    old = Map.new(keys, &{&1, System.get_env(&1)})

    on_exit(fn ->
      for {key, value} <- old do
        if value, do: System.put_env(key, value), else: System.delete_env(key)
      end
    end)

    System.put_env("MATRIX_NATIVE_EVENT_GRAPH", "true")
    System.put_env("MATRIX_FEDERATION_ENABLED", "true")
    System.delete_env("MATRIX_SIGNING_KEY")
    System.delete_env("MATRIX_SIGNING_KEY_ID")
    assert_raise RuntimeError, ~r/require MATRIX_SIGNING_KEY/, &runtime/0
    System.put_env("MATRIX_SIGNING_KEY", Base.encode64(<<0::256>>, padding: false))
    config = runtime()[:lakehouse_matrix]
    assert config[:native_event_graph] and config[:federation_enabled]
    System.put_env("MATRIX_SIGNING_KEY_ID", "ed25519:invalid-key-id")
    assert_raise RuntimeError, ~r/MATRIX_SIGNING_KEY_ID/, &runtime/0
    System.delete_env("MATRIX_SIGNING_KEY_ID")
    System.put_env("MATRIX_NATIVE_EVENT_GRAPH", "false")
    assert_raise RuntimeError, ~r/requires MATRIX_NATIVE_EVENT_GRAPH/, &runtime/0
    System.put_env("MATRIX_FEDERATION_ENABLED", "1")
    assert_raise RuntimeError, ~r/must be true or false/, &runtime/0
  end

  test "compose default secret placeholders cannot boot production" do
    System.put_env(%{
      "DATABASE_URL" => "ecto://postgres:postgres@postgres/lakehouse_dev",
      "SECRET_KEY_BASE" =>
        "dEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKERdEVDOCKER",
      "JWT_SECRET" => "docker-dev-jwt-secret-change-me-in-production",
      "IAM_ADMIN_PASSWORD" => "changeme",
      "PHX_HOST" => "iam.jeeth.dev"
    })

    assert_raise RuntimeError, ~r/SECRET_KEY_BASE must be/, &runtime/0
  end
end
