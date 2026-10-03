defmodule LakehouseIam.ProductionConfigTest do
  use ExUnit.Case, async: false

  @root Path.expand("../../../..", __DIR__)
  @values %{
    "DATABASE_URL" => "ecto://postgres:postgres@postgres/lakehouse_dev",
    "SECRET_KEY_BASE" => String.duplicate("s", 64),
    "JWT_SECRET" => String.duplicate("j", 48),
    "IAM_ADMIN_PASSWORD" => "a-fresh-admin-password-for-tests",
    "PHX_HOST" => "iam.jeeth.dev",
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
    assert runtime()[:lakehouse_web][LakehouseWeb.Endpoint][:check_origin] == ["https://iam.jeeth.dev"]
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
