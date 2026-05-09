defmodule LakehouseIam.Auth.CallbackURLTest do
  use ExUnit.Case

  alias LakehouseIam.Auth.CallbackURL

  setup do
    prev = Application.get_env(:lakehouse_iam, :relaxed_callback_urls)
    Application.put_env(:lakehouse_iam, :relaxed_callback_urls, true)

    on_exit(fn ->
      Application.put_env(:lakehouse_iam, :relaxed_callback_urls, prev)
    end)

    :ok
  end

  test "always rejects 169.254.x.x even when relaxed" do
    assert {:error, msg} = CallbackURL.validate("http://169.254.169.254/latest/meta-data", "tokenURL")
    assert msg =~ "169.254"
  end

  test "rejects non-http schemes" do
    assert {:error, _} = CallbackURL.validate("javascript:alert(1)", "redirectURL")
  end
end
