defmodule LakehouseIam.RegistrationTest do
  use ExUnit.Case, async: false
  alias LakehouseIam.Registration

  setup do
    previous = Application.get_env(:lakehouse_iam, :registration_key)
    Application.put_env(:lakehouse_iam, :registration_key, "test-invitation-key")
    on_exit(fn -> Application.put_env(:lakehouse_iam, :registration_key, previous) end)
  end

  test "requires the exact key and rejects missing or malformed values" do
    assert :ok = Registration.authorize("test-invitation-key")

    for key <- [nil, "", "wrong", "TEST-INVITATION-KEY", "test-invitation-key ", 1, []] do
      assert {:error, "A valid registration key is required."} = Registration.authorize(key)
    end
  end

  test "an unconfigured key closes public registration" do
    for key <- [nil, ""] do
      Application.put_env(:lakehouse_iam, :registration_key, key)
      assert {:error, _} = Registration.authorize("test-invitation-key")
      assert {:error, _} = Registration.authorize("")
    end
  end
end
