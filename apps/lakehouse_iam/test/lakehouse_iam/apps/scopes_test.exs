defmodule LakehouseIam.Apps.ScopesTest do
  use ExUnit.Case, async: true
  alias LakehouseIam.Apps.Scopes

  test "profile permissions are separately requestable and never implied" do
    assert {:ok, ["profile.name"]} = Scopes.parse("profile.name")
    assert {:ok, ["profile.username", "profile.picture"]} = Scopes.parse("profile.username profile.picture")
    refute Scopes.covers?(["profile.name"], ["profile.username"])
    refute Scopes.covers?(["profile.name"], ["profile.picture"])
    assert {:error, _} = Scopes.parse("profile.everything")
  end
end
