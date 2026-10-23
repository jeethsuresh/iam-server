defmodule LakehouseMatrix.IdentityDomainTest do
  use ExUnit.Case, async: false

  test "qualified Matrix user IDs retain the domain boundary" do
    domain = LakehouseMatrix.Identity.homeserver_domain()
    assert LakehouseMatrix.Identity.parse_user_id("@alice:#{domain}") == {:ok, "alice"}
    assert LakehouseMatrix.Identity.parse_user_id("@alice:foreign.example") == :error
  end
end
