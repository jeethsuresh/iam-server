defmodule LakehouseIam.Apps.PkceTest do
  use ExUnit.Case, async: true

  alias LakehouseIam.Apps.Pkce

  test "challenge verifies matching verifier" do
    v = Pkce.generate_verifier()
    c = Pkce.challenge(v)
    assert :ok = Pkce.verify(v, c, "S256")
  end

  test "challenge rejects wrong verifier" do
    c = Pkce.challenge(Pkce.generate_verifier())
    assert {:error, "invalid_code_verifier"} = Pkce.verify("wrong-verifier-value-xxxx", c, "S256")
  end
end
