defmodule LakehouseIam.SessionTokenTest do
  use ExUnit.Case, async: false
  alias LakehouseIam.Auth.Token

  test "valid sessions verify; expired or malformed sessions fail closed" do
    assert {:ok, %{"username" => "alice"}} = Token.issue("alice") |> Token.verify()
    secret = Application.fetch_env!(:lakehouse_iam, :jwt_secret)
    key = JOSE.JWK.from_oct(:crypto.hash(:sha256, secret))

    for expiry <- [System.system_time(:second) - 1, nil, "tomorrow"] do
      {_, expired} =
        JOSE.JWT.sign(key, %{"alg" => "HS256"}, %{"username" => "alice", "exp" => expiry})
        |> JOSE.JWS.compact()

      assert :error = Token.verify(expired)
    end

    assert :error = Token.verify("broken-token")
  end
end
