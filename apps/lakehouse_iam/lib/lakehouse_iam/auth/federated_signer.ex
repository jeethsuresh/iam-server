defmodule LakehouseIam.Auth.FederatedSigner do
  @moduledoc """
  ES256 JWT minted for the application's `tokenURL` callback (iam-server compatible).
  """

  def sign(private_jwk, username, session_id) do
    exp = System.system_time(:second) + Application.fetch_env!(:lakehouse_iam, :token_ttl_seconds)

    claims = %{
      "username" => username,
      "sessionID" => session_id,
      "exp" => exp
    }

    jwt = JOSE.JWT.from(claims)

    JOSE.JWT.sign(private_jwk, %{"alg" => "ES256", "typ" => "JWT"}, jwt)
    |> JOSE.JWS.compact()
    |> elem(1)
  end
end
