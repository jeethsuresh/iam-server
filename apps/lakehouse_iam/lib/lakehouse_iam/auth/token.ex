defmodule LakehouseIam.Auth.Token do
  @moduledoc """
  HS256 session JWT for `/profile`-style auth (iam-server compatible claims).
  """
  @behaviour LakehouseIam.Auth.TokenBehaviour

  @impl true
  def issue(username) when is_binary(username) do
    exp = System.system_time(:second) + token_ttl()
    claims = %{"username" => username, "exp" => exp}
    jwk = hs256_jwk()

    jwt = JOSE.JWT.from(claims)

    JOSE.JWT.sign(jwk, %{"alg" => "HS256", "typ" => "JWT"}, jwt)
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  @impl true
  def verify(compact) when is_binary(compact) do
    jwk = hs256_jwk()

    case JOSE.JWT.verify_strict(jwk, ["HS256"], compact) do
      {true, %JOSE.JWT{fields: fields}, _jws} ->
        {:ok, fields}

      {false, _, _} ->
        :error
    end
  end

  defp hs256_jwk do
    secret = Application.fetch_env!(:lakehouse_iam, :jwt_secret)
    # Derive a 256-bit oct key from arbitrary configured secret (production should still use a strong secret).
    JOSE.JWK.from_oct(:crypto.hash(:sha256, secret))
  end

  defp token_ttl, do: Application.fetch_env!(:lakehouse_iam, :token_ttl_seconds)
end
