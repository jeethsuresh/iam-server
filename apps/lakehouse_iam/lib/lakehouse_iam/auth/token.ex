defmodule LakehouseIam.Auth.Token do
  @moduledoc """
  HS256 session JWT for `/profile`-style auth (iam-server compatible claims).
  """
  @behaviour LakehouseIam.Auth.TokenBehaviour

  @impl true
  def issue(username), do: issue(username, [])

  def issue(username, opts) when is_binary(username) do
    exp = System.system_time(:second) + Keyword.get(opts, :expires_in, token_ttl())
    claims = %{"username" => username, "exp" => exp}

    claims =
      case Keyword.get(opts, :session_id) do
        nil ->
          claims

        id ->
          Map.merge(claims, %{"sid" => id, "rfe" => Keyword.fetch!(opts, :session_expires_at)})
      end

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
        if is_integer(fields["exp"]) and fields["exp"] > System.system_time(:second) and
             is_binary(fields["username"]) and active_session?(fields) do
          {:ok, fields}
        else
          :error
        end

      {false, _, _} ->
        :error
    end
  rescue
    _ -> :error
  end

  def verify(_), do: :error

  defp active_session?(%{"sid" => id, "username" => username}),
    do: LakehouseIam.Auth.Sessions.active?(id, username)

  defp active_session?(_), do: true

  defp hs256_jwk do
    secret = Application.fetch_env!(:lakehouse_iam, :jwt_secret)

    # Derive a 256-bit oct key from arbitrary configured secret (production should still use a strong secret).
    JOSE.JWK.from_oct(:crypto.hash(:sha256, secret))
  end

  defp token_ttl, do: Application.fetch_env!(:lakehouse_iam, :token_ttl_seconds)
end
