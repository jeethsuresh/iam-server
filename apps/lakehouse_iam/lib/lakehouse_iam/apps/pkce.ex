defmodule LakehouseIam.Apps.Pkce do
  @moduledoc """
  PKCE S256 helpers (RFC 7636).
  """

  @doc "Generate a high-entropy code_verifier (43–128 chars, unreserved)."
  def generate_verifier do
    :crypto.strong_rand_bytes(32)
    |> Base.url_encode64(padding: false)
  end

  @doc "S256 code_challenge = BASE64URL(SHA256(verifier))."
  def challenge(verifier) when is_binary(verifier) do
    :crypto.hash(:sha256, verifier)
    |> Base.url_encode64(padding: false)
  end

  @spec verify(String.t(), String.t(), String.t()) :: :ok | {:error, String.t()}
  def verify(verifier, challenge, method \\ "S256")

  def verify(verifier, challenge, "S256")
      when is_binary(verifier) and is_binary(challenge) do
    if challenge(verifier) == challenge do
      :ok
    else
      {:error, "invalid_code_verifier"}
    end
  end

  def verify(_, _, method), do: {:error, "unsupported_challenge_method:#{method}"}
end
