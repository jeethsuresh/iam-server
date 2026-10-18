defmodule LakehouseAppDemo.OAuthClient do
  @moduledoc "PKCE client helpers for talking to Lakehouse."

  alias LakehouseAppDemo.Pkce

  def parse_username_at_host(input) when is_binary(input) do
    with {:ok, identity} <- LakehouseIam.Identifier.parse(input) do
      {:ok, identity.user_id, "https://" <> identity.domain}
    end
  end

  def start_login(iam_base, username, caller_url, redirect_url, scope) do
    verifier = Pkce.generate_verifier()
    challenge = Pkce.challenge(verifier)
    state = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)

    body = %{
      username: username,
      callerURL: caller_url,
      redirectURL: redirect_url,
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
      scope: scope,
      state: state
    }

    url = endpoint(iam_base, "backend_registration_endpoint", "/backend/register")

    case Req.post(url, json: body, redirect: false, receive_timeout: 10_000) do
      {:ok, %{status: 200, body: %{"sessionID" => sid}}} ->
        authorize =
          endpoint(iam_base, "authorization_endpoint", "/oauth/authorize") <>
            "?sessionID=" <> URI.encode_www_form(sid)

        {:ok, %{authorize_url: authorize, verifier: verifier, state: state, session_id: sid}}

      {:ok, %{status: status, body: body}} ->
        {:error, "register failed #{status}: #{inspect(body)}"}

      {:error, err} ->
        {:error, inspect(err)}
    end
  end

  def exchange_token(iam_base, code, verifier, redirect_uri) do
    url = endpoint(iam_base, "token_endpoint", "/oauth/token")

    case Req.post(url,
           form: %{
             grant_type: "authorization_code",
             code: code,
             code_verifier: verifier,
             redirect_uri: redirect_uri
           },
           redirect: false,
           receive_timeout: 10_000
         ) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      {:ok, %{status: s, body: b}} -> {:error, "token #{s}: #{inspect(b)}"}
      {:error, err} -> {:error, inspect(err)}
    end
  end

  def api_get(iam_base, path, access_token) do
    url = base(iam_base) <> path

    case Req.get(url,
           headers: [{"authorization", "Bearer #{access_token}"}],
           redirect: false,
           receive_timeout: 10_000
         ) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      {:ok, %{status: s, body: b}} -> {:error, "#{s}: #{inspect(b)}"}
      {:error, err} -> {:error, inspect(err)}
    end
  end

  def api_post(iam_base, path, access_token, json_body) do
    url = base(iam_base) <> path

    case Req.post(url,
           json: json_body,
           headers: [{"authorization", "Bearer #{access_token}"}],
           redirect: false,
           receive_timeout: 10_000
         ) do
      {:ok, %{status: status, body: body}} when status in 200..299 -> {:ok, body}
      {:ok, %{status: s, body: b}} -> {:error, "#{s}: #{inspect(b)}"}
      {:error, err} -> {:error, inspect(err)}
    end
  end

  defp base(%{"issuer" => issuer}), do: issuer
  defp base(base) when is_binary(base), do: String.trim_trailing(base, "/")
  defp endpoint(config, key, _path) when is_map(config), do: Map.fetch!(config, key)
  defp endpoint(base, _key, path), do: base(base) <> path
end
