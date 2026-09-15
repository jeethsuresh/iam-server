defmodule LakehouseAppDemo.OAuthClient do
  @moduledoc "PKCE client helpers for talking to Lakehouse."

  alias LakehouseAppDemo.Pkce

  def parse_username_at_host(input) when is_binary(input) do
    case String.split(input, "@", parts: 2) do
      [local, host] when local != "" and host != "" ->
        base =
          cond do
            String.starts_with?(host, "http://") or String.starts_with?(host, "https://") ->
              String.trim_trailing(host, "/")

            true ->
              "http://#{host}"
          end

        {:ok, String.downcase(local), base}

      _ ->
        {:error, "use username@host form"}
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

    url = String.trim_trailing(iam_base, "/") <> "/backend/register"

    case Req.post(url, json: body, receive_timeout: 10_000) do
      {:ok, %{status: 200, body: %{"sessionID" => sid}}} ->
        authorize =
          String.trim_trailing(iam_base, "/") <>
            "/oauth/authorize?sessionID=" <> URI.encode_www_form(sid)

        {:ok, %{authorize_url: authorize, verifier: verifier, state: state, session_id: sid}}

      {:ok, %{status: status, body: body}} ->
        {:error, "register failed #{status}: #{inspect(body)}"}

      {:error, err} ->
        {:error, inspect(err)}
    end
  end

  def exchange_token(iam_base, code, verifier, redirect_uri) do
    url = String.trim_trailing(iam_base, "/") <> "/oauth/token"

    case Req.post(url,
           form: %{
             grant_type: "authorization_code",
             code: code,
             code_verifier: verifier,
             redirect_uri: redirect_uri
           },
           receive_timeout: 10_000
         ) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      {:ok, %{status: s, body: b}} -> {:error, "token #{s}: #{inspect(b)}"}
      {:error, err} -> {:error, inspect(err)}
    end
  end

  def api_get(iam_base, path, access_token) do
    url = String.trim_trailing(iam_base, "/") <> path

    case Req.get(url,
           headers: [{"authorization", "Bearer #{access_token}"}],
           receive_timeout: 10_000
         ) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      {:ok, %{status: s, body: b}} -> {:error, "#{s}: #{inspect(b)}"}
      {:error, err} -> {:error, inspect(err)}
    end
  end

  def api_post(iam_base, path, access_token, json_body) do
    url = String.trim_trailing(iam_base, "/") <> path

    case Req.post(url,
           json: json_body,
           headers: [{"authorization", "Bearer #{access_token}"}],
           receive_timeout: 10_000
         ) do
      {:ok, %{status: status, body: body}} when status in 200..299 -> {:ok, body}
      {:ok, %{status: s, body: b}} -> {:error, "#{s}: #{inspect(b)}"}
      {:error, err} -> {:error, inspect(err)}
    end
  end
end
