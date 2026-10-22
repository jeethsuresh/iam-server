defmodule LakehouseIam.Auth.OAuth do
  @moduledoc """
  Authorization-code + PKCE completion helpers for federated apps.
  """
  alias LakehouseIam.Apps.{Grants, Tokens}
  alias LakehouseIam.Federated

  @doc """
  After login+consent: mint auth code and build redirect URL.
  """
  def issue_code_redirect(session, principal_id, room_mode, room_ids, opts \\ []) do
    case Grants.upsert(principal_id, session.app_origin, session.scopes, room_mode, room_ids) do
      {:ok, grant} ->
        code =
          :crypto.strong_rand_bytes(32)
          |> Base.url_encode64(padding: false)

        :ok =
          Federated.put_code(code, %{
            grant_id: grant.id,
            session_id: Keyword.get(opts, :session_id),
            redirect_url: session.redirect_url,
            app_origin: session.app_origin,
            scopes: session.scopes,
            code_challenge: session.code_challenge,
            code_challenge_method: session.code_challenge_method,
            state: session.state
          })

        uri = URI.parse(session.redirect_url)

        q =
          URI.decode_query(uri.query || "")
          |> Map.delete("error")
          |> Map.delete("error_description")

        q = Map.put(q, "code", code)
        q = if session.state, do: Map.put(q, "state", session.state), else: q
        redirect = %URI{uri | query: URI.encode_query(q)} |> URI.to_string()
        {:ok, redirect}

      {:error, _} = err ->
        err
    end
  end

  def exchange_code(code, verifier, redirect_uri) do
    with payload when not is_nil(payload) <- Federated.take_code(code),
         :ok <- Federated.verify_pkce(payload, verifier),
         :ok <- match_redirect(payload.redirect_url, redirect_uri),
         grant when not is_nil(grant) <-
           LakehouseIam.Repo.get(LakehouseIam.Schema.AppGrant, payload.grant_id),
         scopes <- payload.scopes || Enum.reject(grant.scopes, &(&1 == "native.broker")),
         {:ok, tokens} <- Tokens.issue(grant, payload.session_id, scopes: scopes) do
      {:ok, tokens}
    else
      nil -> {:error, :invalid_grant}
      {:error, "invalid_code_verifier"} -> {:error, :invalid_code_verifier}
      {:error, :redirect_mismatch} = err -> err
      {:error, _} -> {:error, :invalid_grant}
      _ -> {:error, :invalid_grant}
    end
  end

  def error_redirect(session, error)
      when error in ["login_required", "consent_required", "access_denied"] do
    uri = URI.parse(session.redirect_url)
    query = URI.decode_query(uri.query || "") |> Map.delete("code") |> Map.put("error", error)
    query = if session.state, do: Map.put(query, "state", session.state), else: query
    %URI{uri | query: URI.encode_query(query)} |> URI.to_string()
  end

  defp match_redirect(stored, provided) when stored == provided, do: :ok
  defp match_redirect(_, _), do: {:error, :redirect_mismatch}
end
